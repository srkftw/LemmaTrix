#!/usr/bin/env python3
"""Explicit raw-pixel/raw-evdev adapter for the assembly development machines.

No guest rendering or application policy is implemented here. The complete BGRX
frame is guest-generated. Input is transported as Linux evdev type/code/value.
"""
import argparse
import os
from pathlib import Path
import stat
import struct
import sys

WIDTH, HEIGHT, PIXEL_BYTES = 640, 400, 640 * 400 * 4
# Physical evdev codes: text interpretation, modifiers and focus stay in guest.
KEYS = dict(zip('1234567890', range(2, 12)))
KEYS.update(dict(zip('qwertyuiop', range(16, 26))))
KEYS.update(dict(zip('asdfghjkl', range(30, 39))))
KEYS.update(dict(zip('zxcvbnm', range(44, 51))))
KEYS.update({'Escape': 1, 'minus': 12, 'equal': 13, 'BackSpace': 14, 'Tab': 15,
 'bracketleft': 26, 'bracketright': 27, 'Return': 28, 'Control_L': 29,
 'semicolon': 39, 'apostrophe': 40, 'grave': 41, 'Shift_L': 42,
 'backslash': 43, 'comma': 51, 'period': 52, 'slash': 53, 'Shift_R': 54,
 'Alt_L': 56, 'space': 57, 'Caps_Lock': 58, 'Control_R': 97,
 'Alt_R': 100, 'Home': 102, 'Up': 103, 'Prior': 104, 'Left': 105,
 'Right': 106, 'End': 107, 'Down': 108, 'Next': 109, 'Insert': 110,
 'Delete': 111, 'Super_L': 125, 'Super_R': 126})
KEYS.update({f'F{i}': 58 + i if i <= 10 else 76 + i for i in range(1, 13)})
# Tk may report shifted symbols instead of physical keys.
SHIFTED = dict(zip('!@#$%^&*()_+{}:"~|<>?', '1234567890-=[];\'`\\,./'))
SYMBOLS = {'!':'exclam','@':'at','#':'numbersign','$':'dollar','%':'percent',
 '^':'asciicircum','&':'ampersand','*':'asterisk','(':'parenleft',')':'parenright',
 '_':'underscore','+':'plus','{':'braceleft','}':'braceright',':':'colon',
 '"':'quotedbl','~':'asciitilde','|':'bar','<':'less','>':'greater','?':'question'}
BASE = {'-':'minus','=':'equal','[':'bracketleft',']':'bracketright',
 ';':'semicolon',"'":'apostrophe','`':'grave','\\':'backslash',',':'comma',
 '.':'period','/':'slash'}
for shifted, plain in SHIFTED.items():
    KEYS[SYMBOLS.get(shifted, shifted)] = KEYS.get(BASE.get(plain, plain), 0)


def frame(path):
    """Read a completed frame; the odd/even marker detects torn host reads."""
    try:
        with path.open('rb', buffering=0) as source:
            source.seek(PIXEL_BYTES)
            before = source.read(8)
            if len(before) != 8 or int.from_bytes(before, 'little') & 1:
                return None
            source.seek(0)
            pixels = source.read(PIXEL_BYTES)
            source.seek(PIXEL_BYTES)
            if source.read(8) != before or len(pixels) != PIXEL_BYTES:
                return None
            return before, pixels
    except FileNotFoundError:
        return None


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--frame', required=True, type=Path)
    p.add_argument('--events', required=True, type=Path)
    args = p.parse_args(argv)
    try:
        import tkinter as tk
    except ImportError as exc:
        p.error(f'the explicit pixel adapter needs Python tkinter: {exc}')
    created = False
    if not args.events.exists():
        os.mkfifo(args.events, 0o600)
        created = True
    if not stat.S_ISFIFO(args.events.stat().st_mode):
        p.error('--events must be a named FIFO, not a persistent input-history file')
    fd = os.open(args.events, os.O_RDWR | os.O_NONBLOCK)
    root = tk.Tk()
    root.title('LemmaTrix — raw pixel/input adapter')
    root.resizable(False, False)
    blank = tk.PhotoImage(width=WIDTH, height=HEIGHT)
    view = tk.Label(root, image=blank, width=WIDTH, height=HEIGHT, borderwidth=0, cursor='none')
    view.pack()
    pressed, buttons = set(), set()
    last_pointer = [WIDTH // 2, HEIGHT // 2]
    last_frame = [None]
    image = [None]
    dropped = [False]

    def report_drop():
        if dropped[0]:
            try:
                if os.write(fd, struct.pack('<HHI', 0, 3, 0)) == 8:
                    dropped[0] = False
            except BlockingIOError:
                pass

    def emit(events):
        report_drop()
        if dropped[0]:
            return
        packet = b''.join(struct.pack('<HHI', t, c, v & 0xffffffff) for t, c, v in events)
        try:
            if os.write(fd, packet) != len(packet):
                raise BlockingIOError('short raw input write')
        except BlockingIOError:
            # FIFO overflow becomes a device-visible SYN_DROPPED marker once the
            # source drains. Never manufacture a trusted approval or retry click.
            pressed.clear()
            buttons.clear()
            dropped[0] = True

    def key(event, down):
        code = KEYS.get(event.keysym, KEYS.get(event.keysym.lower(), 0))
        if not code:
            return 'break'
        value = (2 if code in pressed else 1) if down else 0
        (pressed.add if down else pressed.discard)(code)
        emit([(1, code, value), (0, 0, 0)])
        return 'break'

    def motion(event):
        x, y = max(0, min(WIDTH - 1, event.x)), max(0, min(HEIGHT - 1, event.y))
        dx, dy = x - last_pointer[0], y - last_pointer[1]
        last_pointer[:] = x, y
        if dx or dy:
            emit([(2, 0, dx), (2, 1, dy), (0, 0, 0)])

    def button(event, down):
        view.focus_set()
        motion(event)
        code = {1: 272, 2: 274, 3: 273}.get(event.num)
        if code:
            (buttons.add if down else buttons.discard)(code)
            emit([(1, code, int(down)), (0, 0, 0)])

    def focus_lost(_event):
        emit([(1, code, 0) for code in sorted(pressed | buttons)] + [(0, 3, 0), (0, 0, 0)])
        pressed.clear()
        buttons.clear()

    def update():
        report_drop()
        result = frame(args.frame)
        if result and result[0] != last_frame[0]:
            marker, pixels = result
            rgb = bytearray(WIDTH * HEIGHT * 3)
            rgb[0::3], rgb[1::3], rgb[2::3] = pixels[2::4], pixels[1::4], pixels[0::4]
            image[0] = tk.PhotoImage(data=f'P6\n{WIDTH} {HEIGHT}\n255\n'.encode() + rgb, format='PPM')
            view.configure(image=image[0])
            last_frame[0] = marker
        root.after(33, update)

    view.bind('<KeyPress>', lambda e: key(e, True))
    view.bind('<KeyRelease>', lambda e: key(e, False))
    view.bind('<Motion>', motion)
    view.bind('<ButtonPress>', lambda e: button(e, True))
    view.bind('<ButtonRelease>', lambda e: button(e, False))
    view.bind('<FocusOut>', focus_lost)
    view.focus_set()
    root.after(0, update)
    try:
        root.mainloop()
    finally:
        os.close(fd)
        if created:
            args.events.unlink(missing_ok=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
