"""Raw device input and framebuffer helpers for the LT development machines.

These helpers never inspect or mutate guest memory, call UI setters, or issue
Launcher commands. QEMU uses QMP's hardware input and screendump endpoints; the
assembly machines use their documented raw evdev FIFO and completed BGRX frame.
"""
from __future__ import annotations
import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from pixel_presenter import KEYS, WIDTH, HEIGHT, PIXEL_BYTES, frame as raw_frame

QCODE = {code: name for name, code in KEYS.items() if len(name) == 1 and name.isalnum()}
QCODE.update({1:'esc',12:'minus',13:'equal',14:'backspace',15:'tab',26:'bracket_left',
 27:'bracket_right',28:'ret',29:'ctrl',39:'semicolon',40:'apostrophe',41:'grave_accent',
 42:'shift',43:'backslash',51:'comma',52:'dot',53:'slash',54:'shift_r',56:'alt',57:'spc',
 58:'caps_lock',97:'ctrl_r',100:'alt_r',102:'home',103:'up',104:'pgup',105:'left',
 106:'right',107:'end',108:'down',109:'pgdn',110:'insert',111:'delete',125:'meta_l',126:'meta_r'})
QCODE.update({58+i if i <= 10 else 76+i: f'f{i}' for i in range(1,13)})
BUTTONS = {272:'left',273:'right',274:'middle'}
ASCII = dict(zip('1234567890',range(2,12)))
ASCII.update(dict(zip('qwertyuiop',range(16,26))))
ASCII.update(dict(zip('asdfghjkl',range(30,39))))
ASCII.update(dict(zip('zxcvbnm',range(44,51))))
ASCII.update({'-':12,'=':13,'\b':14,'\t':15,'[':26,']':27,'\n':28,';':39,"'":40,
 '`':41,'\\':43,',':51,'.':52,'/':53,' ':57})
SHIFT = dict(zip('!@#$%^&*()_+{}:"~|<>?', '1234567890-=[];\'`\\,./'))


@dataclass(frozen=True)
class Frame:
    width: int
    height: int
    bgrx: bytes

    @property
    def digest(self):
        return hashlib.sha256(self.bgrx).hexdigest()

    def ppm(self):
        rgb = bytearray(self.width * self.height * 3)
        rgb[0::3],rgb[1::3],rgb[2::3] = self.bgrx[2::4],self.bgrx[1::4],self.bgrx[0::4]
        return f'P6\n{self.width} {self.height}\n255\n'.encode() + rgb


def prepare_input(backend, graphics_path):
    """Create a nonpersistent raw input FIFO before starting an assembly guest.

    Returns an RDWR nonblocking descriptor that must stay open during the session.
    QEMU's input source is its QMP endpoint and needs no host FIFO.
    """
    if backend == 'qemu':
        return None
    path = Path(str(graphics_path) + '.evdev')
    if not path.exists():
        os.mkfifo(path, 0o600)
    if not stat.S_ISFIFO(path.stat().st_mode):
        raise ValueError('raw interactive input requires a FIFO, not an input-history file')
    return os.open(path, os.O_RDWR | os.O_NONBLOCK)


class DeviceInput:
    def __init__(self, backend, graphics_path, timeout=30):
        if backend not in ('qemu','x86_64','aarch64'):
            raise ValueError('unknown graphical machine backend')
        self.backend,self.path,self.timeout = backend,Path(graphics_path),timeout
        self.fd,self.socket,self.stream = None,None,None
        self.serial,self.held,self.buttons = 0,set(),set()
        self.pointer = [WIDTH//2,HEIGHT//2]
        if backend == 'qemu':
            deadline = time.monotonic() + timeout
            while True:
                connection = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                try:
                    connection.connect(str(self.path))
                    break
                except (FileNotFoundError,ConnectionRefusedError):
                    connection.close()
                    if time.monotonic() >= deadline:
                        raise TimeoutError('QMP input endpoint did not become ready')
                    time.sleep(.02)
            connection.settimeout(timeout)
            self.socket = connection
            self.stream = connection.makefile('rwb',buffering=0)
            greeting = json.loads(self.stream.readline())
            if 'QMP' not in greeting:
                raise ValueError('input endpoint is not QMP')
            self.qmp('qmp_capabilities')
        else:
            self.fd = prepare_input(backend,graphics_path)

    def __enter__(self):
        return self

    def __exit__(self,*_):
        self.close()

    def close(self):
        if self.stream:
            self.stream.close()
            self.stream = None
        if self.socket:
            self.socket.close()
            self.socket = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def qmp(self,execute,arguments=None):
        self.serial += 1
        request = dict(execute=execute,id=self.serial)
        if arguments is not None:
            request['arguments'] = arguments
        self.stream.write(json.dumps(request).encode()+b'\n')
        while True:
            line = self.stream.readline()
            if not line:
                raise EOFError('QEMU closed its graphical input endpoint')
            result = json.loads(line)
            if result.get('id') == self.serial:
                if 'error' in result:
                    raise ValueError('QMP '+execute+': '+json.dumps(result['error']))
                return result['return']

    def raw(self,events):
        if self.backend == 'qemu':
            qevents = []
            for kind,code,value in events:
                if kind == 1 and code in BUTTONS:
                    qevents.append(dict(type='btn',data=dict(down=bool(value),button=BUTTONS[code])))
                elif kind == 1:
                    if code not in QCODE:
                        raise ValueError('evdev key has no defined QEMU qcode')
                    qevents.append(dict(type='key',data=dict(down=bool(value),key=dict(type='qcode',data=QCODE[code]))))
                elif kind == 2 and code in (0,1,8):
                    if code == 8:
                        button = 'wheel-up' if value > 0 else 'wheel-down'
                        for _ in range(abs(value)):
                            qevents.extend([dict(type='btn',data=dict(down=True,button=button)),dict(type='btn',data=dict(down=False,button=button))])
                    else:
                        qevents.append(dict(type='rel',data=dict(axis='x' if code == 0 else 'y',value=value)))
                elif kind != 0:
                    raise ValueError('unsupported evdev event type')
            if qevents:
                self.qmp('input-send-event',dict(events=qevents))
        else:
            packet = b''.join(struct.pack('<HHI',t,c,v & 0xffffffff) for t,c,v in events)
            if len(packet) > 4096:
                raise ValueError('raw device packet exceeds atomic FIFO write budget')
            deadline = time.monotonic() + self.timeout
            while True:
                try:
                    if os.write(self.fd,packet) != len(packet):
                        raise RuntimeError('short raw input FIFO write')
                    return
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('raw input source did not drain')
                    time.sleep(.01)

    def key(self,code,down=True):
        if isinstance(code,str):
            code = KEYS.get(code,KEYS.get(code.lower()))
        if code is None or code not in QCODE:
            raise ValueError('unknown evdev key')
        value = (2 if code in self.held else 1) if down else 0
        (self.held.add if down else self.held.discard)(code)
        self.raw([(1,code,value),(0,0,0)])

    def press(self,code,delay=.025):
        self.key(code,True)
        time.sleep(delay)
        self.key(code,False)
        time.sleep(delay)

    def textASCII(self,text,delay=.025):
        for char in text:
            shifted = char.isupper() and char.isascii() or char in SHIFT
            plain = SHIFT.get(char,char.lower())
            if plain not in ASCII:
                raise ValueError('textASCII accepts the defined printable ASCII keyboard subset')
            if shifted:
                self.key(42,True)
            self.press(ASCII[plain],delay)
            if shifted:
                self.key(42,False)

    def chord(self,*codes,delay=.025):
        for code in codes:
            self.key(code,True)
        time.sleep(delay)
        for code in reversed(codes):
            self.key(code,False)
        time.sleep(delay)

    def mouse(self,x,y,buttons=None,relative=False):
        if relative:
            dx,dy = int(x),int(y)
            self.pointer[:] = [max(0,min(WIDTH-1,self.pointer[0]+dx)),max(0,min(HEIGHT-1,self.pointer[1]+dy))]
        else:
            x,y = max(0,min(WIDTH-1,int(x))),max(0,min(HEIGHT-1,int(y)))
            dx,dy = x-self.pointer[0],y-self.pointer[1]
            self.pointer[:] = [x,y]
        events = [(2,0,dx),(2,1,dy)]
        if buttons is not None:
            selected = set(buttons)
            if not selected <= BUTTONS.keys():
                raise ValueError('unsupported pointer button')
            events.extend((1,code,int(code in selected)) for code in sorted(self.buttons ^ selected))
            self.buttons = selected
        self.raw(events+[(0,0,0)])

    def click(self,x,y,button=272,delay=.04):
        self.mouse(x,y,buttons={button})
        time.sleep(delay)
        self.mouse(x,y,buttons=set())
        time.sleep(delay)

    def focus_lost(self):
        self.raw([(1,c,0) for c in sorted(self.held|self.buttons)]+[(0,3,0),(0,0,0)])
        self.held.clear()
        self.buttons.clear()

    def frame(self):
        if self.backend != 'qemu':
            result = raw_frame(Path(str(self.path)+'.bgrx'))
            return Frame(WIDTH,HEIGHT,result[1]) if result else None
        with tempfile.TemporaryDirectory(prefix='lt-pixels-') as directory:
            path = Path(directory)/'frame.ppm'
            self.qmp('screendump',dict(filename=str(path)))
            data = path.read_bytes()
        # QEMU's binary PPM header is ASCII and contains no comment lines.
        magic,dimensions,maximum,rgb = data.split(b'\n',3)
        if magic != b'P6' or maximum != b'255':
            raise ValueError('QEMU returned an unsupported screendump format')
        width,height = map(int,dimensions.split())
        if len(rgb) != width*height*3:
            raise ValueError('truncated QEMU framebuffer')
        bgrx = bytearray(width*height*4)
        bgrx[0::4],bgrx[1::4],bgrx[2::4] = rgb[2::3],rgb[1::3],rgb[0::3]
        return Frame(width,height,bytes(bgrx))

    def wait_frame(self,previous=None,timeout=15):
        deadline = time.monotonic()+timeout
        while True:
            result = self.frame()
            if result is not None and (previous is None or result.digest != previous):
                return result
            if time.monotonic() >= deadline:
                raise TimeoutError('guest did not present a new complete frame')
            time.sleep(.04)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--backend',required=True,choices=['qemu','x86_64','aarch64'])
    p.add_argument('--graphics',required=True,type=Path)
    p.add_argument('--text')
    p.add_argument('--click',nargs=2,type=int,metavar=('X','Y'))
    p.add_argument('--capture',type=Path)
    args = p.parse_args(argv)
    with DeviceInput(args.backend,args.graphics) as source:
        if args.click:
            source.click(*args.click)
        if args.text:
            source.textASCII(args.text)
        result = source.wait_frame()
        if args.capture:
            args.capture.write_bytes(result.ppm())
        print(json.dumps(dict(backend=args.backend,width=result.width,height=result.height,frame_sha256=result.digest)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
