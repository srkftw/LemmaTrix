"""Explicit decoded PCM sink. No WAV parsing, catalog or playback decisions."""
import os, shutil, socket, subprocess, sys, threading
from pathlib import Path


def playback_command():
 executable=shutil.which('aplay')
 if executable:
  return [executable,'-q','-t','raw','-f','S16_LE','-r','48000','-c','2']
 executable=shutil.which('pw-cat')
 if executable:
  # pw-cat's s16 maps to native-endian SPA_AUDIO_FORMAT_S16. Never silently
  # reinterpret the guest's S16LE bytes on a big-endian adapter host.
  if sys.byteorder!='little':raise ValueError('pw-cat PCM output requires a little-endian host')
  return [executable,'--playback','--raw','--format','s16','--rate','48000','--channels','2','--channel-map','stereo','-']
 raise ValueError('aplay or pw-cat is required for the explicitly selected PCM speaker sink')


class PCMSink:
 def __init__(self,path=None,play=False):
  self.guest,self.local=socket.socketpair()
  self.guest.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,4096)
  self.closed=threading.Event();self.output=None;self.player=None;self.error=None
  self.watcher=None;self.command=None;self.sink_name=None;self.returncode=None
  try:
   if path is not None:
    fd=os.open(Path(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    self.output=os.fdopen(fd,'wb',buffering=0)
   if play:
    # Unbuffered stdin avoids a hidden Python queue or a blocking flush during
    # teardown when an unavailable sink has stopped reading the bounded pipe.
    self.command=playback_command();self.sink_name=Path(self.command[0]).name
    self.player=subprocess.Popen(self.command,stdin=subprocess.PIPE,bufsize=0)
    self.watcher=threading.Thread(target=self.watch_player,daemon=True)
   self.thread=threading.Thread(target=self.run,daemon=True)
  except BaseException:
   self.guest.close();self.local.close()
   if self.output:self.output.close()
   self.stop_player()
   raise
 def start(self):
  if self.watcher:self.watcher.start()
  self.thread.start()
 def fail(self,error):
  if not self.closed.is_set() and self.error is None:
   self.error=error
   print('PCM sink error: '+str(error),file=sys.stderr,flush=True)
  # A dead process must not leave a live socket that accepts samples forever.
  try:self.local.shutdown(socket.SHUT_RDWR)
  except OSError:pass
  self.local.close()
 def watch_player(self):
  code=self.player.wait();self.returncode=code
  if not self.closed.is_set():self.fail(OSError('PCM output process exited with status '+str(code)))
 def run(self):
  try:
   while not self.closed.is_set():
    raw=self.local.recv(4096)
    if not raw:break
    if self.output:self.output.write(raw)
    if self.player:
     remaining=memoryview(raw)
     while remaining and not self.closed.is_set():
      written=self.player.stdin.write(remaining)
      if not written:raise OSError('PCM output process accepted no samples')
      remaining=remaining[written:]
  except (OSError,ValueError) as error:self.fail(error)
 def stop_player(self):
  if not self.player:return
  try:self.player.stdin.close()
  except (OSError,ValueError):pass
  try:self.player.wait(timeout=2)
  except subprocess.TimeoutExpired:
   self.player.terminate()
   try:self.player.wait(timeout=2)
   except subprocess.TimeoutExpired:self.player.kill();self.player.wait(timeout=2)
  self.returncode=self.player.returncode
 def close(self):
  self.closed.set()
  try:self.local.shutdown(socket.SHUT_RDWR)
  except OSError:pass
  self.local.close();self.guest.close()
  self.stop_player()
  if self.thread.ident is not None:self.thread.join(timeout=2)
  if self.watcher and self.watcher.ident is not None:self.watcher.join(timeout=2)
  if self.output:self.output.close()
