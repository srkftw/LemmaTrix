"""Explicit decoded PCM sink. No WAV parsing, catalog or playback decisions."""
import os, shutil, socket, subprocess, threading
from pathlib import Path

class PCMSink:
 def __init__(self,path=None,play=False):
  self.guest,self.local=socket.socketpair()
  self.guest.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,4096)
  self.closed=threading.Event();self.output=None;self.player=None;self.error=None
  try:
   if path is not None:
    fd=os.open(Path(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    self.output=os.fdopen(fd,'wb',buffering=0)
   if play:
    executable=shutil.which('aplay')
    if not executable:raise ValueError('aplay is required for the explicitly selected PCM speaker sink')
    self.player=subprocess.Popen([executable,'-q','-t','raw','-f','S16_LE','-r','48000','-c','2'],stdin=subprocess.PIPE)
   self.thread=threading.Thread(target=self.run,daemon=True)
  except BaseException:
   self.guest.close();self.local.close()
   if self.output:self.output.close()
   raise
 def start(self):self.thread.start()
 def run(self):
  try:
   while not self.closed.is_set():
    raw=self.local.recv(4096)
    if not raw:break
    if self.output:self.output.write(raw)
    if self.player:self.player.stdin.write(raw);self.player.stdin.flush()
  except OSError as error:self.error=error
 def close(self):
  self.closed.set()
  try:self.local.shutdown(socket.SHUT_RDWR)
  except OSError:pass
  self.local.close();self.guest.close()
  if self.thread.ident is not None:self.thread.join(timeout=2)
  if self.output:self.output.close()
  if self.player:
   self.player.stdin.close()
   try:self.player.wait(timeout=2)
   except subprocess.TimeoutExpired:self.player.terminate();self.player.wait(timeout=2)
