"""Opaque adapter boundaries, including epoch isolation on one listener."""
import socket,struct,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from transport import MultiplexStream,HEADER,MAGIC

def run():
 adapter=MultiplexStream();adapter.start();guest=adapter.guest;guest.settimeout(3);pending=bytearray();remotes=[]
 def send(op,slot,data=b'',epoch=0):guest.sendall(HEADER.pack(MAGIC,op,slot,len(data),epoch,0)+data)
 def event():
  while len(pending)<16:pending.extend(guest.recv(4096))
  q=HEADER.unpack_from(pending)
  while len(pending)<16+q[3]:pending.extend(guest.recv(4096))
  data=bytes(pending[16:16+q[3]]);del pending[:16+q[3]]
  return q,data
 probe=socket.socket();probe.bind(('127.0.0.1',0));address=probe.getsockname();probe.close();endpoint=f'{address[0]}:{address[1]}'.encode()
 try:
  for slot in range(2):send(2,slot,endpoint);assert event()[0][1:3]==(9,slot)
  for slot in range(2):
   remote=socket.create_connection(address);remotes.append(remote);q,_=event();assert q[1:3]==(8,slot) and q[4]==1,q
  for slot,r in enumerate(remotes):r.sendall(bytes([slot])*31)
  received={}
  while len(received)<2:
   q,data=event();assert q[1]==7;received[q[2]]=data
  assert received=={0:bytes(31),1:bytes([1])*31}
  remotes[0].close();q,_=event();assert q[1:3]==(5,0) and q[4]==2,q
  replacement=socket.create_connection(address);remotes.append(replacement);q,_=event();assert q[1:3]==(8,0) and q[4]==3,q
  send(7,0,b'stale',epoch=1);q,_=event();assert q[1:3]==(6,0),q
  send(7,1,b'alive',epoch=1);assert remotes[1].recv(5)==b'alive'
  send(7,0,b'fresh',epoch=3);assert replacement.recv(5)==b'fresh'
  print('shared listener, independent clients, epoch isolation, surviving writes: PASS')
 finally:
  for remote in remotes:remote.close()
  adapter.close()
if __name__=='__main__':run()
