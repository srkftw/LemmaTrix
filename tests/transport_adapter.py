"""Opaque adapter boundaries, including epoch isolation on one listener."""
import argparse,errno,hashlib,json,socket,struct,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from transport import MultiplexStream,HEADER,MAGIC

def run(output=None):
 began=time.monotonic();checks=[]
 adapter=MultiplexStream();adapter.start();guest=adapter.guest;guest.settimeout(3);pending=bytearray();remotes=[]
 def send(op,slot,data=b'',epoch=0,value=0):guest.sendall(HEADER.pack(MAGIC,op,slot,len(data),epoch,value)+data)
 def event():
  while len(pending)<16:
   part=guest.recv(4096);assert part,'adapter closed the opaque event stream';pending.extend(part)
  q=HEADER.unpack_from(pending)
  while len(pending)<16+q[3]:
   part=guest.recv(4096);assert part,'adapter closed a partial opaque event';pending.extend(part)
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
  replacement=socket.create_connection(address);remotes.append(replacement)
  # One native listen command admits one socket. A disconnected, accepted
  # channel cannot steal a connection before the guest replenishes admission.
  guest.settimeout(.1)
  try:event()
  except socket.timeout:pass
  else:raise AssertionError('retired native listener accepted another client')
  guest.settimeout(3);send(2,2,endpoint);assert event()[0][1:3]==(9,2)
  q,_=event();assert q[1:3]==(8,2) and q[4]==1,q
  send(7,0,b'stale',epoch=1);q,_=event();assert q[1:3]==(6,0),q
  send(7,1,b'alive',epoch=1);assert remotes[1].recv(5)==b'alive'
  send(7,2,b'fresh',epoch=1);assert replacement.recv(5)==b'fresh'
  checks.append('shared listener, native admission ownership, independent clients, epoch isolation and surviving writes')
  # The final readiness-loop slot deliberately owns a live socket. Before the
  # fix, a malformed later command reused that function-scoped remote variable
  # during cleanup, closing this unrelated socket and then killing select().
  send(2,15,endpoint);assert event()[0][1:3]==(9,15)
  victim=socket.create_connection(address);victim.settimeout(3);remotes.append(victim)
  q,_=event();assert q[1:3]==(8,15)and q[4]==1,q
  for slot,op,data,value,label in((3,1,b'not-an-endpoint',0,'invalid endpoint'),
                                 (4,2,endpoint,1,'invalid receive window')):
   send(op,slot,data,value=value);q,payload=event()
   assert q[1:]==(6,slot,0,0,errno.EINVAL)and payload==b'',q
   send(7,15,b'survives '+label.encode(),epoch=1)
   wanted=b'survives '+label.encode();received=bytearray()
   while len(received)<len(wanted):
    part=victim.recv(len(wanted)-len(received));assert part,'unrelated established socket was closed';received.extend(part)
   assert bytes(received)==wanted
   victim.sendall(label.encode());q,payload=event()
   assert q[1:3]==(7,15)and q[4]==1 and payload==label.encode(),(q,payload)
   send(7,1,b'independent',epoch=1);assert remotes[1].recv(11)==b'independent'
   assert adapter.thread.is_alive()and adapter.error is None,adapter.error
   checks.append(label+' rejects only its command while independent established sockets remain bidirectionally usable at the same epochs')
  assert adapter.error is None,adapter.error
 finally:
  for remote in remotes:remote.close()
  adapter.close()
 report=dict(schema=1,result='pass',checks=checks,seconds=time.monotonic()-began,
  adapter_sha256=hashlib.sha256((Path(__file__).resolve().parents[1]/'tools/transport.py').read_bytes()).hexdigest(),
  scope='isolated opaque host adapter commands and socket ownership only; no Native, cryptography, connected community or current Alice failure causality claim')
 if output:output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report,indent=2))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path);run(p.parse_args().output)
