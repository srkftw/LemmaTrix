"""Focused opaque-byte fault-control checks; no protocol or crypto oracle."""
import argparse,json,os,socket,struct,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from transport import MultiplexStream,HEADER,MAGIC,CHANNELS,LIMIT

def run(output=None):
 checks=[]
 with tempfile.TemporaryDirectory(prefix='lt-tx-fault-') as tmp:
  path=Path(tmp)/'control.sock';adapter=MultiplexStream(path);adapter.start()
  guest=adapter.guest;guest.settimeout(3);pending=bytearray();remotes=[]
  def send(op,slot,data=b'',epoch=0):guest.sendall(HEADER.pack(MAGIC,op,slot,len(data),epoch,0)+data)
  def event():
   while len(pending)<HEADER.size:pending.extend(guest.recv(4096))
   q=HEADER.unpack_from(pending)
   while len(pending)<HEADER.size+q[3]:pending.extend(guest.recv(4096))
   data=bytes(pending[HEADER.size:HEADER.size+q[3]]);del pending[:HEADER.size+q[3]]
   return q,data
  def control(**command):
   with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
    client.settimeout(3);client.connect(str(path));client.sendall(json.dumps(command).encode()+b'\n');reply=bytearray()
    while b'\n' not in reply:
     data=client.recv(4096)
     assert data,'control closed without a reply'
     reply.extend(data);assert len(reply)<=4096
    return json.loads(reply)
  def wait(predicate):
   end=time.monotonic()+3
   while time.monotonic()<end:
    value=predicate()
    if value:return value
    time.sleep(.01)
   raise TimeoutError('bounded adapter observation')
  probe=socket.socket();probe.bind(('127.0.0.1',0));address=probe.getsockname();probe.close();endpoint=f'{address[0]}:{address[1]}'.encode()
  try:
   assert path.stat().st_mode&0o777==0o600
   try:MultiplexStream(path)
   except ValueError:pass
   else:raise AssertionError('existing control path was replaced')
   assert control(op='status')['channels']==[dict(slot=i,epoch=0,connected=False,connecting=False,tx_paused=False,pending_bytes=0,tx_bytes=0,rx_bytes=0)for i in range(CHANNELS)]
   for slot in (0,1):
    send(2,slot,endpoint);assert event()[0][1:3]==(9,slot)
    remote=socket.create_connection(address);remote.settimeout(3);remotes.append(remote)
    q,_=event();assert q[1:3]==(8,slot)and q[4]==1
   assert not control(op='pause',slot=0,epoch=0)['ok']
   paused=control(op='pause',slot=0,epoch=1);assert paused['ok']and paused['channel']['tx_paused']
   send(7,0,b'bounded opaque ciphertext',epoch=1)
   status=wait(lambda:(s if s['pending_bytes']==25 else None)if(s:=control(op='status',slot=0)['channel'])else None)
   assert status['tx_bytes']==0 and status['tx_paused']
   remotes[0].settimeout(.1)
   try:remotes[0].recv(1)
   except socket.timeout:pass
   else:raise AssertionError('paused socket transmitted bytes')
   # Both an independent channel and the paused channel's receive direction
   # remain usable. Control requests do not parse these arbitrary bytes.
   send(7,1,b'independent',epoch=1);assert remotes[1].recv(11)==b'independent'
   remotes[0].sendall(b'incoming');q,data=event();assert q[1:3]==(7,0)and data==b'incoming'
   status=control(op='status',slot=0)['channel'];assert status['rx_bytes']==8 and status['tx_bytes']==0
   assert not control(op='resume',slot=0,epoch=0)['ok']
   assert control(op='resume',slot=0,epoch=1)['ok'];remotes[0].settimeout(3)
   assert remotes[0].recv(25)==b'bounded opaque ciphertext'
   status=wait(lambda:(s if s['tx_bytes']==25 else None)if(s:=control(op='status',slot=0)['channel'])else None)
   assert status['pending_bytes']==0 and not status['tx_paused']
   checks.append('exact-epoch pause barrier, opaque pending bytes, independent send, incoming traffic and resume')
   assert control(op='pause',slot=0,epoch=1)['ok']
   for _ in range(LIMIT//1008+1):send(7,0,bytes(1008),epoch=1)
   q,_=event();assert q[1:3]==(5,0)and q[4]==2
   status=control(op='status',slot=0)['channel'];assert status['pending_bytes']==0 and not status['tx_paused']and not status['connected']
   replacement=socket.create_connection(address);replacement.settimeout(3);remotes.append(replacement)
   q,_=event();assert q[1:3]==(8,0)and q[4]==3
   assert not control(op='pause',slot=0,epoch=1)['ok']
   send(7,0,b'new epoch',epoch=3);assert replacement.recv(9)==b'new epoch'
   checks.append('unchanged64KiB pending limit, overflow disconnect, epoch invalidation and no queued-byte reuse')
   for command in ({'op':'pause','slot':True,'epoch':3},{'op':'status','epoch':3},{'op':'unknown'},{'op':'status','extra':1}):assert not control(**command)['ok']
   with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)as client:
    client.settimeout(3);client.connect(str(path));client.sendall(b'x'*513)
    assert not json.loads(client.recv(1024))['ok']
   checks.append('bounded malformed-input rejection, strict field types and existing-path protection')
   assert adapter.error is None,adapter.error
  finally:
   for remote in remotes:remote.close()
   adapter.close()
  assert not path.exists()
 report=dict(schema=1,result='pass',profile='opt-in-local-opaque-tx-fault-v1',checks=checks,buffer_limit=LIMIT,control_clients=4,command_limit=512,security_scope='Opaque socket adapter only; no native cryptographic or delivery assurance claimed.')
 if output:output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report,indent=2))

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path);run(p.parse_args().output)
