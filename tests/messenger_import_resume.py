"""Explicitly retry an already received native project after a busy F7.

Run only after the prior actor controller releases its portals. No new sender
transfer, message, key or remote queue entry is created. The current approved
three-hop terminal and native incoming object/root must match the public fixture.
"""
from __future__ import annotations
import argparse,hashlib,json,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from messenger_journey import Guest,role,net,inspect,transfer_state,wait,screenshot
import identity,messenger

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--campaign',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--fixture',required=True,type=Path);p.add_argument('--actor',default='bob',choices=('alice','bob'));a=p.parse_args()
 campaign=a.campaign.resolve();out=a.output.resolve();out.mkdir(exist_ok=False);fixture=json.loads(a.fixture.read_text());g=Guest(a.actor,'qemu',campaign,campaign/'guest.bin',graphical=True,vault=campaign/(a.actor+'.img')).attach(campaign);began=time.monotonic();events=[]
 report=dict(schema=1,result='running',command=sys.argv,helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),fixture=str(a.fixture.resolve()),events=events)
 try:
  g.ui=next(r[0]for r in identity.instances(g.client)if r[2]==799 and 0<r[1]<5)
  g.owner=messenger.endpoint(g.client,2,420);g.delivery=messenger.endpoint(g.client,4,464)
  circuit=net(g,32)[0];terminal,pin=net(g,41);assert circuit[2:4]==(3,0)and terminal[2:4]==(3,0)and pin==hashlib.sha256((campaign/'mailbox.certificate').read_bytes()).digest()
  incoming=[]
  for i in range(2):
   f,b=role(g,2,434,h=i,a=21,allow=(3,))
   if f[0]==0 and f[2]==2 and b[:32].hex()==fixture['ciphertext_object_id']:
    assert b[32:64].hex()==fixture['canonical_root'];incoming.append(list(f))
  assert len(incoming)==1
  initial=transfer_state(g);assert initial[1]==9
  attempts=0;end=time.monotonic()+180
  while time.monotonic()<end:
   state=transfer_state(g)
   if state[1]in(20,21,23,24):break
   pending=struct.unpack_from('<8Q',g.client.request(150,struct.pack('<Q8Q',g.ui,783,0,0,0,0,0,0,1)))
   if pending[6]==0 and attempts<16:
    g.device.press(65,delay=.1);attempts+=1;events.append(dict(kind='actual_F7',elapsed_seconds=time.monotonic()-began,ui=list(inspect(g)[0]),transfer=list(transfer_state(g))))
   time.sleep(.25)
  else:raise TimeoutError('bounded explicit F7 retry never admitted the incoming import')
  last=None;end=time.monotonic()+300
  while time.monotonic()<end:
   state=transfer_state(g)
   if state!=last:print('Native received import',state,flush=True);events.append(dict(kind='progress',elapsed_seconds=time.monotonic()-began,transfer=list(state)));last=state
   if state[1]==24:break
   if state[1]==9:raise RuntimeError(('admitted native import failed',state,role(g,4,464,a=3)[0]))
   time.sleep(.1)
  else:raise TimeoutError('bounded native received import did not complete')
  frame=screenshot(g,'stalled-import-explicit-retry');outgoing=inspect(g)[0]
  assert state[6]!=0,'native canonical importer must expose its committed Objects root'
  report.update(result='pass',initial=list(initial),incoming=incoming,circuit=list(circuit),terminal=list(terminal),mailbox_pin=pin.hex(),native_import=list(state),committed_root_capability=state[6],actual_F7_count=attempts,frame_sha256=frame,ui=list(outgoing),broker_state=list(role(g,4,464,a=3)[0]),elapsed_seconds=time.monotonic()-began,scope='Later explicit F7 after text finished drains the previously cancelled incoming project into the native canonical Objects importer. It is not a claim that the first busy F7 was admitted, and it creates no sender ciphertext or manifest.')
  (out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 except BaseException as error:
  report.update(result='failed-preserved-actors',error=repr(error),native_transfer=list(transfer_state(g)),ui=list(inspect(g)[0]),broker_state=list(role(g,4,464,a=3)[0]));(out/'failure.json').write_text(json.dumps(report,indent=2)+'\n');raise
 finally:g.device.close();g.client.close()
if __name__=='__main__':main()
