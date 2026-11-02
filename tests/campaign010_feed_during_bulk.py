"""Read the real routed Feed after an ordinary Forge bulk peer is active."""
import argparse,json,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import network
from campaign010_forge_distribution import Client
from campaign010_forge_coexistence import snapshot
from campaign010_notes_sharing import ui_call
from graphical_devices import DeviceInput
from creator_journey import rendered_text
from forge_journey import wait

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--state',type=Path,required=True);a=p.parse_args();r=json.loads(a.state.read_text());s=r['session'];ui=DeviceInput('qemu',Path(s['graphics']));began=time.monotonic()
 try:
  with Client(Path(s['socket']),timeout=300)as c:before=snapshot(c,s);bulk_before=network.status(c,slot=0);q,body=ui_call(c,s['feed']['ui'],791);public_before=body[:96]
  for _ in range(10):
   if rendered_text(ui.frame(),520,34,16)==f"{s['feed']['ui']:016x}":break
   ui.chord(56,15);time.sleep(.35)
  else:raise AssertionError('normal native focus did not reach Feed UI')
  ui.press(28)
  def received():
   with Client(Path(s['socket']),timeout=30)as c:
    q,body=ui_call(c,s['feed']['ui'],791);selected,event=ui_call(c,s['feed']['ui'],795)
   return dict(header=list(q),status_body_hex=body.hex(),event_id=event[:32].hex(),event_head_hex=event[32:])if any(event[:32])and struct.unpack_from('<Q',body,104)[0]==0 else None
  actual=wait(received,'actual routed Feed timeline body after bulk selection',180)
  with Client(Path(s['socket']),timeout=300)as c:after=snapshot(c,s);bulk_after=network.status(c,slot=0);_,body=ui_call(c,s['feed']['ui'],791)
  assert public_before==body[:96],'Feed identity or configured scope changed'
  assert before['route']==after['route']and before['route'][2]==3,'bulk and Feed failed to preserve route'
  assert bulk_before['endpoint_authenticated']and bulk_after['endpoint_authenticated'],'routed read displaced bulk authentication'
  old=bytes.fromhex(before['profiles_body_hex']);new=bytes.fromhex(after['profiles_body_hex'])
  for i in range(4):
   arow=struct.unpack_from('<8Q',old,i*128);brow=struct.unpack_from('<8Q',new,i*128)
   assert arow[:4]==brow[:4]and new[i*128+64:i*128+96]==old[i*128+64:i*128+96]
   assert brow[6]<=arow[6]and brow[7]<=arow[7],'terminal lifetime allowance renewed'
  r['routed_feed_during_bulk']=dict(result='pass',before=before,after=after,bulk_before=bulk_before,bulk_after=bulk_after,event_id=actual['event_id'],query_seconds=round(time.monotonic()-began,3),content_sha256=__import__('hashlib').sha256(actual.pop('event_head_hex')).hexdigest());r['result']='pass-live-bulk-and-routed-feed';a.state.write_text(json.dumps(r,indent=2)+'\n');(a.state.parent/'routed-feed-after-bulk.ppm').write_bytes(ui.frame().ppm());print('PASS actual routed Feed event retrieved while Forge bulk peer stays authenticated',flush=True)
 except BaseException as error:
  r['routed_feed_during_bulk']=dict(result='fail',error=repr(error));a.state.write_text(json.dumps(r,indent=2)+'\n');raise
 finally:ui.close()

if __name__=='__main__':main()
