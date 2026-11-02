"""Attach an explicit Forge bulk peer without resetting a live routed Feed owner.

The selected persona has already published its real project card through a
three-hop terminal. This script uses physical package approval and ordinary
public provisioning; it never restores or edits any guest memory.
"""
import argparse,hashlib,json,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import federation,forge,identity,live,network,onion,releases
from campaign010_forge_distribution import Client,PUBLIC
from campaign010_forge_continue import attach,fetch
from campaign010_notes_sharing import ui_call
from creator_journey import rendered_text
from forge_journey import wait
from graphical_devices import DeviceInput

def snapshot(c,s):
 route,body=onion.call(c,32);profiles,pbody=onion.call(c,49);ui,_=ui_call(c,s['feed']['ui'],791)
 return dict(route=list(route),route_body_hex=body.hex(),profiles_header=list(profiles),profiles_body_hex=pbody.hex(),feed_ui=list(ui),ordinary=[list(r)for r in identity.instances(c)if r[0]&255>=7 and 0<r[1]<5])

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--session',type=Path,required=True);p.add_argument('--forge',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True);s=json.loads(a.session.read_text())['session'];ui=DeviceInput('qemu',Path(s['graphics']));started=time.monotonic();record=dict(schema=1,result='running',session=s,scope=__doc__)
 def write():record['elapsed_seconds']=round(time.monotonic()-started,3);(a.output/'execution.json').write_text(json.dumps(record,indent=2)+'\n')
 try:
  with Client(Path(s['socket']),timeout=300)as c:
   before=snapshot(c,s);known={r[0]for r in identity.instances(c)};raw=a.forge.read_bytes();c.request(10,raw[128:160]+releases.public_key(PUBLIC));info=c.stage(a.forge)
  record['before']=before;write();ui.press(88)
  frame=wait(lambda:(f if rendered_text(f:=ui.frame(),16,12,24)=='SIGNED PACKAGE CANDIDATE'else None),'actual selected Forge package approval',120)
  (a.output/'forge-approval.ppm').write_bytes(frame.ppm());time.sleep(.4);ui.press(28)
  def running():
   with Client(Path(s['socket']),timeout=30)as c:
    try:active=c.request(29,raw[128:160])
    except ValueError:return None
    if active[160:192].hex()!=info['release_id']:return None
    rows=[r for r in identity.instances(c)if r[0]not in known and r[2]==1919 and 0<r[1]<5 and 7<=r[0]&255<15]
   return rows[0][0]if len(rows)==1 else None
  instance=wait(running,'new ordinary Forge incarnation after real physical approval',120)
  for _ in range(10):
   if rendered_text(ui.frame(),520,34,16)==f'{instance:016x}':break
   ui.chord(56,15);time.sleep(.3)
  else:raise AssertionError('physical focus did not select the newly approved Forge')
  with Client(Path(s['socket']),timeout=300)as c:after=snapshot(c,s)
  assert before['route']==after['route'] and before['route'][2]==3,'Forge installation changed existing native circuit'
  assert before['profiles_body_hex']==after['profiles_body_hex'],'Forge installation changed selected terminal profile or its finite totals'
  assert before['feed_ui']==after['feed_ui'] and before['feed_ui'][5]in(6,7),'Forge installation reset accepted Feed outbox/status'
  record.update(result='pass-install-preserves-routed-feed',forge=instance,forge_package_sha256=hashlib.sha256(raw).hexdigest(),forge_release=info['release_id'],after=after);write();print('PASS ordinary Forge installation preserves native circuit, terminal profile, Feed owner and accepted card',flush=True)
 except BaseException as error:
  record.update(result='fail',error=repr(error));write()
  try:(a.output/'failure.ppm').write_bytes(ui.frame().ppm())
  except Exception:pass
  raise
 finally:ui.close()

if __name__=='__main__':main()
