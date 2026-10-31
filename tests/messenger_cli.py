"""Actual native Messenger CLI admission smoke; host CLI handles public bytes.

The graphical two-guest campaign is separate. This verifies the supported
owner/UI -> temporary scoped certification -> coordinator admission order at
its real five-process/32-exact-operation bounds, using installed native apps.
"""
import argparse,contextlib,hashlib,io,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools')]
import driver,identity,live,live_build,messenger,releases
PUB=ROOT/'tests/keys/development-rsa-public.pem';KEY=ROOT/'tests/keys/development-rsa.pem'
def main():
 p=argparse.ArgumentParser();p.add_argument('--image',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);image=out/'guest.bin';image.write_bytes(a.image.read_bytes());packages={};package_records={}
 for name,module,rights in [('owner','Guest.MessengerSession',0),('ui','Guest.Messenger',799),('delivery','Guest.MessengerDelivery',1024),('identity','Guest.Identity',0)]:
  binary=live_build.app(module,module+'.main','cli-'+name,2);raw,_=releases.make(binary,'cli-'+name,'0.8.0',rights,KEY,profile=2);path=out/(name+'.ltrel');path.write_bytes(raw);packages[name]=path;package_records[name]=dict(code_bytes=binary.stat().st_size,package_sha256=hashlib.sha256(raw).hexdigest(),release_id=releases.inspect(raw)['release_id'])
 sock=out/'guest.sock';log=(out/'guest.log').open('wb');process=None;checks=[];commands=[]
 def cli(*args):
  capture=io.StringIO();argv=['--socket',str(sock),*map(str,args)]
  with contextlib.redirect_stdout(capture):assert messenger.main(argv)==0
  result=json.loads(capture.getvalue());commands.append(dict(arguments=list(map(str,args)),result=result));print('CLI',args[0],json.dumps(result),flush=True);return result
 def passed(s):checks.append(s);print('PASS',s,flush=True)
 try:
  process=subprocess.Popen([str(ROOT/'lt'),'run','--backend','qemu','--image',str(image),'--socket',str(sock)],cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
  until=time.monotonic()+90
  while not sock.exists():
   if process.poll()is not None or time.monotonic()>until:raise RuntimeError('guest start')
   time.sleep(.05)
  start=cli('start','--owner',packages['owner'],'--ui',packages['ui'],'--public',PUB)
  assert start['ui']and start['delivery']is None
  federation=hashlib.sha256(b'public native CLI component federation').hexdigest();scope=hashlib.sha256(b'public native CLI scoped contact certificate').hexdigest()
  cli('configure','--ui',start['ui'],'--federation',federation);cli('create','--federation',federation,'--output',out/'bundle256');cli('select-mailbox','--fingerprint',hashlib.sha256(b'explicit CLI public mailbox descriptor fixture').hexdigest())
  certified=cli('certify-contact','--identity-release',packages['identity'],'--public',PUB,'--scope',scope,'--output',out/'invitation672');assert certified['bytes']==672 and not certified['private_keys_exported']
  c=live.Client(sock,timeout=600)
  try:
   try:identity.endpoint(c,400)
   except ValueError:pass
   else:raise AssertionError('temporary signer remained bound')
   assert len([row for row in identity.instances(c)if(row[0]&255)>=7 and 0<row[1]<5])==2
  finally:c.close()
  passed('actual CLI starts owner/UI, configures federation, creates native device and commits public role2 contact certification through three temporary exact grants; signer stops')
  delivered=cli('delivery-start','--release',packages['delivery'],'--public',PUB,'--ui',start['ui'],'--ui-release',packages['ui'],'--owner-release',packages['owner']);assert delivered['exact_grant_count']==32
  exported=cli('export','--certified','--output',out/'exported672');assert exported['bytes']==672 and(out/'exported672').read_bytes()==(out/'invitation672').read_bytes()
  c=live.Client(sock,timeout=600)
  try:
   assert messenger.endpoint(c,4,464)==delivered['delivery']
   try:messenger.bind(c,4,delivered['delivery'],messenger.launcher(c),460,bytes.fromhex(delivered['delivery_release']))
   except ValueError:pass
   else:raise AssertionError('33rd exact operation binding unexpectedly admitted')
  finally:c.close()
  passed('actual CLI admits coordinator with eight exact bindings after signer teardown; total32 boundary rejects an additional binding and certified export remains usable')
  report=dict(schema=1,result='pass',image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),packages=package_records,checks=checks,commands=commands,private_key_exported=False,limits='One QEMU public-command admission component. Device creation uses native CLI for this test; actual graphical creation/approval/compose/receive belongs to the central campaign.')
  (out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:
  if process and process.poll()is None:os.killpg(process.pid,signal.SIGTERM);process.wait(20)
  log.close()
if __name__=='__main__':main()
