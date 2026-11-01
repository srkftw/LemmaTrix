"""Native protected purpose2 static-node credential retain/restart/recover."""
import argparse,hashlib,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live,identity,messenger,nodes,onion,releases,server_store
from onion_route import create

def main():
 p=argparse.ArgumentParser();p.add_argument('--image',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args();d=a.output.resolve();d.mkdir(parents=True,exist_ok=False)
 image=d/'guest.bin';image.write_bytes(a.image.read_bytes());disk=d/'operator.img';server_store.provision(disk);sock=d/'portal.sock';log=(d/'guest.log').open('ab');proc=c=None;checks=[]
 # This deterministic high-entropy credential is a public test fixture. Node
 # private transport/onion/signing keys are created exclusively by each guest.
 credential=hashlib.sha256(b'published operator retention test credential').digest()
 raw,_=releases.make(ROOT/'build/live/apps/identity.bin','node-identity','1.0.0',0,ROOT/'tests/keys/development-rsa.pem',profile=2);package=d/'identity.ltrel';package.write_bytes(raw)
 def start():
  nonlocal proc,c
  sock.unlink(missing_ok=True);proc=subprocess.Popen([str(ROOT/'lt'),'run','--image',str(image),'--backend','qemu','--socket',str(sock),'--server-store',str(disk)],cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
  end=time.monotonic()+90
  while not sock.exists():
   if proc.poll()is not None or time.monotonic()>end:raise RuntimeError('operator start')
   time.sleep(.05)
  c=live.Client(sock,timeout=600)
 def stop():
  nonlocal proc,c
  if c:c.close();c=None
  if proc and proc.poll()is None:os.killpg(proc.pid,signal.SIGTERM);proc.wait(20)
  proc=None
 def authorize():
  who=next(row[0] for row in identity.instances(c) if row[0]&255==6);c.request(178,struct.pack('<2Q',who,1))
 def passed(s):checks.append(s);print('PASS',s,flush=True)
 def denied(fn):
  try:fn()
  except ValueError:return
  raise AssertionError('native access incorrectly accepted')
 try:
  start();identity.start(c,package,ROOT/'tests/keys/development-rsa-public.pem');cert,pin=create(c,'127.0.0.1:39127','credential test family')
  denied(lambda:onion.call(c,43,data=credential));passed('attached operator backing alone does not authorize credential retention')
  authorize();onion.call(c,43,data=credential);onion.call(c,43,data=credential)
  with disk.open('rb') as backing:
   backing.seek(56*512);assert backing.read(8*512)==bytes(8*512),'operator retention overwrote ServiceJobs public receipt keys'
   backing.seek(8*512);assert backing.read(16*512)==bytes(16*512),'operator retention overwrote ServerStore roots'
  passed('dedicated sectors1..6 preserve existing ServerStore roots and ServiceJobs key regions')
  public=c.request(2);stop();start()
  denied(lambda:onion.call(c,44,data=credential));authorize();denied(lambda:onion.call(c,44,data=bytes(32)))
  onion.call(c,44,data=credential);_,restored=onion.call(c,25,h=4);assert restored[:480]==cert and restored[480:]==pin
  passed('actual guest restart, explicit consent, wrong-key denial and native private/public possession recovery')
  onion.call(c,45);denied(lambda:onion.call(c,25,h=4));denied(lambda:onion.call(c,44,data=credential));passed('lock clears accessible static keys and revokes operator store grant')
  authorize();onion.call(c,44,data=credential);_,restored=onion.call(c,25,h=4);assert restored[:480]==cert
  passed('fresh explicit operator unlock restores same certified node without host private-key export')
  report=dict(schema=1,result='pass',image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),checks=checks,public_certificate_sha256=hashlib.sha256(cert).hexdigest(),limits='Static DH credentials only; no live channel counters or Identity signing seed persisted. Local native test, not physical power-loss proof.')
  (d/'evidence.json').write_text(json.dumps(report,indent=2)+'\n')
 finally:stop();log.close()
if __name__=='__main__':main()
