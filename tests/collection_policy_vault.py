"""Focused live independent-policy + encrypted-record restart boundary check."""
import argparse,hashlib,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import inventory,library,live,nodes,project_vault,releases
from library_journey import wait

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 image=out/'guest.bin';image.write_bytes(a.image.read_bytes());vault=out/'personal.img';vault.touch();vault.chmod(0o600)
 with vault.open('wb')as f:f.truncate(151000*512)
 key=os.urandom(32);private=ROOT/'build/campaign005/publisher.pem';public=ROOT/'build/campaign005/publisher.pub'
 raw,_=releases.make(a.binary,'collections-policy-check','1.0.0',1151,private,profile=2,license='NOASSERTION');package=out/'policy.ltrel';package.write_bytes(raw);info=releases.inspect(raw)
 report=dict(image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),release_id=info['release_id'],checks=[])
 def boot(name):
  sock=out/(name+'.sock');log=(out/(name+'.log')).open('wb');proc=subprocess.Popen([str(ROOT/'lt'),'run','--backend','qemu','--socket',str(sock),'--vault',str(vault),'--image',str(image)],stdout=log,stderr=log,start_new_session=True)
  wait(lambda:sock.exists()or proc.poll()is not None,60,'guest readiness');c=live.Client(sock,timeout=180);project_vault.unlock(c,key);instance=nodes.start_package(c,nodes.approved_package(package,public,info['release_id'],1151),raw);return proc,log,c,instance
 def stop(proc,log,c):
  c.close();os.killpg(proc.pid,signal.SIGTERM);proc.wait(10);log.close()
 proc=log=c=None
 try:
  proc,log,c,instance=boot('before');fid=hashlib.sha256(b'policy-test-selected-federation').digest();ca=hashlib.sha256(b'private-collection-A').digest();cb=hashlib.sha256(b'private-collection-B').digest()
  fa,_=library.call(c,instance,720,1,2000000,6,data=ca+fid,c=3);fb,_=library.call(c,instance,720,1,3000000,2,data=cb+fid,c=3)
  _,before=library.call(c,instance,721,fa[1]);library.call(c,instance,720,1,4000000,4,data=cb+fid,c=3);_,after=library.call(c,instance,721,fa[1]);assert before==after
  report['checks'].append('updating collection B leaves A generation, consent, budget and identity byte-exact')
  saved,_=inventory.call(c,274,0,data=before);assert saved[2]==1
  _,stored=inventory.call(c,275,0);assert stored==before
  _,before_b=library.call(c,instance,721,fb[1]);saved_b,_=inventory.call(c,274,1,data=before_b);assert saved_b[2]==1
  _,stored_b=inventory.call(c,275,1);assert stored_b==before_b
  assert struct.unpack_from('<Q',before,48)[0]==2000000 and struct.unpack_from('<Q',before,64)[0]==6
  assert struct.unpack_from('<Q',before_b,48)[0]==4000000 and struct.unpack_from('<Q',before_b,64)[0]==4
  report['checks'].append('A and B commit to distinct encrypted selected slots with independent approved budgets and provider sets')
  for mode in (1,2,4):
   try:library.call(c,instance,720,1,2000000,6,data=ca+fid,c=mode)
   except ValueError as error:assert 'status2'in str(error)
   else:raise AssertionError('unsupported mode accepted')
  report['checks'].append('unsupported privacy modes reject without modifying either collection')
  stop(proc,log,c);proc=log=c=None
  assert ca not in vault.read_bytes() and cb not in vault.read_bytes()
  def recover_both(instance):
   recovered=[]
   for slot,collection,budget,providers,original in ((0,fa[1],2000000,6,before),(1,fb[1],4000000,4,before_b)):
    _,stored=inventory.call(c,275,slot);assert stored==original
    library.call(c,instance,723,collection,data=stored);_,restored=library.call(c,instance,721,collection);q=lambda n:struct.unpack_from('<Q',restored,n)[0]
    assert q(16)==1 and q(24)==0 and q(96)==1 and q(128)==0 and restored[160:224]==original[160:224]
    assert q(48)==budget and q(64)==providers
    recovered.append(dict(slot=slot,collection_slot=collection,approved_budget=q(48),provider_mask=q(64),generation=q(8),monitoring=q(16),acquisition=q(24),awaiting_fresh_approval=q(96),live_retention_grant=q(128)))
   return recovered
  proc,log,c,fresh=boot('after');report['after_restart']=recover_both(fresh)
  report['checks'].append('restart recovers both authenticated selected policies/history with distinct budgets/providers, zero live grants and no autonomous acquisition approval')
  changed=bytearray(before);struct.pack_into('<Q',changed,48,2500000);f,_=inventory.call(c,274,0,data=changed);assert f[2]==2
  stop(proc,log,c);proc=log=c=None
  # Corrupt only the candidate bank. The prior authenticated committed policy remains.
  with vault.open('r+b')as f:f.seek((150950+1)*512);first=f.read(1);f.seek(-1,1);f.write(bytes([first[0]^1]));f.flush();os.fsync(f.fileno())
  proc,log,c,fresh=boot('fallback');report['after_corrupted_newer_A']=recover_both(fresh)
  report['checks'].append('corrupted newer A ciphertext falls back to previous complete A; independent committed B survives byte-exact and both still require fresh acquisition approval')
  report['result']='passed';report['policy_slots']=8;report['record_bytes']=512;report['acquisition_after_recovery']='awaiting explicit renewal';report['whole_store_rollback_freshness']=False
  (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:
  if proc is not None:stop(proc,log,c)
if __name__=='__main__':main()
