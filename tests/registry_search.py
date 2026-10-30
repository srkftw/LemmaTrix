"""Search and structural descriptor checks on an explicitly retained real catalog."""
import argparse,hashlib,json,os,signal,struct,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import federation,live,releases,server_store

def main():
 p=argparse.ArgumentParser();p.add_argument('--catalog',required=True,type=Path);p.add_argument('--key',required=True,type=Path);p.add_argument('--public',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args();a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=False);sock=a.output/'portal.sock';log=(a.output/'guest.log').open('wb');proc=subprocess.Popen([str(ROOT/'lt'),'run','--socket',str(sock),'--server-store',str(a.catalog/'registry.store')],cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
 try:
  deadline=time.monotonic()+90
  while not sock.exists():
   assert proc.poll() is None
   if time.monotonic()>deadline:raise TimeoutError('boot')
   time.sleep(.05)
  c=live.Client(sock,timeout=240)
  try:
   raw,manifest=releases.make(ROOT/'build/live/apps/registry.bin','consumer-registry','1.0.0',2175,a.key,profile=2);path=a.output/'registry.ltrel';path.write_bytes(raw);c.request(10,releases.project('consumer-registry')+releases.public_modulus(a.public));info=c.stage(path);c.request(23,bytes.fromhex(info['release_id'])+struct.pack('<Q',2175));slot=struct.unpack_from('<Q',c.request(24),8)[0];instance=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',slot)),8)[0]
   server_store.call(c,230);grant=server_store.call(c,231,instance,1,1048576,hashlib.sha256(b'Campaign005 consumer catalog explicit namespace').digest())[0][1];federation.configure(c,instance,a.catalog/'federation.pub','consumer',grant,allowed_rights=8191);federation.call(c,instance,10)
   cursor=0;records=[];descriptor=None
   while True:
    try:fields,data=federation.call(c,instance,21,h=cursor,a=2,b=5,data=b'CrAtE')
    except ValueError as error:
     if str(error)=='native registry status6':break
     raise
    assert len(data)==768 and struct.unpack_from('<Q',data,16)[0]==5 and fields[3]>cursor;cursor=fields[3];descriptor=data
    _,consumer=federation.call(c,instance,20,h=fields[2]);assert b'Crate Workshop' in consumer;records.append(hashlib.sha256(consumer).hexdigest())
   assert len(records)==2 and len(set(records))==2,records
   exact_fields,exact=federation.call(c,instance,22,data=descriptor+descriptor[320:352]);assert exact==descriptor and exact_fields[1]==5
   altered_cached=bytearray(descriptor);altered_cached[-1]^=1
   try:federation.call(c,instance,22,data=bytes(altered_cached)+descriptor[320:352])
   except ValueError as error:assert str(error)=='native registry status3'
   else:raise AssertionError('altered cached signature acquired fast-check authority')
   for h,facet,query,status in [(0,1,b'crate',6),(0,2,b'absent',6),(17,0,b'',2),(0,3,b'',2),(0,0,b'\0',2),(0,0,b'a'*65,2)]:
    try:federation.call(c,instance,21,h=h,a=facet,b=len(query),data=query)
    except ValueError as error:assert str(error)==f'native registry status{status}',str(error)
    else:raise AssertionError('invalid or unmatching search unexpectedly returned a record')
   # A federation signature authenticates bytes but cannot change the canonical
   # descriptor's media/game facet relationship accepted by this verifier.
   altered=bytearray(descriptor);struct.pack_into('<Q',altered,16,4)
   with tempfile.TemporaryDirectory() as td:
    header=Path(td)/'header';header.write_bytes(altered[:512]);altered[512:]=releases.pkg.crypto(['dgst','-sha256','-sign',a.catalog/'federation.pem',header]).stdout
   try:federation.call(c,instance,11,data=bytes(altered)+bytes(altered[320:352]))
   except ValueError as error:assert str(error)=='native registry status5'
   else:raise AssertionError('signed media descriptor accepted a game facet')
   # A newly signed revocation enters the same shared verifier cache. The
   # old exact positive bytes must cease passing the fast per-chunk check.
   last_slot=fields[2];last_sequence=struct.unpack_from('<Q',descriptor,48)[0]
   federation.call(c,instance,8,h=last_slot,a=last_sequence);revocation=federation.sign_once(c,instance,a.catalog/'federation.pem','consumer',8191);assert revocation['listing']==3
   try:federation.call(c,instance,22,data=descriptor+descriptor[320:352])
   except ValueError as error:assert str(error)=='native registry status3'
   else:raise AssertionError('known revocation did not invalidate exact cached authority')
   report=dict(image=hashlib.sha256((ROOT/'build/live/guest.bin').read_bytes()).hexdigest(),registry_sha256=hashlib.sha256((ROOT/'build/live/apps/registry.bin').read_bytes()).hexdigest(),source_catalog=str(a.catalog),matches=records,case_insensitive=True,facet_filter=True,pagination=True,malformed_denied=True,signed_facet_substitution_denied=True,backing_copied=False,fast_current_known_only=True,known_revocation_denied=True)
   (a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
   try:c.request(70)
   except EOFError:pass
  finally:c.close()
  proc.wait(timeout=20)
 finally:
  if proc.poll() is None:os.killpg(proc.pid,signal.SIGKILL);proc.wait()
  log.close()
if __name__=='__main__':main()
