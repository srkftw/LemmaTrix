"""Continue the already selected live collection to an approved partial checkpoint.

This is a narrow recovery helper for an existing explicitly owned fixture. It
does not provision a key, backing, consumer row or provider payload. Consent,
pause and retention use actual native input; all inspection uses public SDKs.
"""
import argparse,hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import content,library_peer,network,releases
from creator_journey import require,rendered_text
from graphical_devices import DeviceInput
from library_checkpoint_resume import Existing,ProcessIdentity
from library_journey import appcall,wait
from library_game_save import preserve_failure


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base',type=Path,required=True);p.add_argument('--seconds',type=int,required=True);a=p.parse_args();out=a.base.resolve()
 original=json.loads((out/'failure.json').read_text());personal=Existing(out/'personal');entry=next(x for x in original['guests'] if Path(x['directory']).name=='personal');personal.proc=ProcessIdentity(entry['pid']);personal.graphics=personal.base/'display.qmp';personal.ui=DeviceInput('qemu',personal.graphics)
 lib=personal.role(1919);registry=Existing(out/'registry');seed1=Existing(out/'seed1');seed2=Existing(out/'seed2');fid=hashlib.sha256(releases.public_modulus(out/'federation.pub')).digest();wave=content.original_wave(a.seconds,2);manifest,_,_=content.commitments(wave);rootsha=hashlib.sha256(manifest).digest()
 report=dict(image=hashlib.sha256((out/'platform.bin').read_bytes()).hexdigest(),checks=[],limitations=['explicit development encrypted personal backing; no physical-vault durability claim','these existing seed instances are volatile; durable independent seeds are a separately executed check','decoded sample capture; speaker output not exercised'])
 def passed(label,**facts):
  report['checks'].append(dict(check=label,result='passed',**facts));(out/'journey.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',label,flush=True)
 def word(offset):
  with personal.client()as c:return struct.unpack_from('<Q',appcall(c,lib,701)[1],offset)[0]
 def job():
  with personal.client()as c:return struct.unpack('<16Q',appcall(c,lib,704,0,0,128)[1])
 try:
  with personal.client()as c:
   f,data=appcall(c,lib,703,0,0,128);row=struct.unpack('<16Q',data)
   _,library_state=appcall(c,lib,701);require(row[1]!=0 and struct.unpack_from('<Q',library_state,16)[0]==1 and struct.unpack_from('<Q',library_state,96)[0]==0,'selected Add reference/policy differs from preserved state')
   _,sha=appcall(c,lib,703,0,1216,32);require(sha==rootsha,'preserved row names another immutable manifest')
   require(content.api(c).objects(312)[0][1]==0,'personal payload appeared before acquisition consent')
  # Renew explicit operator terms under the same configured relationships. No
  # reserve/write or payload ingestion occurs on either already populated seed.
  for slot,node in [(0,registry),(1,seed1),(2,seed2)]:
   peer=node.role(1025);_,material=network.load_credentials(out/('client'+str(slot)+'.credential'))
   with node.client()as c:
    h=0
    if slot:
     h=content.reserve(content.api(c),wave,7001,material[32:64],fid)[0]
     state=content.api(c).objects(306,h)[0];require(state[2]==2 and state[3]==len(wave),'original seed does not own complete verified payload')
     h=content.api(c).objects(308,h,peer)[0][1]
    library_peer.call(c,peer,402,0);library_peer.call(c,peer,400,0,1 if not slot else 2,1 if not slot else int.from_bytes(rootsha[:8],'little')|1,h,16777216,100000,material[:32]+material[64:96]+(fid if not slot else rootsha))
  passed('preserved native metadata Add is a stored reference before acquisition consent; both existing seeds still own the complete selected bytes',metadata_reference=row[1],total_bytes=len(wave),manifest_sha256=rootsha.hex(),provider_payload_reimported=False)
  personal.ui.press(34);wait(lambda:word(208)==1,30,'native bounded acquisition approval');personal.ui.press(28)
  def checked():
   q=job()
   if q[0] in (12,13,14):raise RuntimeError(('acquisition failed',q))
   return q[4]>=3 and q[0]<10
  wait(checked,900,'three checked chunks');personal.ui.press(25);wait(lambda:job()[0]==11,60,'native acquisition pause')
  with personal.client()as c:
   q,_=appcall(c,lib,705,0);state=content.api(c).objects(306,q[1])[0];checked_bytes=state[3];require(8192<=checked_bytes<len(wave),'checkpoint has no partial checked progress')
  personal.ui.press(19);wait(lambda:word(376)==1,60,'native checkpoint retention request');wait(lambda:rendered_text(personal.ui.frame(),16,16,7)=='TRUSTED',300,'trusted selected partial checkpoint approval');personal.ui.press(28)
  wait(lambda:word(376)==0 and word(176)==17,1200,'encrypted selected partial checkpoint committed')
  with personal.client()as c:
   raw=c.request(246,struct.pack('<8Q',246,0,3,0,0,0,0,1));fields=struct.unpack_from('<8Q',raw);require(fields[2]==1 and fields[3]==checked_bytes,'retained checkpoint changed checked-byte count')
  passed('native pause and trusted R retain only checked partial chunks plus selected metadata',verified_bytes=checked_bytes,total_bytes=len(wave),generation=fields[1],complete=False)
  (out/'partial-checkpoint.ppm').write_bytes(personal.ui.frame().ppm());personal.stop();seed1.stop()
 except BaseException as error:
  preserve_failure([personal],out,error);raise
 finally:
  if personal.ui:personal.ui.close();personal.ui=None


if __name__=='__main__':main()
