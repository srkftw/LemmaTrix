"""Content grant/job boot-epoch regression using two fresh ordinary guests."""
import argparse,hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import content
from library_journey import Node


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 a.output=a.output.resolve();a.output.mkdir(exist_ok=False);observed=[];old=None
 def denied(call):
  try:call()
  except ValueError:return
  raise AssertionError('stale content token accepted')
 for phase in (0,1):
  node=Node(str(phase),a.output,a.image.resolve())
  try:
   with node.client()as c:
    caller=struct.unpack_from('<Q',c.request(2),32)[0];sdk=content.api(c)
    if old:
     denied(lambda:sdk.objects(306,old['handle']));denied(lambda:sdk.objects(304,old['job']))
    raw=content.original_wave(.01,2)if phase==0 else content.original_wave(.02,1)
    h,m,chunks,proofs=content.reserve(c,raw,991,hashlib.sha256(b'explicit-provider').digest(),hashlib.sha256(b'explicit-federation').digest())
    job=sdk.objects(301,h,0,data=proofs[0])[0][1]
    record=dict(caller=caller,handle=h,job=job,manifest_sha256=hashlib.sha256(m).hexdigest())
    if old:
     assert caller!=old['caller'] and h!=old['handle'] and job!=old['job'],(old,record)
     denied(lambda:sdk.objects(306,old['handle']));denied(lambda:sdk.objects(304,old['job']))
     assert sdk.objects(306,h)[1]==m and sdk.objects(304,job)[0][2]==1
    else:old=record
    observed.append(record)
  finally:node.stop()
 result=dict(schema=1,result='passed',image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),two_fresh_guests=observed,checks=['old root and job denied before fresh allocation','distinct boot caller/root/job tokens','old root and job remain denied after fresh different-manifest allocations','fresh selected grants and jobs remain usable'])
 (a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

if __name__=='__main__':main()
