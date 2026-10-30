"""Only the verified-stage cancellation/cleanup read boundary, using a signed caller.

An optional baseline demonstrates actual wiped bytes being returned by operation43;
the selected corrected image must deny that read while bounded cleanup is active.
The unchanged signed harness only forwards ordinary Objects IPC under its own UID.
"""
import argparse,hashlib,json,sys,types
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import nodes,releases
from creator_retention import Session,require
from import_jobs import Actor,graph,stage,detail,denied
from library_journey import wait


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--baseline-image',type=Path);p.add_argument('--package',type=Path,default=ROOT/'build/campaign005/import-jobs-final/import-owner.ltrel');p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);checks=[];info=releases.inspect(a.package.read_bytes())
 def run(name,image,corrected):
  image=image.resolve();identity=hashlib.sha256(image.read_bytes()).hexdigest();session=Session(types.SimpleNamespace(output=out/name,image=image,expected_image=identity,backend='qemu'),None)
  try:
   session.boot()
   with session.client()as c:
    instance=nodes.start_package(c,nodes.approved_package(a.package,a.public,info['release_id'],127),a.package.read_bytes());actor=Actor(c,instance);selected,records=graph('cancel-verified',83,edges=32);transaction=stage(actor,selected,records);actor.objects(44,transaction,32001)
    def sealed():
     f,d=detail(actor,transaction)
     return (f,d)if f[2]==2 and d[5]>=1 else None
    wait(sealed,180,'actual first verified/typed private payload');actor.objects(46,transaction,1);before=actor.objects(43,transaction,0,0,512)[1];require(before==records[0]['payload'][:512],'actual checked bytes differ before cancellation');actor.objects(46,transaction,3)
    if corrected:denial=denied(lambda:actor.objects(43,transaction,0,0,512),3);after=None
    else:
     fields,after=actor.objects(43,transaction,0,0,512);require(fields[1]==512 and after==bytes(512) and after!=before,'baseline did not reproduce cached verification over wiped payload');denial=None
    cleanup,progress=detail(actor,transaction);require(cleanup[2]==5 and cleanup[6]==90,'observed read did not occur during active bounded cleanup');require(not actor.objects(23,a=0)[0][1],'cancelled import published a root');actor.objects(46,transaction,4)
   result=dict(check='cancelled verified stage is denied before cleanup finishes' if corrected else 'baseline reproduces wiped bytes returned under prior cached verification',result='passed',image=identity,package_release=info['release_id'],instance=instance,transaction=transaction,before_sha256=hashlib.sha256(before).hexdigest(),denial=denial,after_sha256=hashlib.sha256(after).hexdigest()if after is not None else None,cleanup_fields=list(cleanup),cleanup_detail=list(progress));checks.append(result);(out/'result.json').write_text(json.dumps(dict(checks=checks,host_memory_patches=False,new_signing_or_compilation=False),indent=2)+'\n');print('PASS',result['check'],flush=True)
  finally:session.stop(hard=True)
 if a.baseline_image:run('baseline',a.baseline_image,False)
 run('fixed',a.image,True)
if __name__=='__main__':main()
