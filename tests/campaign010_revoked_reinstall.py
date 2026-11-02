"""Actual public Launcher install/start/reinstall refusal after exact revocation."""
import argparse,hashlib,json,struct,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import releases
from creator_journey import Journey

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('image','release','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 j=Journey(SimpleNamespace(output=a.output/'guest',image=a.image,backend='qemu'))
 raw=a.release.read_bytes();info=releases.inspect(raw,raw[576:608]);report=dict(schema=1,result='running',image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),release=info,checks=[]);start=time.monotonic()
 try:
  j.boot(vault=False)
  with j.client()as c:
   c.request(10,bytes.fromhex(info['project_id'])+raw[576:608]);c.stage(a.release)
   c.request(23,bytes.fromhex(info['release_id'])+struct.pack('<Q',info['rights']))
   slot=struct.unpack_from('<Q',c.request(24),8)[0];c.request(30,bytes.fromhex(info['release_id']))
   try:c.request(25,struct.pack('<Q',slot))
   except ValueError as error:report['checks'].append(dict(check='revoked installed release cannot start',result='pass',error=str(error)))
   else:raise AssertionError('revoked release started')
   inspected=c.stage(a.release)
   if inspected['release_id']!=info['release_id']:raise AssertionError('inspection changed release')
   c.request(23,bytes.fromhex(info['release_id'])+struct.pack('<Q',info['rights']))
   try:c.request(24)
   except ValueError as error:report['checks'].append(dict(check='same exact revoked release remains inspectable but cannot reinstall through a fresh slot',result='pass',error=str(error)))
   else:raise AssertionError('revoked release reinstalled')
  report['result']='pass'
 except BaseException as error:report.update(result='failure',error=repr(error),traceback=traceback.format_exc());raise
 finally:
  j.stop(hard=True);report['elapsed_seconds']=time.monotonic()-start;(a.output/'execution.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True)
if __name__=='__main__':main()
