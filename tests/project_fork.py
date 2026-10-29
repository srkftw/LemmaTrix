"""Guest fork identity, exact provenance, publisher scope and independent edits."""
import argparse,hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import live,projects

def check(c):
 source,sourceid=projects.node(c,b'def weight : UInt64 := 7\n',10)
 resource,resourceid=projects.node(c,b'5\n',10)
 payload=projects.manifest([('Main.lean',10,sourceid),('accent.txt',10,resourceid)])
 manifest,head=projects.node(c,payload,11)
 root=c.objects(22,manifest,0,8,data=bytes(32)+b'upstream'.ljust(64,b'\0'))[0][1]
 original_binding=c.objects(29,root)[0][7]
 publisher=hashlib.sha256(b'explicit test publisher public-key identity').digest()
 name=b'changed-fork'
 fields,data=c.objects(42,root,len(name),data=bytes.fromhex(head)+publisher+name.ljust(64,b'\0'))
 assert len(data)==192 and fields[1],(fields,len(data))
 fork=fields[1];forkhead=data[:32].hex();lineage=data[96:128].hex()
 assert data[128:160].hex()==head and data[160:192].hex()==head
 logical=projects.project_identity(c,fork)
 assert logical==forkhead and logical!=head
 assert c.objects(29,fork)[0][7]!=original_binding
 assert projects.project_identity(c,root)==head
 frozen=c.objects(24,fork)[0][1];entries=projects.decode_manifest(c.read_object(frozen))
 assert ('.fork',15,lineage) in entries
 lineage_handle=projects.resolve(c,fork,lineage);provenance=c.read_object(lineage_handle)
 assert len(provenance)==208 and struct.unpack_from('<Q',provenance,32)[0]==0x314b524f46544c
 assert provenance[48:80].hex()==head and provenance[80:112].hex()==head
 assert provenance[144:176]==publisher and any(provenance[176:208])
 new=[]
 for path,kind,identity in entries:
  if kind!=10:new.append((path,kind,identity));continue
  old=projects.resolve(c,fork,identity)
  contents=b'def weight : UInt64 := 19\n' if path=='Main.lean' else b'11\n'
  _,changed=projects.node(c,contents,10,old);new.append((path,10,changed))
 changed,changedid=projects.node(c,projects.manifest(new),11,frozen)
 c.objects(22,changed,fork,len(name),data=bytes.fromhex(forkhead)+name.ljust(64,b'\0'))
 assert projects.project_identity(c,fork)==logical
 assert projects.snapshot(c,fork)[1]=={'Main.lean':b'def weight : UInt64 := 19\n','accent.txt':b'11\n'}
 assert projects.snapshot(c,root)[1]=={'Main.lean':b'def weight : UInt64 := 7\n','accent.txt':b'5\n'}
 return dict(upstream_project=head,upstream_head=head,fork_project=logical,fork_head=changedid,lineage=lineage,publisher=publisher.hex(),checks=['fresh guest nonce creates distinct canonical identity','typed Fork commits exact upstream identity/head and chosen publisher','local root authority is fresh','independent source/resource edits preserve fork identity and upstream bytes'],signature='no signature claimed before a scheme3 publisher release covers this source root')

def main():
 p=argparse.ArgumentParser();p.add_argument('--socket',required=True,type=Path);p.add_argument('--output',type=Path);a=p.parse_args();c=live.Client(a.socket)
 try:report=check(c)
 finally:c.close()
 if a.output:a.output.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report,indent=2))

if __name__=='__main__':main()
