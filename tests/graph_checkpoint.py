"""Actual guest schema2 checkpoint/reclaim and post-checkpoint edit checks."""
import argparse,json,struct,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import live,projects

def publish(c,name,source,root=0,head=None,parent=0):
 payload=projects.manifest([('Main.lean',10,source)])
 node,identity=projects.node(c,payload,11,parent)
 raw=bytes.fromhex(head) if head else bytes(32)
 f,_=c.objects(22,node,root,len(name),data=raw+name.encode().ljust(64,b'\0'))
 return f[1],identity,node

def check(c):
 source,sourceid=projects.node(c,b'def value : UInt64 := 7\n',10)
 root,origin,manifest=publish(c,'checkpoint-native',sourceid)
 changed,changedid=projects.node(c,b'def value : UInt64 := 9\n',10,source)
 root,head,revised=publish(c,'checkpoint-native',changedid,root,origin,manifest)
 private=c.import_object(b'unrelated private retention choice',1)
 binding=c.objects(29,root)[0][7]
 f,data=c.objects(41,root,1,data=bytes.fromhex(head))
 assert len(data)==192 and data[96:128].hex()==origin and data[128:160].hex()==head
 created,reclaimed,archive,schema=struct.unpack_from('<4Q',data,160)
 assert created==2 and reclaimed==4 and archive==1 and schema==2,(created,reclaimed,archive,schema)
 assert projects.project_identity(c,root)==origin
 assert c.objects(29,root)[0][7]==binding
 newhead,files=projects.snapshot(c,root)
 assert newhead!=head and files['Main.lean']==b'def value : UInt64 := 9\n'
 assert c.read_object(private)==b'unrelated private retention choice'
 try:projects.resolve(c,root,head)
 except ValueError:pass
 else:raise AssertionError('archival parent was falsely advertised as available current closure')
 cap=c.objects(24,root)[0][1]
 schema_meta,_=c.objects(21,cap);assert schema_meta[5]==2
 current_source=projects.decode_manifest(c.read_object(cap))[0][2]
 current_handle=projects.resolve(c,root,current_source)
 after,afterid=projects.node(c,b'def value : UInt64 := 12\n',10,current_handle)
 root,final,_=publish(c,'checkpoint-native',afterid,root,newhead,cap)
 assert projects.project_identity(c,root)==origin
 assert projects.snapshot(c,root)[1]['Main.lean']==b'def value : UInt64 := 12\n'
 return dict(checks=['schema2 checkpoint preserves verifiable origin and archived head commitments','explicit source-only scope creates two records and reclaims four superseded owner records','private object and live root capability binding preserved','archival payload unavailable reported by scoped lookup; ordinary editing continues with stable identity'],project_id=origin,archived_head=head,checkpoint_head=newhead,current_head=final,created=created,reclaimed=reclaimed)

def main():
 p=argparse.ArgumentParser();p.add_argument('--socket',required=True,type=Path);a=p.parse_args();c=live.Client(a.socket,timeout=240)
 try:print(json.dumps(check(c),indent=2))
 finally:c.close()
if __name__=='__main__':main()
