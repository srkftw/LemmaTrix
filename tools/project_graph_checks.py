"""Focused checks of the running guest graph and encrypted multi-root vault.

These are service-boundary checks, not graphical acceptance. Reuses the selected
built image; creates explicit disposable projects only in the requested session.
"""
import argparse,hashlib,json,struct
from pathlib import Path
import live,projects,project_vault


def reject(action,status):
 try:action()
 except ValueError as error:
  if f'status{status}' not in str(error):raise
 else:raise AssertionError('invalid graph operation accepted')


def canonical(kind,payload,parent=bytes(32)):
 return hashlib.sha256(struct.pack('<4Q',0x3145444f4e544c,1,kind,1)+hashlib.sha256(payload).digest()+parent).hexdigest()


def publish(client,name,entries,root=0,expected=bytes(32),parent=0):
 payload=projects.manifest(entries);manifest,identity=projects.node(client,payload,11,parent)
 assert identity==canonical(11,payload,expected if parent else bytes(32))
 data=expected+name.encode().ljust(64,b'\0')
 f,ids=client.objects(22,manifest,root,len(name),data=data)
 assert ids[:32].hex()==identity
 return f[1],identity,manifest


def check(client,vault=False):
 checks=[]
 source=b'import Guest.ProjectSDK\n-- arbitrary UTF-8 source: '+chr(955).encode()+b'\n'+b'-- source resource\n'*2300
 resource=bytes(range(256))*140
 h,a=projects.node(client,source,10);r,b=projects.node(client,resource,10)
 assert a==canonical(10,source) and b==canonical(10,resource)
 root,head,manifest=publish(client,'graph-primary',[('Main.lean',10,a),('assets/input.bin',10,b)])
 second_data=b'private second selected project\n'
 second_source,second_id=projects.node(client,second_data,10)
 second,second_head,_=publish(client,'graph-secondary',[('Notes.txt',10,second_id)])
 checks.append('canonical typed identities; two named project roots and aggregate source/resource bytes exceed64KiB')
 reject(lambda:client.objects(25,second,data=bytes.fromhex(a)),1)
 reject(lambda:client.objects(8,h),8)
 checks.append('root-scoped resolution denies unrelated content; rooted content cannot be dropped')
 for name in ('../secret','a//b','a/./b','a/../b','/absolute','C:drive'):
  encoded=name.encode();bad=struct.pack('<4Q',projects.MAGIC,1,1,0)+struct.pack('<2Q',10,len(encoded))+bytes.fromhex(a)+encoded.ljust(80,b'\0')
  reject(lambda bad=bad:client.import_object(bad,11),2)
 bad=projects.manifest([('same',10,a),('same',10,b)])
 reject(lambda:client.import_object(bad,11),2)
 bad=projects.manifest([('missing',10,'55'*32)])
 reject(lambda:client.import_object(bad,11),2)
 checks.append('guest rejects traversal, ambiguous paths, duplicate names and missing typed references')
 changed=source+b'-- intentional semantic source revision\n'
 newer,newid=projects.node(client,changed,10,h)
 assert newid==canonical(10,changed,bytes.fromhex(a))
 root,newhead,newmanifest=publish(client,'graph-primary',[('Main.lean',10,newid),('assets/input.bin',10,b)],root,bytes.fromhex(head),manifest)
 reject(lambda:client.objects(22,newmanifest,root,len('graph-primary'),data=bytes.fromhex(head)+b'graph-primary'.ljust(64,b'\0')),8)
 actual,files=projects.snapshot(client,root)
 assert actual==newhead and files['Main.lean']==changed
 old=projects.resolve(client,root,a)
 assert client.read_object(old)==source
 checks.append('revision ancestry survives reopen; stale expected-head publication is rejected')
 private=client.import_object(b'unsaved private object',1)
 private_fields,private_hash=client.objects(5,private)
 result=dict(checks=checks,roots=[dict(cap=root,name='graph-primary',head=newhead),dict(cap=second,name='graph-secondary',head=second_head)],private=private,private_sha256=private_hash.hex(),expected_bytes=len(source)+len(changed)+len(resource)+len(second_data))
 if vault:
  saved=project_vault.retain(client,[root,second]);inventory=project_vault.inventory(client)
  assert saved['bytes']>65536 and saved['projects']==2
  assert {x['name'] for x in inventory['projects']}=={'graph-primary','graph-secondary'}
  assert private_hash.hex() not in {n['sha256'] for n in inventory['nodes']}
  assert bytes.fromhex(a) in [bytes.fromhex(n['id']) for n in inventory['nodes']]
  checks.append('real encrypted streaming vault retains both selected named graphs and ancestry, excluding private object')
  result['saved']=saved;result['inventory']=inventory
 return result


def verify_recovery(client,expected):
 recovered=project_vault.recover(client)
 assert {(r['name'],r['head']) for r in recovered['roots']}=={(r['name'],r['head']) for r in expected['roots']}
 for old in expected['roots']:
  reject(lambda old=old:client.objects(24,old['cap']),3)
 reject(lambda:client.objects(5,expected['private']),3)
 roots=projects.roots(client)
 assert len(roots)==2
 for root in roots:
  actual,files=projects.snapshot(client,root['cap'])
  assert actual==root['head'] and files
 return dict(recovered=recovered,checks=['fresh session restores names, stable identities, complete content and ancestry; stale handles and unsaved private content denied'])


def main(argv=None):
 p=argparse.ArgumentParser(description='Focused real-guest Project/Vault boundary checks')
 p.add_argument('--socket',required=True,type=Path);p.add_argument('--key',type=Path);p.add_argument('--vault',action='store_true');p.add_argument('--recover',type=Path);p.add_argument('--output',type=Path)
 args=p.parse_args(argv);client=live.Client(args.socket)
 try:
  if args.key:project_vault.unlock(client,args.key.read_bytes())
  result=verify_recovery(client,json.loads(args.recover.read_text())) if args.recover else check(client,args.vault)
  if args.output:args.output.write_text(json.dumps(result,indent=2)+'\n')
  print(json.dumps(result,indent=2))
 finally:client.close()
 return 0
if __name__=='__main__':raise SystemExit(main())
