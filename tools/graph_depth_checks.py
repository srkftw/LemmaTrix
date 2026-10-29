"""Focused actual Objects traversal check for ordinary-shaped and deep graphs.

No host compiler, signing, vault or UI acceptance. Creates disposable authorized
records through ordinary graph operations, then checks publication, closure,
resolution, root pinning and collection without increasing service stack budgets.
"""
import argparse,json
from pathlib import Path
import live,projects


def check_shape(client,count):
 handles=[];identities=[];root=0
 try:
  parent=0
  for index in range(count):
   payload=('def lineageValue : UInt64 := '+str(index)+'\n').encode()
   parent,identity=projects.node(client,payload,10,parent)
   handles.append(parent);identities.append(identity)
  payload=projects.manifest([('Main.lean',10,identities[-1])])
  manifest,head=projects.node(client,payload,11);handles.append(manifest)
  name='deep-lineage-check'
  fields,_=client.objects(22,manifest,0,len(name),data=bytes(32)+name.encode().ljust(64,b'\0'));root=fields[1]
  assert projects.project_identity(client,root)==head
  expected=set(identities+[head]);seen=set();cursor=0
  while cursor<64:
   fields,ids=client.objects(26,root,cursor)
   if not fields[1]:break
   seen.add(ids[:32].hex())
   assert fields[3]>cursor
   cursor=fields[3]
  assert seen==expected
  for index in (0,count//2,count-1):
   handle=projects.resolve(client,root,identities[index])
   assert client.read_object(handle)==('def lineageValue : UInt64 := '+str(index)+'\n').encode()
  try:client.objects(8,handles[0])
  except ValueError as error:assert 'status8' in str(error)
  else:raise AssertionError('deep rooted ancestor was collected')
  client.objects(11)
  assert client.read_object(projects.resolve(client,root,identities[0]))==b'def lineageValue : UInt64 := 0\n'
  assert projects.snapshot(client,root)[0]==head
  return dict(source_lineage=count,total_nodes=count+1,head=head,checks=['complete root publication','every ancestor appears in bounded closure','old/middle/new Source resolution','root pin protects oldest ancestor','root survives actual collection and reopen'])
 finally:
  if root:client.objects(28,root)
  for handle in reversed(handles):
   try:client.objects(8,handle)
   except ValueError:pass


def check(client):
 return dict(shapes=[check_shape(client,n) for n in (23,48)],scope='explicit management graph operations;24-node ordinary quota shape plus49-node administrative stress; no compiler/signing and no resource-profile increase')


def main(argv=None):
 p=argparse.ArgumentParser(description='Bounded worklist graph traversal checks on a running guest')
 p.add_argument('--socket',type=Path,required=True);p.add_argument('--output',type=Path)
 args=p.parse_args(argv);client=live.Client(args.socket)
 try:
  result=check(client)
  if args.output:args.output.write_text(json.dumps(result,indent=2)+'\n')
  print(json.dumps(result,indent=2))
 finally:client.close()
 return 0
if __name__=='__main__':raise SystemExit(main())
