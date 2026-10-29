"""Focused actual guest transactions; requires an explicitly running guest socket."""
import argparse,hashlib,json,struct,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import live,projects

def denied(call,code):
 try:call()
 except ValueError as e:
  assert str(e)==f'Objects status{code}',str(e)
 else:raise AssertionError('invalid transaction accepted')

def records(name,seed=b'import Guest.ProjectSDK\n'):
 first=seed+b'-- authorized source\n'*1800
 resource=bytes(range(256))*160
 a=projects.canonical_node(10,first);b=projects.canonical_node(10,resource)
 payload=projects.manifest([('Main.lean',10,a),('assets/input.bin',10,b)])
 head=projects.canonical_node(11,payload)
 return [dict(name=name,head=head)],[dict(kind=11,id=head,payload=payload),dict(kind=10,id=b,payload=resource),dict(kind=10,id=a,payload=first)]

def begin(client,roots,nodes):
 r=roots[0];name=r['name'].encode()
 return client.objects(35,a=1,b=len(nodes),c=sum(len(n['payload']) for n in nodes),data=struct.pack('<2Q',0,len(name))+bytes.fromhex(r['head'])+name.ljust(80,b'\0'))[0][1]

def offer(client,txn,index,node):
 payload=node['payload']
 client.objects(36,txn,index,node['kind'],len(payload),data=bytes.fromhex(node['id'])+bytes.fromhex(node.get('parent','00'*32))+hashlib.sha256(payload).digest())
 for off in range(0,len(payload),512):client.objects(37,txn,index,off,data=payload[off:off+512])

def check(client):
 before=projects.roots(client);checks=[]
 selected,nodes=records('transaction-main')
 txn=begin(client,selected,nodes)
 assert projects.roots(client)==before
 offer(client,txn,0,nodes[0])
 assert projects.roots(client)==before
 assert all(x['head']!=selected[0]['head'] for x in projects.roots(client))
 status,_=client.objects(40,txn);assert status[2:6]==(1,3,len(nodes[0]['payload']),sum(len(n['payload']) for n in nodes))
 client.objects(39,txn)
 denied(lambda:client.objects(40,txn),3)
 assert projects.roots(client)==before
 checks.append('partial stages remain unrooted; progress is actual received bytes; cancel reclaims and invalidates transaction')
 imported=projects.import_records(client,selected,nodes)[0]
 head,files=projects.snapshot(client,imported['cap'])
 assert head==selected[0]['head'] and sum(map(len,files.values()))>65536
 assert files['assets/input.bin']==nodes[1]['payload']
 logical=projects.project_identity(client,imported['cap']);binding=client.objects(29,imported['cap'])[0][7]
 assert logical==head
 duplicate,_=records('transaction-copy')
 copied=projects.import_records(client,duplicate,nodes)[0]
 assert projects.project_identity(client,copied['cap'])==logical
 assert client.objects(29,copied['cap'])[0][7]!=binding
 checks.append('unordered closure >64KiB validates atomically; reimport preserves content identity but receives a distinct live authority binding')
 # Omitting one source is invalid even if the root arrived first.
 missing,_=records('transaction-missing',b'different-root\n')
 badnodes=records('unused',b'different-root\n')[1][:2]
 denied(lambda:projects.import_records(client,missing,badnodes),2)
 assert not any(x['name']=='transaction-missing' for x in projects.roots(client))
 checks.append('missing dependencies fail without publishing a root prefix')
 badroots,badnodes=records('transaction-hash',b'different-hash\n')
 badnodes[1]['id']='13'*32
 denied(lambda:projects.import_records(client,badroots,badnodes),2)
 checks.append('substituted canonical node identity aborts private stage')
 extra,extra_nodes=records('transaction-extra',b'extra-root\n')
 payload=b'not in requested closure';extra_nodes.append(dict(kind=10,id=projects.canonical_node(10,payload),payload=payload))
 denied(lambda:projects.import_records(client,extra,extra_nodes),2)
 checks.append('extra unrelated object outside requested root closure is denied')
 return dict(checks=checks,root=imported,copy=copied,logical_project_id=logical,live_binding=binding,bytes=sum(len(n['payload']) for n in nodes))

def main():
 p=argparse.ArgumentParser();p.add_argument('--socket',type=Path,required=True);a=p.parse_args()
 c=live.Client(a.socket,timeout=240)
 try:print(json.dumps(check(c),indent=2))
 finally:c.close()
if __name__=='__main__':main()
