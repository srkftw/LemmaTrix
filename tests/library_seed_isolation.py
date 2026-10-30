"""Read a retained seed after the publisher and the other retained seed stop.

Consumes the actual protocol-replication run's own stores and credentials. No
payload is imported, no disk is copied, and no guest memory is inspected.
"""
import argparse,hashlib,json,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import content,network,library_peer
from library_durable_replication import Existing,existing_relation,provision,wait_auth,role,startup_json
from library_journey import wait

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--replication',type=Path,required=True)
 p.add_argument('--source',type=Path,required=True)
 p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();base=a.replication.resolve()
 def finished():
  try:
   r=json.loads((base/'result.json').read_text())
   return r if any(x['check']=='original volatile publisher packages stopped before retained reads' for x in r['checks']) else None
  except (OSError,ValueError,KeyError):return None
 previous=wait(finished,2700,'two independently retained protocol replicas')
 client=Existing(a.source.resolve()/'replica')
 raw=content.original_wave(6,2);manifest,_,proofs=content.commitments(raw)
 root=hashlib.sha256(manifest).digest();stream=int.from_bytes(root[:8],'little')|1
 reads=[]
 for index in (0,1):
  name='seed'+str(index+1);slot=1 if index==0 else 0
  rel=existing_relation(base,name+'-reader')
  server=Existing(base);server.socket=base/(name+'-recovered.sock');peer=role(server,1025)
  boot=startup_json(base/(name+'-recovered.log'));assert boot and boot['instance']==peer
  assert boot['recovered'][0]['bytes']==len(raw)
  # The original finite policy may expire during the second full acquisition.
  # This is explicit operator renewal of the configured root/relationship,
  # using this live boot's scoped read handle, never a persisted capability.
  with server.client() as sc:
   library_peer.call(sc,peer,402,slot)
   network.configure(sc,rel['server'],rel['description'],slot=slot)
   wait(lambda:network.call(sc,13,slot=slot,allow_error=True)[0][0]==0,300,'selected server listener reopened')
   _,material=network.load_credentials(rel['server'])
   scope=library_peer.call(sc,peer,400,slot,2,stream,boot['recovered'][0]['content_handle'],16777216,100000,material[:32]+material[64:96]+root)[0][1]
  provision(client,rel['client'],rel['description'],1);wait_auth(client,[1])
  with server.client() as sc:
   wait(lambda:library_peer.call(sc,peer,401,scope)[0][2]==1,300,'current seed receive grant ready')
  _,d,_=network.load_description(rel['description']);counter=0
  with client.client() as c:
   grant=network.call(c,2,a=3,b=3,c=32768,d=65536,e=100000,data=d[96:128]+hashlib.sha256(d).digest()+root+struct.pack('<QQ',2,stream),slot=1)[0][1]
   def request(op,h=0,n=0):
    nonlocal counter
    counter+=1;rid=12000+counter
    payload=struct.pack('<8Q',0x31524545504c544c,1,op,h,n,0,0,0)
    job=network.call(c,3,grant,a=2,b=rid,data=payload,slot=1)[0][1]
    wait(lambda:network.call(c,4,job,slot=1)[0][2]==3,300,'fresh selected request sent')
    def take():
     f,b=network.call(c,6,grant,slot=1,allow_error=True)
     if f[0]==6:return None
     assert f[0]==0 and f[3]==rid and len(b)>=64
     q=struct.unpack_from('<8Q',b);assert q[3]==0 and q[4]==rid
     return b[64:]
    return wait(take,300,'fresh retained seed response')
   assert request(3)==manifest
   assert request(4,0)==proofs[0] and request(4,len(proofs)-1)==proofs[-1]
   offsets=[0,4096,len(raw)-512]
   for offset in offsets:assert request(5,offset,512)==raw[offset:offset+512]
   network.call(c,14,slot=1)
  reads.append(dict(seed=name,backing=str(base/(name+'.store')),manifest_sha256=root.hex(),checked_offsets=offsets,first_and_last_proofs='exact',fresh_operator_policy=True))
  if index==0:
   subprocess.run([str(ROOT/'lt'),'library-node','stop','--socket',str(server.socket)],cwd=ROOT,check=True)
   wait(lambda:not server.socket.exists(),90,'first retained seed shutdown')
 result=dict(result='passed',replication_image=previous['image'],publisher_packages_stopped=True,
  first_retained_seed_stopped=True,remaining_seed='seed2',remaining_backing=str(base/'seed2.store'),
  manifest_sha256=root.hex(),bytes=len(raw),checked_offsets=offsets,
  first_and_last_index_proofs='exact',fresh_authenticated_connection=True,
  host_payload_import=False,backing_copy=False,independent_reads=reads)
 a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2),flush=True)

if __name__=='__main__':main()
