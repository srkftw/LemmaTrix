"""Explicit native Forge role/peer provisioning. User actions use guest controls."""
import argparse,json,struct
from pathlib import Path
import live,network

def configure(client,instance,credentials,role='client',policy='portable',store_grant=0,recover_and_seed=False):
 side,material=network.load_credentials(credentials)
 peer=material[32:64] if side==1 else material[:32]
 service=material[64:96]
 roles=('client','registry','seed','builder','verifier')
 policies=('portable','source-only')
 request=struct.pack('<8Q',1,0,roles.index(role),policies.index(policy)+1,store_grant,int(recover_and_seed),0,1)+peer+service
 raw=client.request(150,struct.pack('<Q',instance)+request)
 if len(raw)!=64 or struct.unpack_from('<Q',raw)[0]:raise ValueError('native Forge configuration denied')
 return {'instance':instance,'role':role,'policy':policy,'peer':peer.hex(),'service':service.hex(),'server_store_grant':store_grant,'recover_and_seed':recover_and_seed,'native_controls':'F1 admission details; F2 scope; F3 metadata; F4 offer; F5 fetch; F6 install; F7 remote request; F8 server save; F9 inspect/recover; F10 remote approval; F11 federation publish; Esc cancel','signing_authority':'none','personal_retention':'ephemeral; server retention requires a separately granted purpose2 store'}

def federation_configure(client,instance,identity,policy=1,enabled=True):
 identity=network.digest(identity) if enabled else bytes(32)
 raw=client.request(150,struct.pack('<Q',instance)+struct.pack('<8Q',57,0,int(enabled),policy,0,0,0,1)+identity)
 if len(raw)!=64 or struct.unpack_from('<Q',raw)[0]:raise ValueError('native chosen federation configuration denied')
 return {'instance':instance,'federation_required':enabled,'expected_federation_id':identity.hex(),'policy':policy,'native_controls':'F1 inspect actual signed decision; F11 publish exact selected root; F5 fetch requires positive chosen federation result','local_execution':'separate Launcher approval'}

def admission_record(raw):
 if len(raw)!=768:raise ValueError('admission descriptor must be768bytes')
 q=lambda offset:struct.unpack_from('<Q',raw,offset)[0]
 return {'format':q(8),'classification':q(16),'reason':q(24),'policy':q(32),'rights':q(40),'sequence':q(48),'runtime_profile':q(56),'logical_project_id':raw[64:96].hex(),'publication_id':raw[96:128].hex(),'release_id':raw[128:160].hex(),'source_commitment':raw[160:192].hex(),'artifact_commitment':raw[192:224].hex(),'evidence_commitment':raw[224:256].hex(),'policy_commitment':raw[256:288].hex(),'federation_id':raw[288:320].hex(),'root':raw[320:352].hex(),'publisher_key_id':raw[352:384].hex(),'signature_present':any(raw[512:768])}

def federation_inspect(client,instance,local=False):
 raw=client.request(150,struct.pack('<Q',instance)+struct.pack('<8Q',59 if local else 58,0,0,0,0,0,0,1))
 if len(raw)!=(832 if local else 960) or struct.unpack_from('<Q',raw)[0]:raise ValueError('native federation inspection unavailable')
 if local:return {'local_phase':struct.unpack_from('<Q',raw,8)[0],'descriptor':admission_record(raw[64:832])}
 q=struct.unpack_from('<16Q',raw,64)
 return {'required':bool(q[0]),'local_phase':q[1],'local_slot':q[2],'local_sequence':q[3],'send_phase':q[4],'local_classification':q[5],'local_reason':q[6],'remote_phase':q[7],'classification':q[8],'reason':q[9],'remote_sequence':q[10],'metadata_epoch':q[12],'error':q[15],'descriptor':admission_record(raw[192:960])}

def subscription_inspect(client,instance):
 raw=client.request(150,struct.pack('<Q',instance)+struct.pack('<8Q',60,0,0,0,0,0,0,1))
 if len(raw)!=288 or struct.unpack_from('<Q',raw)[0]:raise ValueError('native subscription inspection unavailable')
 q=struct.unpack_from('<8Q',raw,64)
 return {'subscribed':bool(q[0]),'next_local_turn':q[1],'backoff_turns':q[2],'sequence':q[3],'state':q[4],'metadata_queries':q[5],'logical_project_id':raw[128:160].hex(),'publication_id':raw[160:192].hex(),'federation_id':raw[192:224].hex(),'peer_id':raw[224:256].hex(),'desired_root':raw[256:288].hex(),'execution_approved':False,'personal_retention':False}

def inspect(client,instance):
 raw=client.request(150,struct.pack('<Q',instance)+struct.pack('<8Q',2,0,0,0,0,0,0,1))
 if len(raw)!=320 or struct.unpack_from('<Q',raw)[0]:raise ValueError('native Forge unavailable')
 q=struct.unpack_from('<32Q',raw,64)
 return dict(configured=bool(q[0]),selected_root=q[3],frozen_root=q[4],offered_nodes=q[5],offered_bytes=q[6],send_phase=q[7],send_ordinal=q[8],send_offset=q[9],pending_job=q[10],import_transaction=q[14],received_nodes=q[15],status=q[17],metadata_nodes=q[18],metadata_bytes=q[19],role=q[25],policy=q[26],server_store_grant=q[27],queued_fetch=bool(q[22]),last_native_key=q[30])

def main(argv=None):
 p=argparse.ArgumentParser(description='Provision native Forge peer settings; normal actions are graphical')
 p.add_argument('--socket',required=True,type=Path);p.add_argument('--instance',required=True,type=int)
 sub=p.add_subparsers(dest='command',required=True)
 q=sub.add_parser('configure');q.add_argument('--credentials',required=True,type=Path);q.add_argument('--role',choices=('client','registry','seed','builder','verifier'),default='client');q.add_argument('--policy',choices=('portable','source-only'),default='portable');q.add_argument('--store-grant',type=int,default=0);q.add_argument('--recover-and-seed',action='store_true')
 q=sub.add_parser('federation');q.add_argument('--identity',default='');q.add_argument('--policy',choices=('portable','native-restricted'),default='portable');q.add_argument('--disable',action='store_true')
 q=sub.add_parser('admission');q.add_argument('--local',action='store_true')
 sub.add_parser('subscription')
 sub.add_parser('inspect')
 a=p.parse_args(argv);c=live.Client(a.socket)
 try:
  if a.command=='configure':result=configure(c,a.instance,a.credentials,a.role,a.policy,a.store_grant,a.recover_and_seed)
  elif a.command=='federation':result=federation_configure(c,a.instance,a.identity,1 if a.policy=='portable' else 2,not a.disable)
  elif a.command=='admission':result=federation_inspect(c,a.instance,a.local)
  elif a.command=='subscription':result=subscription_inspect(c,a.instance)
  else:result=inspect(c,a.instance)
 finally:c.close()
 print(json.dumps(result,indent=2));return 0

if __name__=='__main__':raise SystemExit(main())
