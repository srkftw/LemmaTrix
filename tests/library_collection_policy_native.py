"""Physical native collection selection cannot move automatic acquisition consent.

Two genuine signed consumer collections are offered by a separate metadata-only
Registry. The signed Library package consumes physical G/S/D/Enter input. There
are no seeds, payload imports or personal backing; this is an approval boundary,
not a successful content acquisition or restart test.
"""
import argparse,hashlib,json,os,socket,struct,sys,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,consumers,content,federation,library_peer,network,nodes,releases
from creator_journey import Journey,require,rendered_text
from library_journey import appcall,wait
from library_no_vault_native import Guest


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--image',type=Path,required=True);p.add_argument('--packages',type=Path,required=True)
 p.add_argument('--key',type=Path,default=ROOT/'build/campaign005/publisher.pem');p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);guests=[];checks=[];packages=[];image_id=hashlib.sha256(a.image.read_bytes()).hexdigest()
 def passed(label,**facts):
  checks.append(dict(check=label,result='passed',**facts));print('PASS',label,flush=True);(out/'progress.json').write_text(json.dumps(dict(image_sha256=image_id,checks=checks),indent=2)+'\n')
 def install(node,name):
  path=a.packages/(name+'.ltrel');raw=path.read_bytes();info=releases.inspect(raw,releases.public_modulus(a.public))
  with node.client()as c:who=nodes.start_package(c,nodes.approved_package(path,a.public,info['release_id'],info['rights']),raw)
  packages.append(dict(guest=node.base.name,release=info['release_id'],rights=info['rights'],instance=who));return who
 try:
  fedkey,fedpub=out/'federation.pem',out/'federation.pub';capsule.generate_key(fedkey,fedpub);fid=hashlib.sha256(releases.public_modulus(fedpub)).digest()
  netkey,netpub=out/'registry.pem',out/'registry.pub';capsule.generate_key(netkey,netpub);identity=hashlib.sha256(os.urandom(32)).digest();probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close();description=out/'registry.service';details=network.create_description(netkey,identity,'127.0.0.1:'+str(port),'library-registry',description)
  credentials=[out/'personal.credential',out/'registry.credential'];network.provision(*credentials,identity,bytes.fromhex(details['server_id']),bytes.fromhex(details['service_id']))
  wave=content.original_wave(.001,2);manifest,_,_=content.commitments(wave);del wave
  collections=[hashlib.sha256(b'Original native policy collection A').digest(),hashlib.sha256(b'Original native policy collection B').digest()]
  records=[consumers.create(key=a.key,project='native-policy-'+str(i),collection=collection,item=hashlib.sha256(('native policy original item '+str(i)).encode()).digest(),edition=hashlib.sha256(('native policy original edition '+str(i)).encode()).digest(),title='Original policy collection '+chr(65+i),resource=manifest,frames=48,channels=2,license_id=1)for i,collection in enumerate(collections)]
  registry=Guest('registry',out,a.image);guests.append(registry);reg=install(registry,'library-registry');peer=install(registry,'library-peer')
  with registry.client()as c:
   federation.configure(c,reg,fedpub,'consumer',allowed_rights=8191)
   for i,record in enumerate(records):
    root=consumers.attach(c,record,manifest,name='native-policy-record-'+str(i))['root'];federation.call(c,reg,3,data=record[32:64]+releases.public_modulus(a.public));federation.call(c,reg,2,h=c.objects(27,root,reg,25)[0][1]);decision=federation.sign_once(c,reg,fedkey,'consumer',8191);require(decision['listing']==4,'Registry refused original consumer metadata')
   require(content.api(c).objects(312)[0][1]==0,'metadata-only Registry acquired payload pages');network.configure(c,credentials[1],description,slot=0);wait(lambda:network.call(c,13,slot=0,allow_error=True)[0][0]==0,60,'registry listen');library_peer.call(c,peer,400,0,1,1,0,65536,100000,identity+bytes.fromhex(details['service_id'])+fid)
  personal=Guest('personal',out,a.image,True);guests.append(personal);verifier=install(personal,'library-registry')
  with personal.client()as c:federation.configure(c,verifier,fedpub,'consumer',allowed_rights=8191);network.configure(c,credentials[0],description,slot=0)
  j=Journey(argparse.Namespace(output=personal.base/'native-actions',public=a.public,image=a.image));j.socket=personal.socket;j.graphics=personal.graphics;j.ui=personal.ui;j.image=image_id;info,lib=j.trust_stage(a.packages/'library-native.ltrel','library-native');packages.append(dict(guest='personal',release=info['release_id'],rights=info['rights'],instance=lib))
  with personal.client()as c:c.request(184,struct.pack('<Q',lib));appcall(c,lib,700,data=fid)
  def raw_state():
   with personal.client()as c:return appcall(c,lib,701)[1]
  def word(n):return struct.unpack_from('<Q',raw_state(),n)[0]
  def row(i,offset,n):
   with personal.client()as c:return appcall(c,lib,703,i,offset,n)[1]
  def state():
   raw=raw_state();q=lambda n:struct.unpack_from('<Q',raw,n)[0]
   with personal.client()as c:jobs=[list(struct.unpack('<16Q',appcall(c,lib,704,i,0,128)[1]))for i in range(4)];pages=content.api(c).objects(312)[0][1]
   return dict(selected=q(8),monitoring=q(88),automatic=q(96),sources=q(104),charged=q(120),generation=q(128),collection=raw[288:320].hex(),approval_open=q(208),approval_row=q(216),jobs=jobs,resident_content_pages=pages)
  def surface():return rendered_text(personal.ui.frame(),520,34,16)==f'{lib:016x}'and rendered_text(personal.ui.frame(),12,58,13)=='LEMMA LIBRARY'
  def press(code):wait(surface,60,'visible exact Library before physical input');personal.ui.press(code)
  def select(index):
   while word(8)!=index:
    old=word(8);press(108 if old<index else 103);wait(lambda:word(8)!=old,60,'physical catalog selection')
  def capture(name):frame=personal.ui.frame();(out/(name+'.ppm')).write_bytes(frame.ppm());return frame.digest
  press(60);personal.ui.press(2);personal.ui.press(28)
  def authenticated():
   with personal.client()as c:return network.status(c,0)['endpoint_authenticated']
  wait(authenticated,300,'physical Registry enrollment');press(59);press(16);wait(lambda:word(16)==2,300,'genuine two-collection catalog')
  for i,record in enumerate(records):
   select(i);press(30);wait(lambda i=i:struct.unpack('<Q',row(i,8,8))[0]!=0,120,'physical metadata Add');actual=row(i,1024,640)+row(i,1664,128);require(actual==record,'native Library consumer bytes differ')
  added=state();require(added['automatic']==0 and added['resident_content_pages']==0 and all(job[0]==0 for job in added['jobs']),'Add created acquisition authority')
  passed('physical registry enrollment Q and A import two genuine signed collection records without payload or acquisition',library_release=info['release_id'],consumer_sha256=[hashlib.sha256(r).hexdigest()for r in records],collections=[x.hex()for x in collections],state=added)
  select(0);press(34);wait(lambda:word(208)==1 and word(216)==1,60,'G selected A approval');capture('G-A-policy');personal.ui.press(28);wait(lambda:word(96)==1 and word(208)==0,60,'physical Enter A policy');approved_a=state();require(approved_a['collection']==collections[0].hex()and approved_a['generation']>0,'A policy selection differs');old_operation=approved_a['jobs'][0][10];require(old_operation!=0,'A policy did not create actual acquisition intent')
  select(1);press(31);wait(lambda:word(96)==0 and raw_state()[288:320]==collections[1],60,'S B monitoring only');monitor_b=state();require(monitor_b['monitoring']==1 and monitor_b['sources']==0 and monitor_b['charged']==0 and monitor_b['approval_row']==0 and monitor_b['generation']>approved_a['generation']and all(job[0]in(0,14)for job in monitor_b['jobs']),'S B retained old consent/work');capture('S-B-monitor-only')
  passed('physical G Enter approves A; selecting B and S retires A authority and enables B monitoring only',approved_A=approved_a,monitoring_B=monitor_b,old_operation=old_operation)
  press(32);wait(lambda:word(208)==1 and word(216)==2,60,'D B requires fresh selected B approval');pending_b=state();require(pending_b['automatic']==0 and all(job[0]in(0,14)for job in pending_b['jobs']),'B queued before approval');capture('D-B-fresh-approval');personal.ui.press(103);require(word(8)==1 and word(216)==2,'pending physical approval retargeted by Up');personal.ui.press(28);wait(lambda:word(96)==1 and word(208)==0,60,'physical Enter fresh B consent');approved_b=state();require(approved_b['collection']==collections[1].hex()and approved_b['generation']>monitor_b['generation']and approved_b['jobs'][0][1]==1 and approved_b['jobs'][0][8]==approved_b['generation']and approved_b['jobs'][0][10]!=old_operation,'new B intent did not bind fresh consent/row')
  passed('physical D B opens fresh approval frozen to B; attempted Up cannot retarget it before Enter',pending_B=pending_b,approved_B=approved_b)
  select(0);press(31);wait(lambda:word(96)==0 and raw_state()[288:320]==collections[0],60,'return A monitoring cannot revive old consent');returned=state();require(returned['generation']>approved_b['generation']and all(job[0]in(0,14)for job in returned['jobs']),'return A restored old work');press(32);wait(lambda:word(208)==1 and word(216)==1,60,'A D still requires approval');personal.ui.press(1);wait(lambda:word(208)==0,60,'physical Escape A pending approval');require(word(96)==0,'Escape manufactured acquisition consent');press(34);wait(lambda:word(208)==1 and word(216)==1,60,'fresh G A approval');capture('fresh-G-A-policy');personal.ui.press(28);wait(lambda:word(96)==1 and word(208)==0,60,'fresh Enter A consent');fresh_a=state();require(fresh_a['generation']>returned['generation']and fresh_a['collection']==collections[0].hex()and fresh_a['jobs'][0][10]!=old_operation,'fresh A consent reused old operation');require(fresh_a['resident_content_pages']==0,'metadata-only test acquired provider payload')
  passed('physical return A S leaves acquisition disabled; D Escape preserves refusal and fresh G Enter creates new consent',returned_A=returned,fresh_A=fresh_a)
  for node in reversed(guests):node.stop();require(node.normal_shutdown,'guest did not exit through normal command70')
  result=dict(schema=1,result='passed',backend='qemu',image_sha256=image_id,library_release=info['release_id'],packages=packages,checks=checks,commands=[dict(guest=g.base.name,command=g.command,normal_shutdown=g.normal_shutdown)for g in guests],native_input=True,personal_backing=False,payload_provider_instances=0,limitations=['metadata-only approval-boundary check; no provider payload transfer, hashing, playback, retention, save or restart positive','G/D approvals are the actual Library displayed bounded-consent interface; trusted executable approval is separately used to start the signed Library','A/B acquisition intents have no configured seed and may fail unavailable; no complete acquisition claim','administrative calls provision explicit credentials/federation and perform read-only inspection; all collection selections and acquisition decisions use physical graphical input'])
  (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
 except BaseException as error:
  failure=dict(error=repr(error),traceback=traceback.format_exc())
  for node in guests:
   if node.ui:
    try:(node.base/'failure.ppm').write_bytes(node.ui.frame().ppm())
    except Exception:pass
  (out/'failure.json').write_text(json.dumps(failure,indent=2)+'\n');raise
 finally:
  for node in reversed(guests):
   if node.proc.poll()is None:node.stop()


if __name__=='__main__':main()
