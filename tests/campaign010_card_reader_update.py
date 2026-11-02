"""Same real Feed-card reader fetches original, approves successor and rolls back.

Original bytes are the ordinary export from the surviving fetched seed. The
provider restores its own selected successor store. Both federation choices are
public, native-verified descriptors; no publisher/operator signature is created.
"""
import argparse,hashlib,json,os,socket,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,federation,forge,identity,network,projects,releases,server_store
from campaign010_forge_mux import MuxNode,archive,PUBLIC,digest
from campaign010_forge_continue import attach,stop,fetch
from campaign010_forge_final_provider import select
from campaign010_forge_distribution import Client
from campaign010_forge_coexistence import snapshot
from graphical_devices import DeviceInput
from creator_journey import rendered_text
from forge_journey import wait

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for f in ('provider','reader','image','server-forge','registry','old','successor','output'):p.add_argument('--'+f,type=Path,required=True)
 p.add_argument('--resume',action='store_true');a=p.parse_args();a.output.mkdir(exist_ok=a.resume,parents=True);state=json.loads(a.provider.read_text());assert state['result']=='pass';base=a.provider.parent;old=archive(a.old);new=archive(a.successor);s=json.loads(a.reader.read_text());session=s['session'];reader=attach(dict(pid=session['pid'],socket=session['socket'],graphics=session['graphics'],forge=s['forge'],registry=session['registry']));prior=attach(state['actors'][0])if not a.resume else type('Stopped',(),{'ui':None})() ;os.environ['LT_GUEST_IMAGE']=str(a.image.resolve());nodes=[];report=dict(schema=1,result='running',scope=__doc__,checks=[],image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),reader_image_sha256='98e18e47f16e478b9da5037460d303545c46bc27deb3fd2060d800ca4c812fdc');began=time.monotonic()
 def write():
  report.update(elapsed_seconds=round(time.monotonic()-began,3),actors=[dict(pid=n.proc.pid if hasattr(n,'proc')else n.pid,socket=str(n.sock),graphics=str(n.qmp),forge=getattr(n,'instance',None),registry=getattr(n,'registry',None))for n in nodes]);(a.output/'execution.json').write_text(json.dumps(report,indent=2)+'\n')
 def passed(label,**kw):report['checks'].append(dict(check=label,result='pass',**kw));write();print('PASS',label,flush=True)
 def verifier(n,configuration,descriptor,initial=False):
  with n.client()as c:
   if not initial:
    try:c.request(26,struct.pack('<Q',n.registry))
    except ValueError:pass
   raw=a.registry.read_bytes()
   if initial:
    c.request(10,raw[128:160]+releases.public_key(PUBLIC));slot,_=c.install(a.registry)
   else:
    slots=[]
    for index in range(16):
     try:material=c.request(13,struct.pack('<Q',index))
     except ValueError:continue
     if material[160:192]==raw[160:192]:slots.append(index)
    assert len(slots)==1,'existing admitted Registry catalog slot missing';slot=slots[0]+1
   n.registry=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',slot)),8)[0]
   federation.configure_native_verifier(c,n.registry,configuration['public_key'],'consumer',allowed_rights=895,generation=configuration['generation'])
   q,_=federation.call(c,n.registry,11,data=descriptor+descriptor[320:352]);assert q[1]>0
   forge.federation_configure(c,n.instance,configuration['federation_id'],3)
 def install(n,item):
  n.focus(n.instance)
  with n.client()as c:
   c.request(10,item['publication']+item['publisher'])
   before={row[0]for row in identity.instances(c)}
  n.ui.press(64)
  frame=wait(lambda:(f if rendered_text(f:=n.ui.frame(),16,12,24)=='SIGNED PACKAGE CANDIDATE'else None),'separate actual fetched release execution review',180)
  assert rendered_text(frame,80,40,13)=='project-notes';(a.output/(item['release'][:12]+'-review.ppm')).write_bytes(frame.ppm());time.sleep(.4);n.ui.press(28)
  def active():
   with n.client()as c:
    try:r=c.request(29,item['publication'])
    except ValueError:return None
    rows=identity.instances(c)
   return r if r[160:192].hex()==item['release']else None
  wait(active,'exact selected release active',180)
  frame=wait(lambda:(f if rendered_text(f:=n.ui.frame(),14,56,13,0xdce9ec)=='Project Notes'else None),'ordinary native Notes surface',120);(a.output/(item['release'][:12]+'-running.ppm')).write_bytes(frame.ppm())
  with n.client()as c:instances=[list(row)for row in identity.instances(c)if row[0]not in before and row[2]==895 and 0<row[1]<5]
  return dict(release=item['release'],new_instances=instances,frame=frame.digest)
 try:
  alpha2=json.loads((base/'alpha-public-verifier.json').read_text());alpha1=json.loads((ROOT/'build/campaign010-forge-distribution-5/alpha-public-verifier.json').read_text());alpha1['generation']=1
  desc1=(ROOT/'build/campaign010-forge-distribution-5/alpha-notes.admission').read_bytes();desc2=(base/('alpha2-'+new['release']+'.admission')).read_bytes()
  if not a.resume:
   # Same reader has already physically installed ordinary Forge without changing
   # its live Feed circuit, terminal profile, public card or non-author owner.
   with reader.client()as c:before=snapshot(c,session)
   stop(prior);provider=MuxNode(a.output/'provider',base/'provider.img');nodes=[provider,reader];provider.install(a.server_forge,PUBLIC);write()
   # A fresh selected peer is independent of the existing native routed profile.
   relation=a.output/'selected-provider';relation.mkdir();key,pub=relation/'endpoint.pem',relation/'endpoint.pub';capsule.generate_key(key,pub);probe=socket.socket();probe.bind(('127.0.0.1',0));endpoint='127.0.0.1:'+str(probe.getsockname()[1]);probe.close();description=relation/'service.public';meta=network.create_description(key,digest('Campaign010 actual Feed reader current provider'),endpoint,'forge',description)
   ck,sk=relation/'client.credential',relation/'server.credential';network.provision(ck,sk,bytes.fromhex(meta['client_id']),bytes.fromhex(meta['server_id']),bytes.fromhex(meta['service_id']))
   with provider.client()as c:server_store.call(c,230);grant=server_store.call(c,231,provider.instance,2,1048576,digest('Campaign010 MUX project-notes-1.1.0 graph'))[0][1];network.configure(c,sk,description,slot=0);network.call(c,13,slot=0)
   with reader.client()as c:network.configure(c,ck,description,slot=0);network.call(c,13,slot=0)
   def authenticated():
    for n in nodes:
     with n.client()as c:
      if not network.status(c,slot=0)['endpoint_authenticated']:return False
    return True
   wait(authenticated,'actual Feed reader explicit bulk peer',180)
   with provider.client()as c:forge.configure(c,provider.instance,sk,'seed','portable',grant,peer_slot=0,stream=1)
   with reader.client()as c:forge.configure(c,reader.instance,ck,peer_slot=0,stream=1);forge.federation_configure(c,reader.instance,alpha1['federation_id'],3)
   verifier(provider,alpha2,desc2,True)
   with reader.client()as c:after=snapshot(c,session)
   assert before['route']==after['route']and before['profiles_body_hex']==after['profiles_body_hex']and before['feed_ui']==after['feed_ui']
   passed('same genuine card reader establishes exact bulk peer preserving routed Feed scope and owner',before=before,after=after)
   provider.focus(provider.instance);provider.ui.press(67);time.sleep(.5)
   def preview():
    value=provider.archive()
    if value['phase']==9:raise AssertionError(value)
    return value if value['phase']==4 else None
   shown=wait(preview,'selected current successor store inspection',180);assert shown['head']==new['root']['head'];provider.ui.press(67)
   wait(lambda:provider.archive()['phase']==8,'actual current successor store recovery',240)
   # Old bytes are exported from the real surviving seed, not copied from the
   # author's original archive. Native ImportJobs rechecks their entire closure.
   with provider.client()as c:
    root=projects.import_records(c,old['doc']['selected'],old['rows'])[0]['cap'];shell=struct.unpack_from('<Q',c.request(2),4*32)[0];c.objects(27,root,shell,127)
  else:
   previous=json.loads((a.output/'execution.json').read_text());(a.output/('failure-'+str(time.time_ns())+'.json')).write_text(json.dumps(previous,indent=2)+'\n');report=previous;report.pop('error',None);report['result']='running';provider=attach(previous['actors'][0]);nodes=[provider,reader];ck=a.output/'selected-provider/client.credential';write()
  verifier(provider,alpha1,desc1);select(provider,old['root']['name']);provider.ui.press(62)
  wait(lambda:provider.inspect()['offered_nodes']==24,'actual selected old release offer',180)
  first=fetch(provider,reader,old['doc']);approved=install(reader,old)
  passed('same card reader independently retrieves and approves original release from actual surviving bytes',transfer=first,installation=approved,card_does_not_grant_execution=True)
  verifier(provider,alpha2,desc2);verifier(reader,alpha2,desc2)
  provider.focus(provider.instance);select(provider,next(r['name']for r in provider.roots()if r['head']==new['root']['head']));provider.ui.press(62)
  wait(lambda:provider.inspect()['offered_nodes']==32,'explicit successor32 offer',180)
  # Refresh only the already selected old-image relationship before this new
  # reviewed transfer. It preserves Noise/peer/stream/Feed and cannot claim17.
  with reader.client()as c:forge.configure(c,reader.instance,ck)
  second=fetch(provider,reader,new['doc']);approved=install(reader,new)
  reader.ui.textASCII('Federated update',delay=.035);reader.ui.press(28)
  wait(lambda:rendered_text(reader.ui.frame(),14,152,10,0xdce9ec)=='Annotation','successor semantic resource',60)
  text='The selected federation supplied the complete successor.';reader.ui.textASCII(text,delay=.035)
  wait(lambda:rendered_text(reader.ui.frame(),18,170,len(text),0xdce9ec)==text,'actual responsive successor text editing',90);reader.ui.chord(29,31)
  wait(lambda:rendered_text(reader.ui.frame(),14,354,24,0xdce9ec)=='Saved immutable revision','actual successor note saved',90)
  passed('same second user explicitly selects new federation, fetches32 objects, approves proper successor and uses changed native app',transfer=second,installation=approved,from_release=old['release'],to_release=new['release'],capability_delta=0,body=text,frame=reader.ui.frame().digest)
  # The native lifecycle panel supplies explicit eligible rollback, while the
  # already running successor retains its own isolated code and local state.
  with reader.client()as c:
   catalog=[]
   for i in range(16):
    try:r=c.request(13,struct.pack('<Q',i))
    except ValueError:continue
    if len(r)==512:catalog.append(r)
  index=next(i for i,r in enumerate(catalog)if r[160:192].hex()==new['release']);reader.ui.chord(56,67)
  def selected_row(i):
   f=reader.ui.frame();at=((72+i*11)*f.width+4)*4;return f.bgrx[at:at+3]==bytes.fromhex('6a5435')
  wait(lambda:selected_row(0),'native lifecycle panel',45)
  for i in range(index):reader.ui.press(108,.08);wait(lambda:selected_row(i+1),'review selected active successor',45)
  (a.output/'rollback-review.ppm').write_bytes(reader.ui.frame().ppm());reader.ui.press(48)
  def rolled():
   with reader.client()as c:r=c.request(29,new['publication'])
   return r[160:192].hex()==old['release']
  wait(rolled,'explicit eligible old release rollback',90);reader.ui.press(1);reader.ui.key(56,False)
  passed('same second user explicitly rolls back eligible retained original release',from_release=new['release'],to_release=old['release'])
  report['result']='pass';write()
 except BaseException as error:
  report.update(result='fail',error=repr(error));write()
  for n in nodes:
   try:(n.path/'reader-update-failure.ppm').write_bytes(n.ui.frame().ppm())
   except Exception:pass
  raise
 finally:
  for n in [prior,reader,*nodes]:
   if n.ui:n.ui.close();n.ui=None
if __name__=='__main__':main()
