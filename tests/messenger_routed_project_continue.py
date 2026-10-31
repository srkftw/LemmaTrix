"""Resume the already delivered conversation reference after a broker fix.

Requires exclusive preserved-actor handoff. Uses normal newer release/parent
admission and recreates only the broker's eight exact bindings. Session owner,
UI, encrypted backing, approved contact and decrypted reference remain intact.
"""
from __future__ import annotations
import argparse,hashlib,json,struct,time,traceback
from pathlib import Path
from messenger_routed_project import ROOT,current_packages,attach,digest,validate_bindings
from messenger_journey import net,role,wait,wait_ui,inspect,screenshot,route,reset_operators,PUB,SIGN
from messenger_product_journey import record_binding,ui_public,publication,close_route
import messenger,releases,projects


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--campaign',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--binary',type=Path,required=True);p.add_argument('--version',required=True)
 p.add_argument('--diagnose',action='store_true')
 p.add_argument('--reuse',action='store_true',help='reuse this exact already admitted diagnostic package')
 a=p.parse_args();campaign=a.campaign.resolve();out=a.output.resolve()
 previous=out/'failure.json'
 assert previous.exists(),'only resume a specifically preserved failed reference'
 report=json.loads(previous.read_text());prepared=report['prepared']
 assert report['checks'][-1]['check'].startswith('actual graphical143byte')
 packages=current_packages(campaign);old=packages['bob']['delivery']['release']
 if a.reuse:
  assert old['version']==a.version and old['executable_sha256']==digest(a.binary)
  package=Path(packages['bob']['delivery']['path']);info=old
 else:
  assert tuple(map(int,a.version.split('.')))>tuple(map(int,old['version'].split('.')))
  raw,_=releases.make(a.binary,old['project'],a.version,1024,SIGN,parent=old['release_id'],profile=2,license='NOASSERTION')
  package=out/('delivery-'+a.version+'.ltrel');package.write_bytes(raw);info=releases.inspect(raw)
 g=None;operators=[];began=time.monotonic();samples=[]
 try:
  g=attach(campaign,out,'bob',True,packages['bob'])
  old_delivery=g.delivery;owner_before=role(g,2,420)[0]
  assert owner_before[1]==1 and owner_before[5]==1
  text='LT-PROJECT1 '+prepared['project_root']+' '+prepared['federation']+' 1'
  read,plain=role(g,2,429,h=owner_before[4]);assert plain==text.encode()
  roots_before=projects.roots(g.client)
  g.device.press(1,delay=.15);time.sleep(.5);g.device.press(15,delay=.15)
  close_route(g)
  if not a.reuse:
   g.client.request(26,struct.pack('<Q',old_delivery))
   g.delivery,did=messenger.install(g.client,package,PUB,1024)
   sid=bytes.fromhex(packages['bob']['owner']['release']['release_id'])
   uid=bytes.fromhex(packages['bob']['ui']['release']['release_id'])
   old_out=g.out;g.out=campaign
   for op in(427,428,434):record_binding(g,2,g.owner,g.delivery,op,sid,did)
   for op in range(460,464):record_binding(g,4,g.delivery,g.ui,op,did,uid)
   record_binding(g,4,g.delivery,messenger.launcher(g.client),464,did)
   g.out=old_out
   manifest=json.loads((campaign/'actor-packages.json').read_text());manifest['bob']['delivery']=str(package)
   (campaign/'actor-packages.json').write_text(json.dumps(manifest,indent=2)+'\n')
  mailbox=attach(campaign,out,'mailbox',False);operators.append(mailbox)
  relays=[]
  for name in('relay1','relay2','relay3'):
   actor=attach(campaign,out,name,False);operators.append(actor);relays.append(actor)
  reset_operators(relays,mailbox)
  net(mailbox,46,h=report['checks'][0]['native_registries']['mailbox'],data=bytes.fromhex(prepared['federation']))
  setup_seconds=route(g,[actor.certificate for actor in relays],mailbox)
  wait(lambda:publication(g),240,'native public prekey publication after broker upgrade')
  wait_ui(g,lambda f:f[2]==0,'retained conversation after broker upgrade')
  began_request=time.monotonic()
  g.device.press(59,delay=.15)
  end=time.monotonic()+(15 if a.diagnose else 90)
  verified=None
  while time.monotonic()<end:
   status,_=role(g,4,464,a=2)
   ui,_=inspect(g);fields,chosen=ui_public(g,785)
   sample=dict(at=time.monotonic()-began,delivery=list(status),ui=list(ui),display=list(fields))
   if not samples or sample['delivery']!=samples[-1]['delivery'] or sample['display']!=samples[-1]['display']:
    samples.append(sample);print('PUBLIC',sample,flush=True)
   if not a.diagnose and ui[4]==79:
    admission=report['checks'][0]['signed_admission']
    assert fields[1]==6 and fields[2]==2 and fields[3]==0 and fields[4]==admission['sequence'] and fields[5]==0 and fields[6]==1
    assert chosen==bytes.fromhex(prepared['project_root']+prepared['federation'])
    verified=fields;break
   if not a.diagnose and status[1]==4:raise AssertionError(('native routed metadata failed',status,ui,fields))
   time.sleep(.15)
  current=current_packages(campaign)
  upgrade=dict(schema=1,prior_instance=old_delivery,current_instance=g.delivery,owner_instance=g.owner,
   owner_state_before=list(owner_before),owner_state_after=list(role(g,2,420)[0]),
   package=str(package),release=info,code_sha256=digest(a.binary),parent=old['release_id'],
   exact_bindings_recreated=0 if a.reuse else 8,normal_version_parent_admission=True,
   reused_exact_current_package=a.reuse,route_setup_seconds=setup_seconds,samples=samples)
  if a.diagnose:
   upgrade['result']='public-diagnostic-only'
   (out/'forge-admission-diagnostic.json').write_text(json.dumps(upgrade,indent=2)+'\n')
  else:
   assert verified is not None,'bounded native routed inspection did not finish'
   assert projects.roots(g.client)==roots_before,'metadata inspection imported content'
   screenshot(g,'project-reference-native-forge-verified')
   report['checks'].append(dict(check='actual conversation F1 invokes existing Forge federation consumer through the same three-relay broker; isolated native Registry verifies root federation signature policy and admission',result='pass',
    inbox_serial=read[1],routed_metadata_seconds=time.monotonic()-began_request,displayed_fields=list(verified),
    timing_scope='Actual F1 gesture to stable verified compositor frame, including public status polling.',
    selected_root=prepared['project_root'],selected_federation=prepared['federation'],
    recipient_content_imported=False,execution_approved=False,broker_upgrade=upgrade))
   report['personal_instances']['bob']['delivery']=g.delivery
   report['original_failed_attempt_seconds']=report.pop('elapsed_seconds',None)
   report.update(result='pass',personal_packages=current,exact_personal_bindings={**report['exact_personal_bindings'],'bob':validate_bindings(g,campaign,current['bob'])},
    observed_failure='Original F1 could starve behind continuous bounded background mailbox work; frozen public request now waits for the next drained idle boundary.',
    continuation_seconds=time.monotonic()-began)
   for key in('error','traceback','stage'):report.pop(key,None)
   (out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n')
   print('PASS actual conversation F1 verifies existing signed Forge reference through native routed broker',flush=True)
 except BaseException as error:
  (out/('diagnostic-failure.json'if a.diagnose else'continuation-failure.json')).write_text(json.dumps(dict(error=repr(error),traceback=traceback.format_exc(),samples=samples),indent=2)+'\n')
  raise
 finally:
  if g:
   if g.device:g.device.close()
   if g.client:g.client.close()
  for actor in operators:
   if actor.client:actor.client.close()

if __name__=='__main__':main()
