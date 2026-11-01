"""Qualify a normal retained Feed UI successor on the preserved moved account.

The original hosting federation stays offline. Only Bob's ordinary Feed UI and
account processes are replaced through native admission and fresh recovery.
"""
from __future__ import annotations
import argparse,hashlib,json,re,struct,subprocess,sys,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import feed
import feed_project_controls as project
from native_community_campaign import attach_campaign,feed_ui
from native_feed_project_account import (upgrade_retained_pair,export_public,save_approved_profile,focus_feed,
    retained_generation,secret,selected_feed_route,settle_exact,check_upgraded_local_block,choose_move_audience,
    rows,read_body,match,preference_bits)
from messenger_journey import wait,screenshot,net
TEXT='The recovered account now reads the original release discussion through this willing host. A busy read clears its partial selection before an ordinary retry; it never treats an earlier timeline response as the new body.'

def checked_read(g,target,observed):
 """Only real First/Next gestures; bounded restart after a visible refusal."""
 focus_feed(g)
 for _ in range(4):
  g.device.press(15)
  try:choice=wait(lambda:(lambda f:f if f[4]in(27,28)else None)(feed_ui(g)[0]),5,'chronological reader choice')
  except TimeoutError:continue
  if choice[4]==27:break
 else:raise RuntimeError('native chronological choice unavailable')
 retries=0;g.device.press(104)
 for _ in range(80):
  def ready():
   f,p=feed_ui(g,795);status=feed_ui(g)[0]
   if getattr(g,'project_observer',None):g.project_observer('shipping native verified reader',target=target.hex(),selected=p[:32].hex())
   if not project.complete_read(g,g.feed_ui):return None
   if not any(p[:32]):
    if status[4]==16 and any(p[144:176]):return dict(blocked=list(status))
    return dict(refused=list(status))if status[6]in(4,9,12,14)else None
   return p
  selected=wait(ready,180,'shipping native row and every checked body chunk')
  if isinstance(selected,dict)and'blocked'in selected:
   observed(dict(check='shipping chronology preserves local block and follows its native next cursor',**selected))
   project.advance_row(g,g.feed_ui,bytes(512));continue
  if isinstance(selected,dict):
   observed(dict(check='visible shipping reader refusal clears content before ordinary First retry',**selected))
   retries+=1
   if retries>4:raise RuntimeError('bounded native reader retry allowance exhausted')
   # Busy is a completed refusal; it is not evidence that a subsequent key
   # has already been processed. Give the finite in-flight owner operation
   # time to finish instead of counting the same sticky notice repeatedly.
   g.device.press(104)
   time.sleep(3)
   continue
  if selected[:32]==target:return selected
  project.advance_row(g,g.feed_ui,selected)
 raise RuntimeError('target absent from bounded chronological native reader')

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--attach',type=Path,required=True);p.add_argument('--packages',type=Path,required=True);p.add_argument('--record-name',default='feed-shipping-reader.json');a=p.parse_args()
 if not re.fullmatch('[a-z0-9-]{1,72}\\.json',a.record_name):raise ValueError('one explicit local JSON record name required')
 out=a.attach.resolve();path=out/a.record_name;began=time.monotonic();prior_path=out/'feed-migrate-account.json';prior=json.loads(prior_path.read_text())
 assert prior['result']=='pass'and not(out/'alpha.sock').exists()
 record=json.loads(path.read_text())if path.exists()else dict(schema=1,checks=[],observations=[],checkpoints={},migration_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest())
 assert record['migration_sha256']==hashlib.sha256(prior_path.read_bytes()).hexdigest()
 if record.get('result')=='pass':print('Previously completed shipping reader retained; no duplicate action');return
 if path.exists():
  archive=path.with_name(path.stem+'-attempt-'+str(len(record.get('attempts',[])))+'.json');archive.write_bytes(path.read_bytes())
  record.setdefault('preserved_attempts',[]).append(dict(path=str(archive),sha256=hashlib.sha256(archive.read_bytes()).hexdigest()))
 for name in('error','traceback'):record.pop(name,None)
 attempt=dict(started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),result='running');record.setdefault('attempts',[]).append(attempt)
 record.update(result='running',controller_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),source_commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip())
 c=record['checkpoints']
 def save():project.write_record(path,record)
 def observed(value):record['observations'].append(value);save()
 def passed(check,**fields):record['checks'].append(dict(check=check,result='pass',**fields));save();print('PASS',check,flush=True)
 save()
 with attach_campaign(out,skip=('alpha',))as campaign:
  actors=campaign.actors;g=actors['bob'];beta=actors['beta'];g.ui=g.feed_ui;state=campaign.state
  record['configuration']=state['configuration'];last=[0.0]
  def progress(stage,**fields):
   if time.monotonic()-last[0]<10:return
   last[0]=time.monotonic();f,d=feed_ui(g);value=dict(observed_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),stage=stage,ui=list(f),diagnostics=list(struct.unpack_from('<8Q',d,96)),route=list(net(g,32)[0]),terminal=list(net(g,41)[0]),**fields);observed(value);print('Native progress',json.dumps(value),flush=True)
  g.project_observer=progress
  try:
   backing=out/'bob.img';approved_path=out/('bob.'+path.stem+'.approved-feed-profile')
   if not approved_path.exists():save_approved_profile(approved_path,export_public(g,True))
   approved=approved_path.read_bytes();author=approved[32:64];event_id=approved[128:160]
   assert event_id.hex()==next(x['event']for x in prior['checks']if 'same retained federation-scoped author publishes'in x['check'])
   old=next(row for _,row in rows(beta)if row[:32]==event_id);assert old[144:176]==author and struct.unpack_from('<Q',old,216)[0]==struct.unpack_from('<Q',approved,24)[0]
   assert sum(row[:32]==event_id for _,row in rows(beta))==1
   if 'recovery'not in c:c['recovery']=dict(key_generation=struct.unpack_from('<Q',approved,160)[0],root_generation=retained_generation(backing));save()
   if 'budget_before'not in record:record['budget_before']=list(feed.invoke(beta.client,490,action=12)[0]);save()
   upgrade=upgrade_retained_pair(g,campaign,a.packages.resolve(),c,save)
   assert upgrade['packages']['feed']['version']=='0.9.4'and upgrade['packages']['feed-account']['version']in('0.9.2','0.9.3')
   if not c.get('upgrade_recorded'):passed('normal per-component Feed successors and exact reused releases replace only Bob personal processes',**upgrade);c['upgrade_recorded']=True;save()
   selected_feed_route(g,beta,[actors['relay'+str(i)]for i in(1,2,3)],observed)
   public=export_public(g,True)if feed_ui(g)[0][1]else None
   recovered=public is not None and public[32:64]==author and struct.unpack_from('<Q',public,160)[0]>c['recovery']['key_generation']and retained_generation(backing)>c['recovery']['root_generation']
   if not recovered:
    assert feed_ui(g)[0][1]==0
    g.client.request(179,struct.pack('<2Q',g.feed_owner,1));focus_feed(g);g.device.press(59);g.device.press(61)
    if feed_ui(g,793)[0][5]!=1:g.device.press(62)
    g.device.textASCII(secret(out/'bob.feed-author-unlock',create=False).hex(),delay=.04);g.device.press(63)
    project.wait_native(g,lambda:feed_ui(g)[0][1]==1 and feed_ui(g)[0][5]==8 and feed_ui(g,793)[0][6]==1 and project.complete_read(g,g.feed_ui)and retained_generation(backing)>c['recovery']['root_generation'],180,'shipping retained author recovery and fresh reseal')
   focus_feed(g);settle_exact(g,beta,observed);public=export_public(g,True)
   assert public[32:128]==approved[32:128]and public[256:1792]==approved[256:1792]and struct.unpack_from('<Q',public,160)[0]>c['recovery']['key_generation']
   if public[128:160]!=event_id and c.get('new_event')!=public[128:160].hex():
    intent=c.get('followup_intent');assert intent and intent['content_sha256']==hashlib.sha256(TEXT.encode()).hexdigest()
    pending=match(beta,author,1,hashlib.sha256(TEXT.encode()).digest())
    assert pending is not None and pending[:32]==public[128:160]and pending[304:368]==approved[64:128]and read_body(beta,pending)==TEXT.encode()
    assert struct.unpack_from('<Q',pending,216)[0]>struct.unpack_from('<Q',approved,24)[0]
    c['new_event']=pending[:32].hex();save()
   assert public[128:160]==event_id or c.get('new_event')==public[128:160].hex()
   passed('shipping successor recovers same author and approved preferences with fresh authority and reconciles one exact prior committed copy',prior_event=event_id.hex(),prior_sequence=struct.unpack_from('<Q',approved,24)[0],key_generation=struct.unpack_from('<Q',public,160)[0],preference_sha256=hashlib.sha256(public[256:1792]).hexdigest(),old_copy_count=1,original_host_offline=True)
   for name,expected in(('long',state['events']['long']),('card',json.loads((out/'feed-project-account.json').read_text())['card'])):
    selected=next(row for _,row in rows(beta)if row[:32].hex()==expected['id']);body=read_body(beta,selected)
    assert hashlib.sha256(body).hexdigest()==expected.get('content_sha256',expected.get('body_sha256'))
    if not c.get(name+'_read'):
     displayed=checked_read(g,selected[:32],observed);assert displayed==selected
     frames=[screenshot(g,'shipping-'+name+'-read')]
     if name=='long':g.device.press(109);frames.append(screenshot(g,'shipping-long-scroll'))
     passed('shipping UI reads original checked '+name+' through Beta while Alpha remains offline',event=selected[:32].hex(),bytes=len(body),content_sha256=hashlib.sha256(body).hexdigest(),frames=frames)
     c[name+'_read']=True;save()
    if name=='card'and not c.get('revocation_checked'):
     focus_feed(g);g.device.press(46)
     project.wait_native(g,lambda:feed_ui(g)[0][4]==65 and feed_ui(g)[0][6]==11 and project.complete_read(g,g.feed_ui),180,'shipping original card inspection revalidates known Registry revocation')
     passed('shipping UI original card still refuses current Registry revocation at action time',native_status=list(feed_ui(g)[0]),new_fork=False,execution_approved=False);c['revocation_checked']=True;save()
   check_upgraded_local_block(g,state,approved,c,save,observed)
   event=match(beta,author,1,hashlib.sha256(TEXT.encode()).digest())
   if event is None:
    choose_move_audience(g,c,save);focus_feed(g);g.device.press(61);wait(lambda:feed_ui(g)[0][2]==1 and feed_ui(g)[0][3]==0,120,'shipping distinct native follow-up draft')
    g.device.textASCII(TEXT,delay=.035);wait(lambda:feed_ui(g)[0][3]==len(TEXT),180,'shipping follow-up native input');g.device.press(62);wait(lambda:feed_ui(g)[0][2]==9,60,'shipping exact preview')
    c['followup_intent']=dict(content_sha256=hashlib.sha256(TEXT.encode()).hexdigest(),bytes=len(TEXT));save();g.device.press(63)
    def accepted():
     progress('shipping follow-up durable acceptance');f=feed_ui(g)[0]
     if f[5]==8:raise RuntimeError(('shipping outbox requires exact reconciliation',list(f)))
     found=match(beta,author,1,hashlib.sha256(TEXT.encode()).digest())
     return found if found is not None and f[5]in(6,7)and project.complete_read(g,g.feed_ui)else None
    event=wait(accepted,600,'shipping native follow-up durable acceptance')
   assert event[304:368]==approved[64:128]and struct.unpack_from('<Q',event,216)[0]>struct.unpack_from('<Q',approved,24)[0]and read_body(beta,event)==TEXT.encode()
   c['new_event']=event[:32].hex();save();after=export_public(g,True)
   assert after[128:160]==event[:32]and after[256:1792]==approved[256:1792]and struct.unpack_from('<Q',after,160)[0]>c['recovery']['key_generation']
   save_approved_profile(out/('bob.'+path.stem+'.final-approved-feed-profile'),after)
   record['budget_after']=list(feed.invoke(beta.client,490,action=12)[0]);assert record['budget_after'][1]==record['budget_before'][1]and record['budget_after'][3]>=record['budget_before'][3]and record['budget_after'][3]<=record['budget_after'][1]
   assert record['budget_after'][2]>=record['budget_before'][2]and record['budget_after'][5]>=record['budget_before'][5]
   passed('shipping UI publishes distinct checked follow-up with same retained author and selected preferences within unchanged finite operator authority',event=event[:32].hex(),bytes=len(TEXT),sequence=struct.unpack_from('<Q',event,216)[0],key_generation=struct.unpack_from('<Q',after,160)[0],ui_publication_phase=feed_ui(g)[0][5],replication_claim=False,profile_sha256=hashlib.sha256(after).hexdigest(),preference_sha256=hashlib.sha256(after[256:1792]).hexdigest(),opaque_root_generation=retained_generation(backing),operator_refill=False)
   record.update(result='pass',seconds=time.monotonic()-began,frame=screenshot(g,'shipping-reader-final'));attempt.update(result='pass',seconds=record['seconds']);save()
  except BaseException as error:
   record.update(result='failure-preserved-native-actors',error=repr(error),traceback=traceback.format_exc(),seconds=time.monotonic()-began);attempt.update(result='failure',error=repr(error),seconds=record['seconds']);save();raise

if __name__=='__main__':main()
