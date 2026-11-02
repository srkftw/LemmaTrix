"""Continue the exact live Forge operation after asynchronous admission review.

Only the public portal and physical QMP input are used. The seed receives every
object from the still-live accepted Alpha offer, then retains its own graph and
verified public catalog before a fresh reader retrieves it after Alpha exits.
"""
import argparse,base64,hashlib,json,os,socket,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import federation,forge,live,network,projects,releases,server_store
from campaign010_forge_distribution import Node,PUBLIC,digest
from creator_journey import rendered_text
from graphical_devices import DeviceInput
from forge_journey import wait
from forge_replication import authenticate,save


def attach(row):
 n=object.__new__(Node);n.path=Path(row['socket']).parent;n.sock=Path(row['socket']);n.qmp=Path(row['graphics']);n.instance=row['forge'];n.registry=row['registry'];n.ui=DeviceInput('qemu',n.qmp);n.log=None;n.pid=row['pid'];return n


def stop(n):
 if n.ui:n.ui.close();n.ui=None
 try:
  c=n.client()
  try:c.request(70)
  except EOFError:pass
  finally:c.close()
 except (OSError,EOFError):pass


def verify_closure(n,archive):
 root=next(r for r in n.roots()if r['head']==archive['selected'][0]['head']);actual={};cursor=0
 with n.client()as c:
  assert projects.project_identity(c,root['cap'])==archive['project_id']
  while True:
   fields,ids=c.objects(26,root['cap'],cursor)
   if not fields[1]:break
   actual[ids[:32].hex()]=(fields[4],fields[5],ids[32:64].hex(),c.read_object(fields[1],True));cursor=fields[3]
 expected={r['id']:(r['kind'],r['schema'],r['parent'],base64.b64decode(r['payload'],validate=True))for r in archive['nodes']}
 assert actual==expected,'actual native closure differs from the selected signed graph'
 return dict(head=root['head'],records=len(actual),payload_bytes=sum(len(r[3])for r in actual.values()))


def fetch(sender,receiver,archive,discover=True):
 receiver.focus(receiver.instance)
 if discover:receiver.ui.press(61)
 head=archive['selected'][0]['head']
 def approved():
  with receiver.client()as c:r=forge.federation_inspect(c,receiver.instance)
  return r if r['remote_phase']==2 and r['descriptor']['root']==head else None
 decision=wait(approved,'actual chosen federation admission completes before F5',180)
 receiver.ui.press(63)
 def complete():
  s=receiver.inspect()
  if s['status']==9:raise AssertionError(('native transfer rejected',s))
  return s if s['status']==11 and not s['import_transaction']else None
 completed=wait(complete,'actual signed source and executable closure fetched',300)
 exact=verify_closure(receiver,archive)
 wait(lambda:sender.inspect()['status']==10,'native validated completion receipt',120)
 return dict(**exact,decision=decision,completed=completed)


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('state','archive','registry','forge','server-forge'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();state=json.loads(a.state.read_text());base=a.state.parent;report=json.loads((base/'execution.json').read_text());archive=json.loads(a.archive.read_text());os.environ['LT_GUEST_IMAGE']=state['image'];Node.server_package=a.server_forge
 alpha,seed=[attach(row)for row in state['actors']];nodes=[alpha,seed];started=time.monotonic();phase='resume after native pending-admission denial'
 selected=archive['selected'][0];head=selected['head'];record=report['checks'][0]['remote']['descriptor'];publication=bytes.fromhex(record['publication_id']);release_id=record['release_id']
 release_node=next(r for r in archive['nodes']if r['kind']==13 and bytes.fromhex(release_id)in base64.b64decode(r['payload']))
 raw=base64.b64decode(release_node['payload']);off=96+struct.unpack_from('<Q',raw,16)[0]*128;publisher=raw[off+576:off+608]
 def write():
  report.update(stage=phase,continuation_elapsed_seconds=round(time.monotonic()-started,3));(base/'execution.json').write_text(json.dumps(report,indent=2)+'\n')
 def passed(label,**fields):report['checks'].append(dict(check=label,result='pass',**fields));write();print('PASS',label,flush=True)
 def verifier(n,configuration,retain=False):
  with n.client()as c:
   raw=a.registry.read_bytes();c.request(10,raw[128:160]+releases.public_key(PUBLIC));slot,_=c.install(a.registry);n.registry=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',slot)),8)[0]
   grant=0
   if retain:
    server_store.call(c,230);grant=server_store.call(c,231,n.registry,1,1048576,digest('Campaign010 seed verified catalog'))[0][1]
   federation.configure_native_verifier(c,n.registry,configuration['public_key'],'consumer',store_grant=grant,allowed_rights=895,generation=configuration['generation'])
   if retain:assert federation.call(c,n.registry,10)[0][1]>0
   forge.federation_configure(c,n.instance,configuration['federation_id'],3)
 try:
  first=fetch(alpha,seed,archive,False);stored=save(seed)
  with seed.client()as c:sequence=federation.call(c,seed.registry,23)[0][1]
  with alpha.client()as c:q,_=federation.call(c,alpha.registry,14)
  pub=json.loads((base/'alpha-public-verifier.json').read_text());configuration=dict(public_key=pub['public_key'],federation_id=pub['federation_id'],generation=q[2]);assert configuration['generation']>1
  passed('restarted Alpha recovers accepted catalog and sealed identity, then seeds independent provider through exact Forge transfer',transfer=first,seed_commit=stored,retained_sequence=sequence,recovery=configuration)
  for n in nodes:stop(n)
  nodes=[];phase='surviving seed retrieval and second-user native install';write()
  relation=base/'reader-seed-continuation';relation.mkdir();probe=socket.socket();probe.bind(('127.0.0.1',0));endpoint='127.0.0.1:'+str(probe.getsockname()[1]);probe.close()
  reader_key,seed_key=relation/'client.credential',relation/'server.credential';network.provision(reader_key,seed_key,digest('new personal reader'),digest('seed'),digest('Campaign010 public Forge surviving relationship'))
  seed=Node(base/'seed-surviving',endpoint,True,base/'seed.img');nodes.append(seed);reader=Node(base/'reader',endpoint);nodes.append(reader)
  seed.setup_link(a.forge,seed_key,digest('Campaign010 seed graph'),role='seed');reader.setup_link(a.forge,reader_key)
  verifier(seed,configuration,True);verifier(reader,configuration);authenticate(reader,seed)
  preview=seed.recover(digest('Campaign010 seed graph'),head)
  final=fetch(seed,reader,archive)
  reader.focus(reader.instance)
  with reader.client()as c:
   c.request(10,publication+publisher)
   try:c.request(29,publication)
   except ValueError:pass
   else:raise AssertionError('fetch granted execution without approval')
  reader.ui.press(64)
  frame=wait(lambda:(f if rendered_text(f:=reader.ui.frame(),16,12,24)=='SIGNED PACKAGE CANDIDATE'else None),'fetched release trusted execution review',180)
  assert rendered_text(frame,80,40,13)=='project-notes';(reader.path/'exact-notes-approval.ppm').write_bytes(frame.ppm());time.sleep(.4);reader.ui.press(28)
  def active():
   with reader.client()as c:
    try:r=c.request(29,publication)
    except ValueError:return False
   return r[160:192].hex()==release_id
  wait(active,'exact fetched native Notes release active',180)
  frame=wait(lambda:(f if rendered_text(f:=reader.ui.frame(),14,56,13,0xdce9ec)=='Project Notes'else None),'actual native Project Notes surface',120)
  (reader.path/'project-notes-running.ppm').write_bytes(frame.ppm())
  reader.ui.textASCII('Distribution review',delay=.08);reader.ui.press(28);reader.ui.textASCII('Verified the surviving provider supplied the signed source and helper.',delay=.08);reader.ui.chord(29,31)
  wait(lambda:rendered_text(reader.ui.frame(),14,354,24,0xdce9ec)=='Saved immutable revision','actual second-user note revision',90)
  reader.ui.chord(29,33);reader.ui.textASCII('surviving',delay=.08);reader.ui.press(28);reader.ui.press(1)
  frame=wait(lambda:(f if rendered_text(f:=reader.ui.frame(),18,170,31,0xdce9ec)=='Verified the surviving provider'else None),'actual second-user searches note body',90);(reader.path/'project-notes-used.ppm').write_bytes(frame.ppm())
  passed('surviving restarted provider supplies exact release, helper, source and admission while publisher and Alpha are offline; second user installs and uses native Notes',transfer=final,preview=preview,release_id=release_id,application_frame=frame.digest)
  root=next(r for r in reader.roots()if r['head']==head)
  live_state=dict(schema=1,pid=reader.proc.pid,socket=str(reader.sock),graphics=str(reader.qmp),backend='qemu',image=state['image'],image_sha256=report['image_sha256'],forge=reader.instance,registry=reader.registry,root=root,release_id=release_id,live_only=True)
  (base/'reader-live.json').write_text(json.dumps(live_state,indent=2)+'\n');report.update(result='pass',reader_continuation=str(base/'reader-live.json'));nodes.remove(reader);reader.ui.close();reader.ui=None;reader.log.close();write()
 except BaseException as error:
  report.update(result='continuation failure',error=repr(error));raise
 finally:
  for n in nodes:
   try:(n.path/'continuation-final.ppm').write_bytes(n.ui.frame().ppm())
   except Exception:pass
   if n.ui:n.ui.close();n.ui=None
  # Failed native actors are deliberately left live for normal-interface
  # diagnosis. A successful seed is stopped; the actual reader remains live.
  if report.get('result')=='pass':
   for n in nodes:stop(n)
  else:report['live_actors']=[dict(pid=getattr(n,'pid',getattr(getattr(n,'proc',None),'pid',None)),socket=str(n.sock),graphics=str(n.qmp),forge=n.instance,registry=n.registry,live_only=True)for n in nodes]
  write()

if __name__=='__main__':main()
