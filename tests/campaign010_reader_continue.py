"""Re-fetch from the still-live independent seed after native reader failure.

Only the disposable failed reader restarts. The seed graph, catalog, identity
and durable store remain intact. No graph archive is imported into either side.
"""
import argparse,base64,contextlib,hashlib,json,os,signal,struct,sys,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import federation,forge,identity,network,projects,releases
from campaign010_forge_distribution import Node,PUBLIC
from creator_journey import require,rendered_text
from forge_journey import wait
from forge_replication import authenticate
from graphical_devices import DeviceInput

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('distribution','image','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--endpoint',required=True);p.add_argument('--failed-reader-pid',type=int,required=True);p.add_argument('--seed-pid',type=int,required=True)
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);source=json.loads((a.distribution/'execution.json').read_bytes());public=json.loads((a.distribution/'alpha-public-verifier.json').read_bytes());services=source['services']
 record=dict(schema=1,result='running',scope=__doc__,image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),source_distribution=str(a.distribution.resolve()),checks=[]);started=time.monotonic()
 def save():record['elapsed_seconds']=round(time.monotonic()-started,3);(out/'execution.json').write_text(json.dumps(record,indent=2)+'\n')
 def passed(label,**fields):record['checks'].append(dict(check=label,result='pass',**fields));save();print('PASS',label,flush=True)
 seed=object.__new__(Node);seed.path=a.distribution/'seed-surviving';seed.sock=seed.path/'portal.sock';seed.qmp=seed.path/'display.qmp';seed.ui=DeviceInput('qemu',seed.qmp);reader=None
 try:
  for info in services.values():require(hashlib.sha256(Path(info['path']).read_bytes()).hexdigest()==info['sha256'],'identified service bytes changed')
  with seed.client()as c:
   seed.instance=next(r[0]for r in identity.instances(c)if r[2]==3967 and r[1]in(1,2,3,4));before=projects.roots(c);old=forge.inspect(c,seed.instance);admission=forge.federation_inspect(c,seed.instance,True)
  require(old['offered_nodes']==24 and admission['local_phase']==2,'surviving seed lost its actual retained closure/admission')
  # The failed actor has no persistent private state. Terminating its process
  # closes the dead management stream and opaque TCP relationship normally.
  os.killpg(a.failed_reader_pid,signal.SIGKILL);time.sleep(.3)
  os.environ['LT_GUEST_IMAGE']=str(a.image.resolve());Node.server_package=Path(services['server_forge']['path'])
  reader=Node(out/'reader',a.endpoint)
  credentials=a.distribution/'reader-seed-continuation'
  reader.setup_link(Path(services['forge']['path']),credentials/'client.credential')
  with seed.client()as c:
   network.configure(c,credentials/'server.credential')
   forge.configure(c,seed.instance,credentials/'server.credential','seed','portable',old['server_store_grant'])
  with reader.client()as c:
   package=Path(services['registry']['path']);raw=package.read_bytes();c.request(10,raw[128:160]+releases.public_key(PUBLIC));slot,_=c.install(package);reader.registry=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',slot)),8)[0]
   federation.configure_native_verifier(c,reader.registry,public['public_key'],'consumer',allowed_rights=895,generation=public['generation']);forge.federation_configure(c,reader.instance,public['federation_id'],3)
  authenticate(reader,seed)
  # Repeat an ordinary offer gesture for the selected retained root, then wait
  # for both metadata and the actual async signed decision before requesting it.
  seed.focus(seed.instance);seed.ui.press(62)
  wait(lambda:seed.inspect()['offered_nodes']==24,'surviving seed exact offer',90)
  reader.focus(reader.instance);reader.ui.press(61)
  wait(lambda:reader.inspect()['status']==6,'actual seed metadata',180)
  def reviewed():
   with reader.client()as c:r=forge.federation_inspect(c,reader.instance)
   if r['remote_phase']==3:raise AssertionError(('current federation refused',r))
   return r if r['remote_phase']==2 and r['descriptor']['release_id']==source['release_id'] else None
  decision=wait(reviewed,'actual signed positive chosen federation review',180)
  reader.ui.press(63)
  def complete():
   value=reader.inspect()
   if value['status']==9:raise AssertionError(('native fetch failed',value))
   return value if value['status']==11 and not value['import_transaction'] else None
  fetched=wait(complete,'actual native signed closure fetch',300)
  wait(lambda:seed.inspect()['status']==10,'actual completion receipt',120)
  with reader.client()as c:
   actual=next(r for r in projects.roots(c)if r['head']==public['root']);exported=projects.archive(c,actual['cap'],out/'fetched-graph.json')
  actual_graph=json.loads((out/'fetched-graph.json').read_bytes());expected=json.loads((ROOT/'build/campaign010-notes-native-4/project-notes-graph.json').read_bytes())
  def records(doc):return {r['id']:(r['kind'],r['schema'],r['parent'],base64.b64decode(r['payload'],validate=True))for r in doc['nodes']}
  require(records(actual_graph)==records(expected),'fetched native graph differs from actual signed export')
  with seed.client()as c:require(projects.roots(c)==before,'provider root state changed during reader restart')
  passed('fresh disposable reader retrieves exact24node212881byte closure from unchanged surviving seed after original source and Alpha offline',fetched=fetched,decision=decision,export=exported,provider_roots_unchanged=True,source_graph_imported=False)
  # F1 leaves Forge's federation detail view. F6 asks the native shell to stage
  # graph bytes and cryptographically verify them before trusted package review.
  with reader.client()as c:
   # Publisher trust is separate from federation admission and execution.
   # Extract the exact selected signed Release public key from fetched bytes.
   entries=projects.decode_manifest(c.read_object(projects.resolve(c,actual['cap'],actual['head'])))
   release_node=next(i for n,k,i in entries if k==13 and not n.startswith('deps/'))
   release_bytes=c.read_object(projects.resolve(c,actual['cap'],release_node))
   count=struct.unpack_from('<Q',release_bytes,16)[0];signed=release_bytes[96+count*128:96+count*128+608]
   require(signed[160:192].hex()==source['release_id'],'selected publisher release differs')
   c.request(10,signed[128:160]+signed[576:608])
  reader.focus(reader.instance)
  if rendered_text(reader.ui.frame(),10,56,10,0x9fc6a5)=='FEDERATION':reader.ui.press(59)
  reader.ui.press(64)
  frame=wait(lambda:(f if rendered_text(f:=reader.ui.frame(),16,12,24)=='SIGNED PACKAGE CANDIDATE'else None),'native F6 trusted executable review without stack fault',180)
  (out/'native-f6-review.ppm').write_bytes(frame.ppm());reader.ui.press(28)
  publication=decision['descriptor']['publication_id']
  def active():
   with reader.client()as c:
    try:r=c.request(29,bytes.fromhex(publication))
    except ValueError:return None
   return r if r[160:192].hex()==source['release_id'] else None
  wait(active,'native exact fetched Notes activation',120)
  frame=wait(lambda:(f if rendered_text(f:=reader.ui.frame(),14,152,8,0xdce9ec)=='Title / 'else None),'actual application first visible input row',90)
  reader.ui.textASCII('Provider review',delay=.15);reader.ui.press(28);time.sleep(.3);reader.ui.textASCII('Verified surviving provider source and helper.',delay=.15);reader.ui.chord(29,31)
  wait(lambda:rendered_text(reader.ui.frame(),14,354,24,0xdce9ec)=='Saved immutable revision','actual second user note saved',90)
  reader.ui.chord(29,33);reader.ui.textASCII('surviving',delay=.15);reader.ui.press(28);reader.ui.press(1)
  frame=wait(lambda:(f if rendered_text(f:=reader.ui.frame(),18,170,27,0xdce9ec)=='Verified surviving provider'else None),'actual second user note search',90)
  (out/'native-notes-used.ppm').write_bytes(frame.ppm())
  with reader.client()as c:require(next(r for r in identity.instances(c)if r[0]&255==1)[3]==0,'Launcher faulted during native graph install')
  passed('native Forge F6 verifies exact graph and trusted review installs useful Notes; second user creates and searches real note',release_id=source['release_id'],publisher=publication,application_frame=frame.digest,native_stack_guard_preserved=True)
  live_record=dict(schema=1,pid=reader.proc.pid,socket=str(reader.sock),graphics=str(reader.qmp),backend='qemu',image=str(a.image.resolve()),image_sha256=record['image_sha256'],forge=reader.instance,registry=reader.registry,root=actual,release_id=source['release_id'],live_only=True)
  (out/'reader-live.json').write_text(json.dumps(live_record,indent=2)+'\n');record.update(result='pass',reader_continuation=str(out/'reader-live.json'));save()
 except BaseException as error:
  record.update(result='failure',error=repr(error),traceback=traceback.format_exc());save();raise
 finally:
  if seed.ui:seed.ui.close()
  if reader:
   if reader.ui:reader.ui.close()
   if reader.log:reader.log.close()
   record['live_reader']=dict(pid=reader.proc.pid,socket=str(reader.sock),graphics=str(reader.qmp),forge=getattr(reader,'instance',None),registry=getattr(reader,'registry',None));save()
 return 0
if __name__=='__main__':raise SystemExit(main())
