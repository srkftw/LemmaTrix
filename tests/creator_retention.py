"""One real bank-body interruption and exact-image Project Vault recovery.

Uses the existing management byte boundary for explicit retention, separately
from creator_journey's keyboard/pointer acceptance. No host plaintext archive,
image patch, guest memory write, rebuild, publisher signing or crypto-vector run.
"""
import argparse,contextlib,hashlib,json,os,signal,shutil,struct,subprocess,sys,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import driver,live,projects,project_vault


def require(value,message):
 if not value:raise AssertionError(message)


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path,value):Path(path).write_text(json.dumps(value,indent=2)+'\n')


def node_summary(node):return {k:node[k] for k in ('kind','length','id','parent','sha256')}


def head_map(roots):return {r['name']:r['head'] for r in roots}


class Session:
 def __init__(self,args,vault):
  self.args=args;self.vault=vault;self.proc=None;self.log=None;self.round=0
  self.runtime=args.output/'runtime';self.socket=args.output/'portal.sock'
  (self.runtime/'live').mkdir(parents=True,exist_ok=True)
  require(digest(args.image)==args.expected_image,'input guest image differs from requested identity')
  shutil.copy2(args.image,self.runtime/'live/guest.bin')
  if args.backend!='qemu':
   binary=ROOT/'build'/('lt-'+args.backend)
   require(binary.is_file(),'assembly backend must already be built: '+str(binary))
   shutil.copy2(binary,self.runtime/binary.name)
 def boot(self):
  require(digest(self.runtime/'live/guest.bin')==self.args.expected_image,'frozen runtime image changed')
  require(not self.proc or self.proc.poll() is not None,'previous owned guest is still running')
  self.socket.unlink(missing_ok=True);self.round+=1
  self.log=(self.args.output/f'transport-{self.round}.log').open('wb')
  command=[sys.executable,__file__,'_serve','--backend',self.args.backend,'--runtime',self.runtime,'--socket',self.socket,'--vault',self.vault]
  self.proc=subprocess.Popen(list(map(str,command)),cwd=ROOT,stdout=self.log,stderr=self.log,start_new_session=True)
  deadline=time.monotonic()+90
  while not self.socket.exists():
   require(self.proc.poll() is None,'guest exited before management readiness; inspect transport log')
   if time.monotonic()>deadline:raise TimeoutError('guest management readiness')
   time.sleep(.05)
 @contextlib.contextmanager
 def client(self):
  client=live.Client(self.socket,timeout=600)
  try:yield client
  finally:client.close()
 def stop(self,hard=False):
  if self.proc and self.proc.poll() is None:
   if hard:os.killpg(self.proc.pid,signal.SIGKILL)
   else:
    try:
     with self.client() as client:client.request(70)
    except (EOFError,OSError):pass
   try:self.proc.wait(timeout=20)
   except subprocess.TimeoutExpired:
    os.killpg(self.proc.pid,signal.SIGKILL);self.proc.wait(timeout=5)
  if self.log:self.log.close();self.log=None
  self.socket.unlink(missing_ok=True)


def rejected(client,op,handle):
 try:client.objects(op,handle)
 except ValueError as error:
  require('status3' in str(error),'stale authority rejected for an unexpected reason: '+str(error))
 else:raise AssertionError('authority from the previous session remained usable')


def recovered_graph(client,expected):
 """Inspect actual reimported Objects metadata, including selected ancestry."""
 imported={};cursor=0
 while cursor<256:
  fields,_=client.objects(9,a=cursor)
  handle=fields[1]
  if not handle:break
  cursor=(handle&255)+1
  if 10<=fields[4]<=14:
   metadata,ids=client.objects(21,handle)
   ordinary,payload_digest=client.objects(5,handle)
   imported[ids[:32].hex()]=dict(kind=metadata[4],length=metadata[2],id=ids[:32].hex(),parent=ids[32:64].hex(),sha256=payload_digest.hex())
 target={n['id']:node_summary(n) for n in expected['nodes']}
 require({key:imported.get(key) for key in target}==target,'recovered Objects graph differs from complete authenticated archive')
 require(set(imported)==set(target),'unexpected graph nodes became visible during recovery')
 roots=projects.roots(client,include_identity=True)
 require(head_map(roots)==head_map(expected['projects']),'recovered project names or heads differ')
 return dict(nodes=len(imported),bytes=sum(n['length'] for n in imported.values()),roots=roots)


def prepare_revision(client,recovered,project):
 primary=next((r for r in recovered['roots'] if r['name']==project),None)
 require(primary is not None,'selected retained project is absent: '+project)
 previous=client.objects(24,primary['cap'])[0][1]
 old_payload=client.read_object(previous);entries=projects.decode_manifest(old_payload)
 detail=old_payload[32+len(entries)*128:]
 name='interruption/probe.bin'
 require(name not in {entry[0] for entry in entries},'fixture already has interruption probe')
 payload=(b'LemmaTrix explicit interruption resource\n'+bytes(range(256)))*160
 require(len(payload)<=65536,'probe must fit one bounded Source')
 source,source_id=projects.node(client,payload,10)
 manifest=projects.manifest(entries+[(name,10,source_id)],detail)
 head_handle,head_id=projects.node(client,manifest,11,previous)
 client.objects(22,head_handle,primary['cap'],len(project),data=bytes.fromhex(primary['head'])+project.encode('ascii').ljust(64,b'\0'))
 extra=[]
 for handle in (source,head_handle):
  fields,ids=client.objects(21,handle);_,sha=client.objects(5,handle)
  extra.append(dict(kind=fields[4],length=fields[2],id=ids[:32].hex(),parent=ids[32:64].hex(),sha256=sha.hex()))
 return primary['cap'],head_id,extra


def restore_and_check(session,key,reference,stale=()):
 session.boot()
 with session.client() as client:
  project_vault.unlock(client,key)
  inventory=project_vault.inventory(client)
  candidates=[reference['before'],reference['candidate']]
  expected=next((c for c in candidates if inventory['generation']==c['generation'] and head_map(inventory['projects'])==head_map(c['projects'])),None)
  require(expected is not None,'recovery exposed neither complete old nor complete new snapshot')
  require({n['id']:node_summary(n) for n in inventory['nodes']}=={n['id']:node_summary(n) for n in expected['nodes']},'authenticated recovery returned a partial/mixed record set')
  restored=project_vault.recover(client)
  graph=recovered_graph(client,expected)
  for operation,handle in stale:rejected(client,operation,handle)
 session.stop()
 return dict(generation=restored['generation'],graph=graph,snapshot='old' if expected is reference['before'] else 'new',fresh_authority=True)


def interrupt(args):
 require(args.backend=='qemu','the single persistence interruption is executed on QEMU reference only')
 require(not args.output.exists(),'output must be a new owned directory')
 args.output.mkdir(parents=True)
 backing=args.output/'interrupted-vault.img';shutil.copy2(args.vault,backing)
 source_digest=digest(args.vault);key=args.key.read_bytes()
 session=Session(args,backing);thread=None;worker_client=None
 try:
  session.boot()
  with session.client() as client:
   project_vault.unlock(client,key)
   baseline=project_vault.inventory(client)
   require(len(baseline['projects'])>=2 and baseline['bytes']>65536 and len(baseline['nodes'])>2,'fixture must retain at least two names and a complete graph exceeding64KiB')
   recovered=project_vault.recover(client)
   recovered_graph(client,baseline)
   private=client.import_object(b'private interruption-session object; explicitly not retained',2)
   selected,new_head,extra=prepare_revision(client,recovered,args.project)
   candidate=dict(generation=baseline['generation']+1,bytes=baseline['bytes']+sum(n['length'] for n in extra),projects=[dict(r,head=new_head) if r['name']==args.project else r for r in baseline['projects']],nodes=baseline['nodes']+extra)
   reference=dict(image=args.expected_image,before=baseline,candidate=candidate)
   write_json(args.output/'reference.json',reference)
  # Observe a second nonempty record's actual inactive-bank body sector. This
  # proves real encrypted multi-object writes reached the supplied backing; the
  # commit roots must still be unchanged when this owned QEMU process is killed.
  first=next(n for n in baseline['nodes'] if n['length'])
  chunk=(first['length']+4095)//4096
  bank=512+(candidate['generation']%2)*10240
  sector=bank+32+chunk*9
  with backing.open('rb',buffering=0) as file:
   file.seek(sector*512);old_sector=file.read(512)
   file.seek(2*512);old_roots=file.read(1024)
  result={};worker_client=live.Client(session.socket,timeout=600)
  def save():
   try:result['ack']=project_vault.retain(worker_client,[selected])
   except BaseException as error:result['error']=type(error).__name__
   finally:worker_client.close()
  thread=threading.Thread(target=save,daemon=True);thread.start()
  deadline=time.monotonic()+600;observed=False
  with backing.open('rb',buffering=0) as file:
   while time.monotonic()<deadline:
    file.seek(sector*512)
    if file.read(512)!=old_sector:observed=True;break
    require(thread.is_alive(),'save finished before an inactive-bank body write was observed: '+repr(result))
    time.sleep(.002)
  require(observed,'inactive bank body write was not observed')
  session.stop(hard=True);thread.join(timeout=10)
  require(not thread.is_alive(),'interrupted management transport did not terminate')
  require('ack' not in result,'save acknowledged durability before interruption')
  with backing.open('rb',buffering=0) as file:file.seek(2*512);new_roots=file.read(1024)
  require(new_roots==old_roots,'chosen interruption raced beyond root publication')
  require(digest(args.vault)==source_digest,'source saved fixture was modified')
  checked=restore_and_check(session,key,reference,[(24,r['cap']) for r in recovered['roots']]+[(5,private)])
  report=dict(image=args.expected_image,backend=args.backend,environment='QEMU RISC-V reference, headless',source_vault_sha256=source_digest,interrupted_vault_sha256=digest(backing),boundary=dict(inactive_bank=candidate['generation']%2,observed_sector=sector,completed_prior_record_chunks=chunk,commit_roots_unchanged=True,durability_acknowledged=False),recovery=checked)
  write_json(args.output/'retention.json',report);print(json.dumps(report,indent=2),flush=True)
  return 0
 finally:
  session.stop(hard=True)
  if thread and thread.is_alive() and worker_client:worker_client.close();thread.join(timeout=5)


def recover(args):
 require(not args.output.exists(),'output must be a new owned directory')
 reference=json.loads(args.reference.read_text())
 require(reference['image']==args.expected_image,'reference and requested guest image differ')
 args.output.mkdir(parents=True)
 backing=args.output/'recovery-vault.img';shutil.copy2(args.vault,backing)
 session=Session(args,backing)
 try:
  checked=restore_and_check(session,args.key.read_bytes(),reference)
  environment={'qemu':'QEMU RISC-V reference, headless','x86_64':'native x86_64 assembly emulator, headless','aarch64':'ARM64 assembly emulator under qemu-aarch64, headless'}[args.backend]
  report=dict(image=args.expected_image,backend=args.backend,environment=environment,recovery=checked)
  write_json(args.output/'recovery.json',report);print(json.dumps(report,indent=2),flush=True)
  return 0
 finally:session.stop(hard=True)


def main():
 parser=argparse.ArgumentParser(description='Exact-image multi-object Project Vault interruption/recovery')
 sub=parser.add_subparsers(dest='command',required=True)
 internal=sub.add_parser('_serve');internal.add_argument('--backend',required=True);internal.add_argument('--runtime',type=Path,required=True);internal.add_argument('--socket',type=Path,required=True);internal.add_argument('--vault',type=Path,required=True)
 for name in ('interrupt','recover'):
  p=sub.add_parser(name);p.add_argument('--backend',choices=('qemu','x86_64','aarch64'),default='qemu');p.add_argument('--image',type=Path,required=True);p.add_argument('--expected-image',required=True);p.add_argument('--vault',type=Path,required=True);p.add_argument('--key',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
  if name=='interrupt':p.add_argument('--project',default='creator')
  else:p.add_argument('--reference',type=Path,required=True)
 args=parser.parse_args()
 if args.command=='_serve':driver.BUILD=args.runtime.resolve();return live.session(args.backend,args.socket,args.vault)
 args.output=args.output.resolve();args.image=args.image.resolve();args.vault=args.vault.resolve();args.key=args.key.resolve()
 return interrupt(args) if args.command=='interrupt' else recover(args)
if __name__=='__main__':raise SystemExit(main())
