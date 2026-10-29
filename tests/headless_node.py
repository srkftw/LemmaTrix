"""Normal lt node init/run/inspect/stop, own-store recovery and native retrieval."""
import argparse,hashlib,json,os,re,signal,socket,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import forge,live,network,projects,releases
from forge_journey import Node,wait

def archive(client,instance):
 raw=client.request(150,struct.pack('<Q',instance)+struct.pack('<8Q',55,0,0,0,0,0,0,1))
 assert len(raw)==208 and struct.unpack_from('<Q',raw)[0]==0
 phase,done,total,code,root=struct.unpack_from('<5Q',raw,64);n=struct.unpack_from('<Q',raw,136)[0]
 return dict(phase=phase,done=done,total=total,code=code,root=root,head=raw[104:136].hex(),name=raw[144:144+n].decode('ascii'))

def prepare(args,out):
 setup_path=out/'setup.json'
 if setup_path.exists():return json.loads(setup_path.read_text())
 # Explicit existing operator inputs; the test never initializes, copies or
 # reconstructs the selected store. It must already hold an admitted archive.
 store=args.store.resolve();private=args.operator_key.resolve();public=args.operator_public.resolve();binary=args.server_binary.resolve()
 if not all(p.is_file() for p in (store,private,public,binary)):raise ValueError('existing server backing, role binary and explicit operator key/public files are required')
 package=out/'native-forge-headless.ltrel'
 if not package.exists():
  data,manifest=releases.make(binary,'native-forge-headless','0.4.0',3199,private,sources=[ROOT/'Guest/Forge.lean',ROOT/'Guest/ForgeArchive.lean'],profile=2,source_base=ROOT)
  package.write_bytes(data);Path(str(package)+'.manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 info=releases.inspect(package.read_bytes());assert info['rights']==3199
 client=out/'client.credential';server=out/'server.credential'
 network.provision(client,server,os.getrandom(32),os.getrandom(32),hashlib.sha256(b'headless node operator selected service').digest())
 probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
 setup=dict(release_id=info['release_id'],rights=info['rights'],namespace=args.namespace,endpoint=f'127.0.0.1:{port}',store=str(store),package=str(package.resolve()),public=str(public),credentials=str(server.resolve()))
 setup_path.write_text(json.dumps(setup,indent=2)+'\n');return setup

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'build/headless-node-operator');p.add_argument('--client-package',type=Path,default=ROOT/'build/forge-server-recovery-final2/native-forge-server.ltrel');p.add_argument('--client-public',type=Path,default=ROOT/'build/forge-server-recovery-final2/operator.pub');p.add_argument('--store',type=Path,default=ROOT/'build/forge-server-recovery-final2/server.img');p.add_argument('--operator-key',type=Path,default=ROOT/'build/forge-server-recovery-final2/operator.pem');p.add_argument('--operator-public',type=Path,default=ROOT/'build/forge-server-recovery-final2/operator.pub');p.add_argument('--server-binary',type=Path,default=ROOT/'build/live/apps/forge-server.bin');p.add_argument('--namespace',default=hashlib.sha256(b'explicit native Forge seed archive test').hexdigest());a=p.parse_args();out=a.output;out.mkdir(parents=True,exist_ok=True)
 setup=prepare(a,out);config=out/'node.json';sock=out/'operator.sock';log=(out/'operator.log').open('wb');node=None;client_node=None
 image=hashlib.sha256((ROOT/'build/live/guest.bin').read_bytes()).hexdigest()
 pinned=ROOT/'build/platform'/f'{image}.bin'
 if pinned.exists():os.environ['LT_GUEST_IMAGE']=str(pinned)
 init=[str(ROOT/'lt'),'node','init',str(config),'--role','seed','--package',setup['package'],'--public',setup['public'],'--credentials',setup['credentials'],'--release-id',setup['release_id'],'--rights',str(setup['rights']),'--store',setup['store'],'--namespace',setup['namespace'],'--bytes','1048576','--endpoint',setup['endpoint'],'--listen','--recover-and-seed']
 try:
  if not config.exists():
   initialized=subprocess.run(init,cwd=ROOT,capture_output=True,text=True,check=True);(out/'initialized.json').write_text(initialized.stdout)
  else:
   approved=json.loads(config.read_text())
   assert all(approved[k]==setup[k] for k in ['package','release_id','rights','namespace','endpoint'])
   assert approved['server_store']==setup['store'] and approved['recover_and_seed'] is True
  node=subprocess.Popen([str(ROOT/'lt'),'node','run',str(config),'--socket',str(sock)],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  def ready():
   if node.poll() is not None:raise AssertionError(('headless node exited',node.returncode,(out/'operator.log').read_text()))
   text=(out/'operator.log').read_text()
   return int(re.search(r'"instance":\s*(\d+)',text).group(1)) if '"headless": true' in text else None
  instance=wait(ready,'operator headless startup',180)
  def recovered():
   c=live.Client(sock)
   try:
    state=archive(c,instance)
    if state['phase']==9:raise AssertionError(('own-store recovery failed',state))
    status=forge.inspect(c,instance)
    return (state,status) if state['phase']==8 and status['frozen_root'] and status['offered_nodes'] else None
   finally:c.close()
  archived,status=wait(recovered,'headless own-store graph recovery and selected serving',180)
  c=live.Client(sock)
  try:
   roots=projects.roots(c);assert len(roots)==1 and roots[0]['head']==archived['head'],roots
   head,expected=projects.snapshot(c,roots[0]['cap']);assert head==archived['head']
   procs=c.request(2);actual=next(struct.unpack_from('<4Q',procs,i) for i in range(0,len(procs),32) if struct.unpack_from('<Q',procs,i)[0]==instance)
   assert actual[2]==3199 and not actual[2]&768,actual
  finally:c.close()
  print('PASS headless role recovered its own committed server backing',flush=True)
  client_node=Node(out/'recipient',setup['endpoint']);c=client_node.client()
  try:network.configure(c,out/'client.credential')
  finally:c.close()
  def authenticated():
   result=[]
   for path in [sock,client_node.sock]:
    c=live.Client(path)
    try:result.append(network.status(c)['endpoint_authenticated'])
    finally:c.close()
   return all(result)
  wait(authenticated,'headless/client authenticated bulk session',120)
  client_info=client_node.install(a.client_package,a.client_public);c=client_node.client()
  try:forge.configure(c,client_node.instance,out/'client.credential')
  finally:c.close()
  client_node.ui.press(61)
  metadata=wait(lambda:(s if (s:=client_node.inspect())['metadata_nodes'] else None),'native peer metadata',120)
  assert client_node.roots()==[],'metadata query retrieved content'
  client_node.ui.press(63)
  def fetched():
   s=client_node.inspect()
   if s['status']==9:raise AssertionError(('native retrieval rejected',s))
   return s if s['status']==11 and s['selected_root'] and not s['import_transaction'] else None
  fetched_state=wait(fetched,'native retrieval from recovered headless seed',240)
  c=client_node.client()
  try:
   roots=projects.roots(c);assert len(roots)==1 and roots[0]['head']==head,roots
   actual,retrieved=projects.snapshot(c,roots[0]['cap']);assert actual==head and retrieved==expected
  finally:c.close()
  inspected=subprocess.run([str(ROOT/'lt'),'node','inspect','--socket',str(sock),'--instance',str(instance)],cwd=ROOT,capture_output=True,text=True,check=True);(out/'inspected.json').write_text(inspected.stdout)
  stop=subprocess.run([str(ROOT/'lt'),'node','stop','--socket',str(sock)],cwd=ROOT,capture_output=True,text=True,timeout=30);(out/'stop.stdout').write_text(stop.stdout);(out/'stop.stderr').write_text(stop.stderr)
  assert stop.returncode==0,('operator stop exit',stop.returncode,stop.stderr)
  assert node.wait(timeout=15)==0
  report=dict(status='passed',image=image,headless_role_release=setup['release_id'],headless_rights=3199,store=setup['store'],namespace=setup['namespace'],recovered=archived,source_bytes=sum(map(len,expected.values())),source_files=len(expected),native_client_release=client_info['release_id'],native_metadata=metadata,native_fetch=fetched_state,commands=['node init exact release/rights','node run --recover-and-seed from explicit config','node inspect','node stop'],scope='Two separate QEMU guests on one host; fresh ordered peer provisioning; original server backing reused directly; no graph fixture replay or backing copy')
  (out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:
  if client_node:client_node.stop()
  if node and node.poll() is None:
   try:
    c=live.Client(sock,timeout=5)
    try:c.request(70)
    except EOFError:pass
    finally:c.close()
   except BaseException:pass
   try:node.wait(timeout=12)
   except subprocess.TimeoutExpired:os.killpg(node.pid,signal.SIGKILL);node.wait()
  log.close()
if __name__=='__main__':main()
