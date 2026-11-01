"""Continue preserved native clients after replacing only their Mailbox app.

Relays, terminal listener, users, contact keys and message state remain native
and running. The adapter fault pauses only an explicitly selected opaque link.
"""
import argparse,contextlib,hashlib,json,socket,struct,sys,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import identity,messenger,projects,releases
from messenger_journey import Guest,net,role,wait,wait_ui,inspect,screenshot,enroll,mailbox_start,restore_operator,enroll_mailbox,send_ui,install,route
from messenger_product_journey import ui_public,record_binding,publication,close_route
from messenger_routed_project import send_reference

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--campaign',type=Path,required=True)
 p.add_argument('--mailbox',type=Path,required=True)
 p.add_argument('--delivery',type=Path,help='replace only personal ciphertext coordinators, preserving UI and native session owners')
 p.add_argument('--reuse-mailbox',action='store_true',help='the previous continuation already installed/recovered this exact Mailbox release')
 p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();campaign=a.campaign.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 packages={name:(campaign/(name+'.ltrel'),releases.inspect((campaign/(name+'.ltrel')).read_bytes()))for name in ('identity','owner','ui','delivery')}
 packages['mailbox']=(a.mailbox.resolve(),releases.inspect(a.mailbox.read_bytes()))
 if a.delivery:packages['delivery']=(a.delivery.resolve(),releases.inspect(a.delivery.read_bytes()))
 original=json.loads((campaign/'failure.json').read_text());checks=[];actors=[];began=time.monotonic();stage='attach preserved native actors'
 report=dict(schema=1,result='running',source=str(campaign),source_failure_sha256=hashlib.sha256((campaign/'failure.json').read_bytes()).hexdigest(),image_sha256=hashlib.sha256((campaign/'guest.bin').read_bytes()).hexdigest(),mailbox=packages['mailbox'][1],checks=checks,limits=original['limits'])
 def record(label,**extra):
  checks.append(dict(check=label,result='pass',**extra));(out/'progress.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',label,flush=True)
 def attach(name,personal=False):
  g=Guest(name,'qemu',campaign,campaign/'guest.bin',graphical=personal).attach(campaign);actors.append(g)
  g.out=out;g.client.journey_trace=out/(name+'.management-request.json')
  if personal:
   g.owner=messenger.endpoint(g.client,2,420);g.delivery=messenger.endpoint(g.client,4,464)
   g.ui=next(row[0]for row in identity.instances(g.client)if row[2]==799 and 0<row[1]<5)
  else:
   g.certificate=(campaign/(name+'.certificate')).read_bytes()if name!='stall'else None
   if g.certificate:g.pin=hashlib.sha256(g.certificate).digest()
  return g
 def fault(op,epoch=None):
  if op in ('pause','resume')and epoch is None:epoch=fault('status')['channel']['epoch']
  c=dict(op=op,slot=0)
  if epoch is not None:c['epoch']=epoch
  s=socket.socket(socket.AF_UNIX);s.settimeout(10);s.connect(str(campaign/'stall-fault.sock'));s.sendall(json.dumps(c).encode()+b'\n');raw=b''
  while b'\n'not in raw:raw+=s.recv(4096)
  s.close();value=json.loads(raw);assert value['ok'],value;return value
 def stall_rpc(g,serial,action,a=0,b=0,data=b''):
  net(g,39,h=serial,data=struct.pack('<8Q',441,action,a,b,0,0,0,1)+data)
  def collect():
   f,payload=net(g,40,h=serial,allow=(6,))
   return (struct.unpack_from('<8Q',payload),payload[64:])if f[0]==0 else None
  return wait(collect,240,'native third-client request')
 def received(g,text):
  f,_=role(g,2,420)
  for cursor in range(1,f[4]+1):
   read,body=role(g,2,429,h=cursor,allow=(3,))
   if read[0]==0 and body==text:return read
  return None
 try:
  mailbox=attach('mailbox');relays=[attach('relay'+str(i))for i in (1,2,3)]
  alice=attach('alice',True);bob=attach('bob',True);stalled=attach('stall')
  before={g.name:list(net(g,32)[0])for g in [mailbox,*relays,alice,bob,stalled]}
  stage='replace only native mailbox application and recover its own backing'
  prior=messenger.endpoint(mailbox.client,3,440)
  if a.reuse_mailbox:mailbox.mailbox=prior
  else:
   mailbox.client.request(26,struct.pack('<Q',prior))
   mailbox.identity_package=campaign/'identity.ltrel';restore_operator(mailbox,campaign);mailbox_start(mailbox,packages)
  assert all(net(g,32)[0][2]==3 for g in (alice,bob,stalled))
  record('same native Mailbox backing and three existing circuits remain running',mailbox_previously_recovered=a.reuse_mailbox,prior_instance=prior,current_instance=mailbox.mailbox,prior_router_states=before)
  certs=[g.certificate for g in relays]
  if a.delivery:
   for g in (alice,bob):
    close_route(g);g.client.request(26,struct.pack('<Q',g.delivery));g.delivery,did=install(g,packages,'delivery',1024)
    sid=bytes.fromhex(packages['owner'][1]['release_id']);uid=bytes.fromhex(packages['ui'][1]['release_id'])
    for op in (427,428,434):record_binding(g,2,g.owner,g.delivery,op,sid,did)
    for op in range(460,464):record_binding(g,4,g.delivery,g.ui,op,did,uid)
    record_binding(g,4,g.delivery,messenger.launcher(g.client),464,did)
    route(g,certs,mailbox);wait(lambda g=g:publication(g),240,g.name+' native prekey reconciliation')
   record('personal ciphertext coordinators replaced and reauthorized while retained native session owners, UI and operators remain running',delivery=packages['delivery'][1])
  # Only this personal client's route is refreshed after its adapter stall.
  stage='refresh third personal client and stall a new bounded upload'
  fault('resume');net(stalled,42);net(stalled,35)
  for i,cert in enumerate([*certs,mailbox.certificate]):enroll(stalled,i,cert)
  net(stalled,31);wait(lambda:net(stalled,32)[0][2]==3,300,'third personal route re-admission')
  net(stalled,38,h=3,a=17,b=messenger.launcher(stalled.client),cword=8388608,d=65536)
  wait(lambda:net(stalled,41)[0][2]==3,240,'third protected terminal re-admission')
  rid=hashlib.sha256(b'Campaign009 third stalled recipient').digest();deposit=hashlib.sha256(b'Campaign009 third public deposit fixture').digest();fetch=hashlib.sha256(b'Campaign009 third public fetch fixture').digest()
  # Enrollment is durable from the first segment; reauthorization is idempotent.
  enroll_mailbox(mailbox,rid+hashlib.sha256(deposit).digest()+hashlib.sha256(fetch).digest())
  payload=b'Bounded opaque native staging transfer.\n'*41
  f,_=stall_rpc(stalled,10,1,len(payload),1,data=rid+deposit+hashlib.sha256(b'Campaign009 third resumed stable upload').digest()+hashlib.sha256(payload).digest());assert f[0]==0,f
  handle=f[1];f,_=stall_rpc(stalled,11,2,handle,0,data=rid+deposit+payload[:512]);assert f[0]==0,f
  epoch=fault('status')['channel']['epoch'];fault('pause',epoch)
  net(stalled,39,h=12,data=struct.pack('<8Q',441,2,handle,512,0,0,0,1)+rid+deposit+payload[512:1024]);stalled_at=time.monotonic()
  assert all(net(g,41)[0][2]==3 for g in (alice,bob,stalled))
  record('third independent client re-admitted without operator reset; exact opaque epoch paused with incomplete native upload',epoch=epoch,handle=handle)
  stage='retry exact original GUI ciphertext while independent client remains stalled'
  original_text=b'native shared service text while another client stalls'
  old,_=inspect(alice);assert old[6]==1,old
  alice.device.press(65,delay=.15)
  accepted,_=wait_ui(alice,lambda f:f[6]==1 and f[4]in(19,27),'original exact-ciphertext retry durable acceptance')
  assert accepted[4]==19,(accepted,ui_public(alice,783)[0])
  wait(lambda:received(bob,original_text),600,'native recipient text after exact retry')
  reply,seconds=send_ui(bob,'native shared service reply while third client stalls')
  wait(lambda:received(alice,b'native shared service reply while third client stalls'),600,'native authenticated reply')
  record('actual graphical Messenger text exact retry and reply complete while third client remains stalled',original_serial=1,reply_serial=reply,reply_seconds=seconds)
  stage='actual routed existing Forge inspection while third client remains stalled'
  admission=next(c for c in original['checks']if 'actual existing signed project' in c['check'])
  root=bytes.fromhex(admission['root']);signed=admission['admission']
  import releases as release_tools
  fed=hashlib.sha256(release_tools.public_modulus(campaign/'federation.pub')).digest()
  text='LT-PROJECT1 '+root.hex()+' '+fed.hex()+' 1'
  _,serial,seconds,_=send_reference(alice,text)
  wait(lambda:received(bob,text.encode()),600,'encrypted exact project reference')
  roots_before=projects.roots(bob.client)
  wait_ui(bob,lambda f:f[4]==20,'actual received project reference displayed')
  bob.device.press(59,delay=.15)
  def verified():
   f,chosen=ui_public(bob,785)
   if f[1]!=6 or f[5]!=0:return None
   assert f[2]==2 and f[3]==0 and f[4]==signed['sequence']and chosen==root+fed,(f,chosen)
   return f
  fields=wait(verified,900,'actual routed existing Forge inspection')
  assert projects.roots(bob.client)==roots_before
  record('conversation F1 completes existing routed Forge signature and admission inspection during third client stall',displayed=list(fields),message_serial=serial,metadata_seconds=seconds,execution_approved=False)
  assert fault('status')['channel']['tx_paused']
  fault('resume',epoch);net(stalled,42);net(stalled,35);stalled.stop()
  assert all(net(g,41)[0][2]==3 for g in (alice,bob))
  record('third cancellation and disconnect leave unrelated authenticated clients usable',stalled_seconds=time.monotonic()-stalled_at)
  screenshot(alice,'native-shared-reply');screenshot(bob,'native-shared-forge')
  report.update(result='pass',elapsed_seconds=time.monotonic()-began);(out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n')
 except BaseException as error:
  report.update(result='failed-preserved-actors',stage=stage,error=repr(error),traceback=traceback.format_exc(),elapsed_seconds=time.monotonic()-began);(out/'failure.json').write_text(json.dumps(report,indent=2)+'\n');raise
 finally:
  for g in actors:
   if g.device:g.device.close()
   if g.client:g.client.close()
if __name__=='__main__':main()
