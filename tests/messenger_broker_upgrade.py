"""Supported native broker upgrade and current-index retry diagnostics.

The host signs only the disclosed package bootstrap. It supplies no operational
private keys, protocol state, mailbox database edits or prepared delivery result.
Run after the prior controller releases all public actor portals.
Replacing a broker loses its assembled batch. A current-index F7 may therefore
return a different bounded error than the original full batch; this command
does not classify it as the original failure or claim delivery success.
"""
from __future__ import annotations
import argparse,hashlib,json,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from messenger_journey import Guest,role,net,reset_operators,route,wait,inspect,transfer_state,SIGN,PUB
from messenger_product_journey import record_binding,publication
import identity,messenger,releases

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--campaign',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
 p.add_argument('--actor',default='alice',choices=('alice','bob'));p.add_argument('--binary',required=True,type=Path)
 p.add_argument('--version',required=True);p.add_argument('--retry-attachment',action='store_true')
 a=p.parse_args();campaign=a.campaign.resolve();out=a.output.resolve();out.mkdir(exist_ok=False)
 mapping=json.loads((campaign/'actor-packages.json').read_text());selected=mapping[a.actor]
 old={k:releases.inspect(Path(v).read_bytes(),releases.public_modulus(PUB))for k,v in selected.items()}
 assert tuple(map(int,a.version.split('.')))>tuple(map(int,old['delivery']['version'].split('.')))
 raw,manifest=releases.make(a.binary,old['delivery']['project'],a.version,1024,SIGN,parent=old['delivery']['release_id'],profile=2)
 package=out/('delivery-'+a.version+'.ltrel');package.write_bytes(raw)
 (out/'delivery.manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 info=releases.inspect(raw,releases.public_modulus(PUB),manifest);actors=[];began=time.monotonic()
 def attach(name,personal=False):
  configuration=campaign/(name+'.public-configuration.json')
  backend=json.loads(configuration.read_text())['backend']if configuration.exists()else'qemu'
  g=Guest(name,backend,campaign,campaign/'guest.bin',graphical=personal,vault=campaign/(name+'.img')if personal else None,store=None if personal else campaign/(name+'.img')).attach(campaign);actors.append(g)
  if personal:
   g.owner=messenger.endpoint(g.client,2,420);g.delivery=messenger.endpoint(g.client,4,464)
   g.ui=next(r[0]for r in identity.instances(g.client)if r[2]==799 and 0<r[1]<5)
  else:
   g.certificate=(campaign/(name+'.certificate')).read_bytes();f,data=net(g,25,h=4);assert f[0]==0 and data[:480]==g.certificate;g.pin=data[480:]
  return g
 report=dict(schema=1,result='running',actor=a.actor,prior=old['delivery'],current=info,command=sys.argv,image_sha256=hashlib.sha256((campaign/'guest.bin').read_bytes()).hexdigest())
 try:
  g=attach(a.actor,True);before=role(g,2,420)[0]
  slots=[role(g,2,434,h=i,a=21,allow=(3,))[0]for i in range(2)]
  live=[r for r in slots if r[0]==0 and r[2]==1];latest=live[-1]if live else None
  cached=None
  if latest is not None:_,cached=role(g,2,434,h=latest[1],a=18,b=13)
  old_instance=g.delivery;g.client.request(26,struct.pack('<Q',old_instance))
  g.delivery,did=messenger.install(g.client,package,PUB,1024)
  sid=bytes.fromhex(old['owner']['release_id']);uid=bytes.fromhex(old['ui']['release_id'])
  for op in(427,428,434):record_binding(g,2,g.owner,g.delivery,op,sid,did)
  for op in range(460,464):record_binding(g,4,g.delivery,g.ui,op,did,uid)
  record_binding(g,4,g.delivery,messenger.launcher(g.client),464,did)
  mapping[a.actor]['delivery']=str(package);(campaign/'actor-packages.json').write_text(json.dumps(mapping,indent=2)+'\n')
  assert role(g,2,420)[0]==before
  mailbox=attach('mailbox');relays=[attach('relay'+str(i))for i in(1,2,3)]
  net(g,42);net(g,35);reset_operators(relays,mailbox)
  setup=route(g,[r.certificate for r in relays],mailbox)
  wait(lambda:publication(g),240,'current native prekey publication after exact broker upgrade')
  initial=role(g,4,464,a=3)[0]
  if a.retry_attachment:
   assert latest is not None and transfer_state(g)[1]==9
   g.device.press(65,delay=.1)
   def failed():
    state=role(g,4,464,a=3)[0]
    return state if (state[1]==7 or state[3]==7)and transfer_state(g)[1]==9 else None
   final=wait(failed,180,'actual graphical exact retry returns a structured native failure')
  else:final=role(g,4,464,a=3)[0]
  after=role(g,2,420)[0];newslots=[role(g,2,434,h=i,a=21,allow=(3,))[0]for i in range(2)]
  assert before==after and slots==newslots
  if cached is not None:
   _,again=role(g,2,434,h=latest[1],a=18,b=13);assert again==cached
  report.update(result='pass',prior_instance=old_instance,current_instance=g.delivery,owner_instance=g.owner,ui_instance=g.ui,exact_bindings_recreated=8,route_setup_seconds=setup,mailbox_pin=mailbox.pin.hex(),native_initial=list(initial),native_final=list(final),owner_before=list(before),owner_after=list(after),local_slots=[list(r)for r in slots],cached_chunk13_sha256=hashlib.sha256(cached).hexdigest()if cached else None,graphical_state=list(inspect(g)[0]),native_transfer=list(transfer_state(g)),elapsed_seconds=time.monotonic()-began,scope='Normal native higher-version/parent package admission and exact eight generation bindings, unchanged key owner/UI arenas, native three-hop route and manual F7. A structured failure is an observed result, not delivery success.')
  (out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 except BaseException as error:
  report.update(result='failed-preserved-actors',error=repr(error));(out/'failure.json').write_text(json.dumps(report,indent=2)+'\n');raise
 finally:
  for g in actors:
   if g.device:g.device.close()
   if g.client:g.client.close()
if __name__=='__main__':main()
