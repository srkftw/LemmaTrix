"""Finish the connected native journey using preserved guests and real input.

The initial graphical text, offline upload, mailbox restart, personal recovery,
and mixed backend route have already executed. This continuation owns the
public portals exclusively and never edits protocol state or opaque backing.
"""
from __future__ import annotations
import argparse,hashlib,json,struct,subprocess,time,traceback
from pathlib import Path
from messenger_journey import *
from messenger_product_journey import ui_public,lock_ui,close_route,publication

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--campaign',type=Path,required=True);p.add_argument('--resume-after-import',action='store_true');a=p.parse_args()
 out=a.campaign.resolve();actors=[];started=time.monotonic();stage='attach existing native actors'
 report=json.loads((out/'progress.json').read_text());report['result']='running';checks=report['checks']
 snapshot=json.loads((out/'selected-attachment.json').read_text());head=snapshot['root']
 def record(label,**values):
  checks.append(dict(check=label,result='pass',**values));(out/'progress.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',label,flush=True)
 def attach(name,personal=False):
  config=out/(name+'.public-configuration.json');backend=json.loads(config.read_text())['backend'] if config.exists() else 'qemu'
  g=Guest(name,backend,out,out/'guest.bin',graphical=personal,vault=out/(name+'.img') if personal else None,store=None if personal else out/(name+'.img')).attach(out);actors.append(g)
  if personal:
   g.owner=messenger.endpoint(g.client,2,420);g.delivery=messenger.endpoint(g.client,4,464)
   g.ui=next(row[0] for row in identity.instances(g.client) if row[2]==799 and 0<row[1]<5)
  else:
   g.certificate=(out/(name+'.certificate')).read_bytes();_,native=net(g,25,h=4)
   assert native[:480]==g.certificate and native[480:]==hashlib.sha256(g.certificate).digest();g.pin=native[480:]
  return g
 try:
  mailbox=attach('mailbox');mailbox.mailbox=messenger.endpoint(mailbox.client,3,441)
  relays=[attach('relay'+str(i)) for i in (1,2,3)];certs=[g.certificate for g in relays]
  alice=attach('alice',True);bob=attach('bob',True)
  report['actor_backends']={g.name:g.backend for g in actors}
  ak=hashlib.sha256(b'Campaign008 disclosed Alice vault-unlock fixture').digest();bk=hashlib.sha256(b'Campaign008 disclosed Bob vault-unlock fixture').digest()
  if not a.resume_after_import:
   stage='existing native pointer attachment import'
   f,text=role(bob,2,429,h=1);assert text==b'native offline message through three relays'
   current=transfer_state(bob)
   if current[1]<20:
    # F12 is a compositor-wide package shortcut. The app's displayed footer
    # has an existing pointer import target; use that real native gesture.
    bob.device.press(1,delay=.15);bob.device.click(400,385,delay=.15)
   last=[None];retrieval_started=time.monotonic()
   def imported():
    state=transfer_state(bob)
    if state!=last[0]:print('bob explicit import',state,flush=True);last[0]=state
    if state[1]==9:raise RuntimeError(('native import failure',state,ui_public(bob,783)[0]))
    return state if state[1]==24 else None
   received=wait(imported,1800,'actual pointer-authorized native project import')
   message,manifest=role(bob,2,429,h=2)
   metadata,commitments=role(bob,2,434,h=message[5],a=5)
   assert metadata[2]==2 and metadata[3]==snapshot['bundle_bytes'] and len(commitments)==64
   actual_head=commitments[32:64].hex();assert actual_head==head
   # Native Project14 precedes UI24 only after the parser's expectedRoot check
   # and Objects canonical closure/hash validation. The root is deliberately
   # delegated to Compositor, not to this host-management Launcher principal.
   screenshot(bob,'final-imported-project')
   record('actual graphical pointer fetches decrypts authenticates ordered attachment chunks and explicitly commits useful Objects project before deletion',native_transfer=list(received),canonical_root=actual_head,native_stream_integrity=True,verification_scope='live expected-root match and native canonical Objects commit; no host source-byte export or claimed independent byte oracle',isolated_retrieval_seconds=None)
   bob.device.press(87,delay=.15);wait(lambda:transfer_state(bob)[1]==1,120,'received project trusted picker inspection')
   screenshot(bob,'received-project-trusted-picker');bob.device.press(1,delay=.15)
   wait(lambda:transfer_state(bob)[1]==0,120,'trusted picker cancellation without forwarding received project')
  else:
   assert any(check.get('native_stream_integrity') for check in checks),'native completed import evidence required'
  stage='explicit graphical lock and opaque older history backup'
  if role(bob,2,420)[0][1]!=0:lock_ui(bob)
  backup=out/'bob-history-backup.img'
  if backup.exists():
   assert backup.stat().st_size==0,'refuse replacing an existing opaque backup'
   backup.unlink()
  # An attach-only host driver has not executed Guest.start's backing-sized
  # adapter limit adjustment. Bound this opaque copy to the selected backing.
  backing_bytes=bob.vault.stat().st_size;soft,hard=resource.getrlimit(resource.RLIMIT_FSIZE)
  if soft!=resource.RLIM_INFINITY and soft<backing_bytes:
   assert hard==resource.RLIM_INFINITY or hard>=backing_bytes
   resource.setrlimit(resource.RLIMIT_FSIZE,(backing_bytes,hard))
  subprocess.run(['cp','--reflink=auto','--sparse=always',str(bob.vault),str(backup)],check=True)
  assert backup.stat().st_size==backing_bytes
  record('explicit graphical lock permits quiescent opaque older history backup without editing backing',backup=str(backup),backing_edited=False)
  unlock_ui(bob,bk,1);bob.device.press(1,delay=.15);close_route(bob);reset_operators(relays,mailbox);route(bob,certs,mailbox)
  stage='actual graphical routed reply'
  message,seconds=send_ui(bob,'native routed reply after recovery')
  record('recovered recipient composes graphical reply and verifies signed durable routed acceptance',message=message,acceptance_seconds=seconds)
  screenshot(bob,'final-reply-stored')
  lock_ui(bob);close_route(bob);reset_operators(relays,mailbox)
  unlock_ui(alice,ak,1);alice.device.press(1,delay=.15);setup=route(alice,certs,mailbox)
  wait(lambda:role(alice,2,420)[0][4]>=1,600,'original sender authenticated reply')
  f,reply=role(alice,2,429,h=1);assert reply==b'native routed reply after recovery'
  wait_ui(alice,lambda f:f[4]==20,'actual routed graphical reply presentation');screenshot(alice,'final-routed-reply')
  record('original sender explicitly recovers and decrypts actual routed reply',inbox_serial=f[1],route_setup_seconds=setup)
  report.update(result='passed-connected-product',finish_seconds=time.monotonic()-started,incomplete_acceptance=['connected failure matrix and exact retry: F helper queued','conversation Forge handoff: G helper queued','supported history import and no-vault controls: H helper queued'])
  (out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n')
 except BaseException as error:
  report.update(result='failed-preserved-actors',stage=stage,error=repr(error),traceback=traceback.format_exc(),finish_seconds=time.monotonic()-started)
  failure=out/'finish-failure.json'
  if failure.exists():(out/('finish-failure-'+str(time.time_ns())+'.json')).write_bytes(failure.read_bytes())
  failure.write_text(json.dumps(report,indent=2)+'\n');raise
 finally:
  for g in actors:
   if g.device:g.device.close()
   if g.client:g.client.close()
if __name__=='__main__':main()
