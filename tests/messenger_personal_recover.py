"""Restart selected encrypted actors through actual graphical normal recovery.

Only the disclosed test vault-unlock credential is derived on the host. Native
operational identities, sessions, attachment keys and ciphertext remain inside
their owners; public metadata and committed ciphertext hashes are observations.
"""
from __future__ import annotations
import argparse,concurrent.futures,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from messenger_journey import Guest,role,transfer_state,inspect,wait,unlock_ui,PUB
from messenger_product_journey import prepare_personal,lock_ui
import identity,messenger,releases

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--campaign',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
 p.add_argument('--ready-packages',required=True,type=Path);p.add_argument('--actor',action='append',choices=('alice','bob'),required=True)
 p.add_argument('--domain-only',action='store_true',help='actual F8/F9 lock/recover in the existing process; exact current package identities must already match');p.add_argument('--retryable-actor',choices=('alice','bob'));p.add_argument('--fixture-credentials',action='store_true',required=True)
 a=p.parse_args();campaign=a.campaign.resolve();out=a.output.resolve();out.mkdir(exist_ok=False)
 ready=json.loads(a.ready_packages.read_text());modulus=releases.public_modulus(PUB)
 packages={name:(Path(path),releases.inspect(Path(path).read_bytes(),modulus))for name,path in ready.items()}
 pin=hashlib.sha256((campaign/'mailbox.certificate').read_bytes()).digest()
 def recover(name):
  g=Guest(name,'qemu',campaign,campaign/'guest.bin',graphical=True,vault=campaign/(name+'.img')).attach(campaign)
  try:
   g.owner=messenger.endpoint(g.client,2,420);g.delivery=messenger.endpoint(g.client,4,464)
   g.ui=next(row[0]for row in identity.instances(g.client)if row[2]==799 and 0<row[1]<5)
   before=role(g,2,420)[0];_,invitation=role(g,2,434,a=27)
   slots=[role(g,2,434,h=i,a=21,allow=(3,))[0]for i in range(2)]
   live=[row for row in slots if row[0]==0 and row[2]==1]
   latest=live[-1]if name==a.retryable_actor and live else None
   cached=None
   if latest is not None:_,cached=role(g,2,434,h=latest[1],a=18,b=13)
   credential=hashlib.sha256(('Campaign008 disclosed '+name.capitalize()+' vault-unlock fixture').encode()).digest()
   if a.domain_only:
    current=json.loads((campaign/'actor-packages.json').read_text())[name]
    assert all(releases.inspect(Path(current[k]).read_bytes())['release_id']==packages[k][1]['release_id']for k in('owner','ui','delivery'))
    lock_ui(g);unlock_ui(g,credential,1);_,restored=role(g,2,434,a=27)
   else:
    g.stop();g.start();restored=prepare_personal(g,packages,pin,credential,recover=True)
   assert restored[32:64]==invitation[32:64]and restored[224:256]==invitation[224:256]
   after=role(g,2,420)[0];newslots=[role(g,2,434,h=i,a=21,allow=(3,))[0]for i in range(2)]
   assert slots==newslots and before[2:5]==after[2:5]
   result=dict(actor=name,result='pass',before=list(before),after=list(after),local_slots=[list(row)for row in slots],packages={k:packages[k][1]for k in('owner','ui','delivery')})
   if cached is not None:
    _,again=role(g,2,434,h=latest[1],a=18,b=13);assert again==cached
    state=wait(lambda:(f if f[1]==10 else None)if(f:=transfer_state(g))else None,120,'actual GUI restores the exact partial transfer as retryable')
    result.update(latest_handle=latest[1],cached_chunk13_sha256=hashlib.sha256(cached).hexdigest(),actual_gui_partial=list(state),actual_ui=list(inspect(g)[0]))
   (out/(name+'.json')).write_text(json.dumps(result,indent=2)+'\n');print('PASS protected graphical recovery',name,result.get('actual_gui_partial'),flush=True);return result
  finally:
   if g.device:g.device.close()
   if g.client:g.client.close()
 with concurrent.futures.ThreadPoolExecutor(max_workers=len(set(a.actor)))as pool:results=list(pool.map(recover,sorted(set(a.actor))))
 mapping=json.loads((campaign/'actor-packages.json').read_text())
 for name in set(a.actor):mapping[name]={k:str(packages[k][0].resolve())for k in('owner','ui','delivery')}
 (campaign/'actor-packages.json').write_text(json.dumps(mapping,indent=2)+'\n')
 report=dict(schema=1,result='pass',command=sys.argv,helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),image_sha256=hashlib.sha256((campaign/'guest.bin').read_bytes()).hexdigest(),actors=results,scope=('Actual graphical F8 lock and F9 normal domain2 recovery in the same native processes preserve current identities, contacts, inboxes and exact ciphertext.'if a.domain_only else'Actual whole-guest restart and graphical normal domain2 recovery preserve current identities, contacts, inboxes and exact ciphertext.')+' Local attachment publication counts do not establish remote acceptance.')
 (out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
