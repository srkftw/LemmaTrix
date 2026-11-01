"""Restart an existing native operator against its opaque protected backing.

Only the independently generated guest credentials are recovered by native
Identity408/Network44. The host retains no operational private key. This helper
restarts Mailbox, re-admits its exact service and finite receipt grants and
checks every published row; unrelated ephemeral Registry admission is not
restored or claimed by this Mailbox recovery operation.
"""
from __future__ import annotations
import argparse,hashlib,json,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from messenger_journey import Guest,role,net,mailbox_start,PUB
import releases

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--campaign',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--ready-packages',required=True,type=Path);a=p.parse_args()
 campaign=a.campaign.resolve();out=a.output.resolve();out.mkdir(exist_ok=False);ready=json.loads(a.ready_packages.read_text())
 packages={name:(Path(path),releases.inspect(Path(path).read_bytes(),releases.public_modulus(PUB)))for name,path in ready.items()}
 configuration=json.loads((campaign/'mailbox.public-configuration.json').read_text());image=campaign/'guest.bin'
 g=Guest('mailbox',configuration['backend'],campaign,image,store=campaign/'mailbox.img',network_fault_control=campaign/'mailbox-fault.sock').attach(campaign)
 began=time.monotonic();report=dict(schema=1,result='running',command=sys.argv,helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),packages={name:info['release_id']for name,(_,info)in packages.items()})
 try:
  before=[list(role(g,3,440,h=2,a=i)[0])for i in range(16)];certificate=(campaign/'mailbox.certificate').read_bytes();profile=(campaign/'mailbox.receipt-profile').read_bytes()
  old_pid=g.process.pid;g.stop();g.start();mailbox_start(g,packages)
  assert g.certificate==certificate and g.pin.hex()==configuration['pin'] and g.receipt_certificate==profile[:352]
  after=[list(role(g,3,440,h=2,a=i)[0])for i in range(16)];assert before==after,('published rows changed during operator recovery',before,after)
  assert (campaign/'mailbox.receipt-profile').read_bytes()==profile
  net(g,30,h=0)
  report.update(result='pass',prior_pid=old_pid,current_pid=g.process.pid,backend=g.backend,certificate_sha256=hashlib.sha256(certificate).hexdigest(),receipt_profile_sha256=hashlib.sha256(profile).hexdigest(),before=before,after=after,elapsed_seconds=time.monotonic()-began,private_key_exported=False,scope='Native whole-Mailbox-guest restart, sealed node/receipt recovery, exact admission and finite current receipt grants. Published ciphertext/receipt rows are unchanged. Ephemeral Registry configuration is outside this restart.')
  (out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 except BaseException as error:
  report.update(result='failed-preserved-actors',error=repr(error));(out/'failure.json').write_text(json.dumps(report,indent=2)+'\n');raise
 finally:
  if g.device:g.device.close()
  if g.client:g.client.close()
if __name__=='__main__':main()
