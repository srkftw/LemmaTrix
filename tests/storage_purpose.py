"""Purpose-bound block devices, independent disks and wrong-purpose refusal."""
import hashlib,json,socket,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'));import driver,live

def build():
 for name in ['Primitives','DevicePrimitives','Devices']:driver.lean(['-o','Guest/'+name+'.olean','Guest/'+name+'.lean'])
 driver.lean(['-o','tests/fixtures/StoragePurposeProbe.olean','tests/fixtures/StoragePurposeProbe.lean'])
 (ROOT/'build/storage-purpose-boot.S').write_text('.option norvc\n.section .text.boot\n.globl _start\n_start:\n li sp,0x800ff000\n li a0,0\n call lt_Guest_storagePurposeMain\n1: j 1b\n')
 driver.compile_guest('tests.fixtures.StoragePurposeProbe',['Guest.storagePurposeMain'],'storage-purpose-probe','build/storage-purpose-boot.S','runtime/kernel.ld')

def check(backend,wrong=False):
 with tempfile.TemporaryDirectory() as d:
  vault=Path(d)/'objects.img';server=Path(d)/'server.img';vault.write_bytes(bytes(512*512));server.write_bytes(bytes(1024*512))
  a,b=socket.socketpair()
  args=live.args_for(backend,ROOT/'build/storage-purpose-probe.bin',vault=vault,server_store=server,network_fd=b.fileno())
  if wrong:
   assert backend=='qemu'
   args=[x.replace('serial=lt-server-v1','serial=unknown-store') for x in args]
  p=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=45,pass_fds=(b.fileno(),));a.close();b.close()
  expected=bytes((i*173+47)%256 for i in range(512))
  assert vault.read_bytes()==bytes(512*512),(backend,'objects changed')
  assert server.read_bytes()[1536:2048]==(bytes(512) if wrong else expected),(backend,p.returncode,p.stdout,p.stderr)
  assert (p.stdout==b'' if wrong else p.returncode==0 and p.stdout==b'S'),(backend,p.returncode,p.stdout,p.stderr)
  return {'backend':backend,'wrong_purpose':wrong,'status':'passed','objects_sha256':hashlib.sha256(vault.read_bytes()).hexdigest()}
if __name__=='__main__':
 build();print(json.dumps([check(x) for x in ['qemu','x86_64','aarch64']]+[check('qemu',True)],indent=2))
