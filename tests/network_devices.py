"""Actual QEMU and assembly-console byte I/O; no graph/network-policy adapter."""
import os,socket,subprocess,sys,time,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import driver,live

def build():
 for name in ['Primitives','DevicePrimitives','Devices']:
  driver.lean(['-o','Guest/'+name+'.olean','Guest/'+name+'.lean'])
 driver.lean(['-o','tests/fixtures/TransportProbe.olean','tests/fixtures/TransportProbe.lean'])
 (ROOT/'build/transport-boot.S').write_text('.option norvc\n.section .text.boot\n.globl _start\n_start:\n li sp,0x800ff000\n li a0,0\n call lt_Guest_transportMain\n1: j 1b\n')
 driver.compile_guest('tests.fixtures.TransportProbe',['Guest.transportMain'],'transport-probe','build/transport-boot.S','runtime/kernel.ld')

def check(backend):
 a,b=socket.socketpair();a.settimeout(45)
 args=live.args_for(backend,ROOT/'build/transport-probe.bin',network_fd=b.fileno())
 proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(b.fileno(),))
 b.close()
 payload=bytes((i*173+47)%256 for i in range(4097))
 try:
  assert proc.stdout.read(1)==b'R',backend
  for i in range(0,len(payload),37):a.sendall(payload[i:i+37])
  result=bytearray()
  while len(result)<len(payload):
   chunk=a.recv(len(payload)-len(result))
   if not chunk:raise AssertionError('stream closed early')
   result.extend(chunk)
  out,err=proc.communicate(timeout=45)
  if result!=payload or proc.returncode!=0 or b'ON' not in out:
   raise AssertionError((backend,proc.returncode,len(result),out,err))
  return {'backend':backend,'bytes':len(result),'sha256':hashlib.sha256(result).hexdigest(),'console':out.decode(),'status':'passed'}
 finally:
  a.close()
  if proc.poll() is None:proc.kill();proc.wait()

if __name__=='__main__':
 build()
 print(json.dumps([check(backend) for backend in sys.argv[1:] or ['qemu','x86_64','aarch64']],indent=2))
