"""Execute Project Vault facet guards on the real native-signed source helper.

This is a predicate test with public release bytes. It imports no accepted graph,
secrets or signing approval into an acceptance guest.
"""
import hashlib,json,os,struct,subprocess,sys
from pathlib import Path
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'tools'),str(Path(__file__).resolve().parent)]
import driver,live_build,projects,sdk
from structured_runtime import BOOT
ROOT=driver.ROOT;B=driver.BUILD/'project-vault-facets'
def stores(pointer,data):
 return ''.join(f'  let t := Guest.store64 {pointer+i} {int.from_bytes(data[i:i+8].ljust(8,bytes(1)),"little")} t\n'for i in range(0,len(data),8)if any(data[i:i+8]))
def main():
 B.mkdir(parents=True,exist_ok=True);project=ROOT/'examples/project-notes';lock=json.loads((project/'lemma.lock.json').read_bytes());release=lock['dependencies'][0]['release_id'];document=json.loads((project/'deps'/(release+'.json')).read_bytes());info,release_node,_,records=sdk.dependency_archive(document)
 table=bytearray(14368);struct.pack_into('<4Q',table,0,0x32564a4f5250544c,2,len(records),0);selected=None
 for i,record in enumerate(records):
  at=2080+i*192;payload=record['payload'];struct.pack_into('<2Q',table,at,record['kind'],len(payload));table[at+16:at+48]=bytes.fromhex(record['id']);table[at+48:at+80]=bytes.fromhex(record.get('parent','00'*32));table[at+80:at+112]=hashlib.sha256(payload).digest();struct.pack_into('<Q',table,at+128,1)
  if record['id']==release_node:selected=(i,payload)
 assert selected is not None
 index,payload=selected;pointer=0x680000+2080+index*192;header=0x700000+160+64
 cases=[('actual v4 source-only helper with no dummy Build',None,None,True),('executable facet cannot use source-only layout',header+384,1,False),('unknown release version',header+8,5,False),('source-only release cannot request rights',header+64,895,False),('RSA prefix cannot reinterpret Ed25519 source facet',0x700000+160+16,768,False),('source-only release must select SourceManifest',0x700000+32,10,False)]
 source='import Guest.ProjectVault\nset_option maxRecDepth 32768\nset_option maxHeartbeats 0\nnamespace VaultFacetCheck\ndef check (t : UInt64) : UInt64 :=\n  let t := Guest.LiveSDK.zero 0x680000 2048 t\n'+stores(0x680000,table)
 for i,(label,address,value,accepted)in enumerate(cases):
  source+='  let t := Guest.LiveSDK.zero 0x700000 8192 t\n'+stores(0x700000,payload)
  if address is not None:source+=f'  let t := Guest.store64 {address} {value} t\n'
  source+=f'  if Guest.ProjectVault.validRecordAt 0x680000 {len(records)} {pointer} t != {str(accepted).lower()} then {i+1} else\n'
 source+='  0\nend VaultFacetCheck\n';path=B/'VaultFacetCheck.lean';path.write_text(source);live_build.compile_module('Guest.ProjectVault');driver.lean(['-o',path.with_suffix('.olean'),path]);assembly=B/'check.S';env=dict(os.environ,LEAN_PATH=str(B)+':'+str(ROOT),PATH=str(Path(driver.tool('lean')).parent)+':'+os.environ['PATH']);driver.run([driver.tool('lean'),'--run','Compiler/Main.lean','VaultFacetCheck',assembly,'VaultFacetCheck.check'],env=env)
 # These service-private buffers occupy VA6–8MiB; map that range explicitly.
 boot=B/'boot.S';boot.write_text(BOOT.replace('lt_Examples_StructuredConsumer_check','lt_VaultFacetCheck_check').replace(' sd t1,16(t0)\n li t1,0x40000cf',' sd t1,16(t0)\n li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf'));objects=[]
 for i,part in enumerate([assembly,boot,ROOT/'runtime/primitives.S']):obj=B/f'{i}.o';driver.asm(part,obj);objects.append(obj)
 elf=B/'check.elf';binary=B/'check.bin';driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf]);driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary]);result=subprocess.run([driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',binary],capture_output=True,timeout=45)
 if result.returncode:raise AssertionError('native vault facet guard failed: '+result.stderr.decode())
 report=dict(schema=1,status='pass',environment='QEMU RV64 compiled shipped storage predicates',dependency_release_id=info['release_id'],release_node=release_node,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),checks=[x[0]for x in cases],assumptions=['AEAD and record hash verification precede these guards','normal native ImportJobs validates recovered signatures, commitments and graph authority'])
 (B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
