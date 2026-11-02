"""Execute shipped native release-claim predicates on generated RV64 code."""
import hashlib,json,struct,sys
from pathlib import Path
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'tools'),str(Path(__file__).resolve().parent)]
import driver,live_build
from structured_runtime import BOOT
ROOT=driver.ROOT;B=driver.BUILD/'release-claims'

def stores(pointer,data):
 return ''.join(f'  let t := Guest.store64 {pointer+i} {int.from_bytes(data[i:i+8].ljust(8,bytes(1)),"little")} t\n' for i in range(0,len(data),8))
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def main():
 B.mkdir(parents=True,exist_ok=True);header=bytearray(512);name=b'project-notes';logical=bytes(range(32));publisher=bytes(range(32,64));publication=bytes(range(64,96))
 for off,value in {64:895,72:1,80:2,88:3,384:1,392:7,400:2,424:len(name)}.items():struct.pack_into('<Q',header,off,value)
 header[96:128]=publisher;header[128:160]=publication;header[432:432+len(name)]=name
 lock=dict(schema=1,facet='NativeApplication',profile=2,machine='LT-Dev-v2',sdk=dict(version='0.1.0',content_id='01'*32),dependencies=[],recipe='lemmatrix-lean-rv64-structured-2',module='Main',entry='Main.main',toolchain=dict(lean='4.34.1',llvm='20.1.8',isa='rv64im',abi='lp64'))
 manifest=dict(schema=4,rights=895,resource_profile=2,facet='NativeApplication',project=name.decode(),version='1.2.3',publisher_generation=7,identity_mapping=dict(scheme=4,logical_project_id=logical.hex(),publisher_key_id=publisher.hex(),publication_id=publication.hex()),machine='LT-Dev-v2',runtime='LT-structured-v3',parent=None,sdk=lock['sdk'],dependencies=[],recipe={k:lock[k]for k in ('module','entry','recipe','toolchain')})
 encoded=canonical(manifest);locked=canonical(lock)+b'\n';cases=[('actual header and exact locked claims',encoded,True)]
 for field,value in [('rights',1024),('resource_profile',1),('publisher_generation',8),('facet','DevelopmentArtifact'),('project','another-project'),('version','1.2.4'),('machine','Linux'),('runtime','host-runtime'),('parent','00'*32)]:cases.append((field+' substitution',{**manifest,field:value},False))
 cases.append(('SDK substitution',{**manifest,'sdk':{**manifest['sdk'],'content_id':'02'*32}},False))
 cases.append(('dependency substitution',{**manifest,'dependencies':[{'rights':895}]},False))
 cases.append(('nested spoof does not select a different claim',{**manifest,'rights':0,'extra':{'rights':895}},False))
 cases.append(('strings containing fake JSON stay strings',{**manifest,'extra':'{ "rights":0, "sdk":null }'},True))
 cases.append(('logical identity substitution',{**manifest,'identity_mapping':{**manifest['identity_mapping'],'logical_project_id':'ff'*32}},False))
 cases.append(('entry recipe substitution',{**manifest,'recipe':{**manifest['recipe'],'entry':'Other.main'}},False))
 cases.append(('duplicate top-level key',encoded.replace(b'"rights":895',b'"rights":895,"rights":895'),False))
 cases.append(('escaped key spoof',encoded.replace(b'"rights":895',b'"\\u0072ights":895'),False))
 cases.append(('deep array bound',{**manifest,'extra':[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]},False))
 cases.append(('unpaired surrogate',encoded[:-1]+b',"z":"\\ud800"}',False))
 cases.append(('invalid UTF-8',encoded[:-1]+b',"z":"\xc0\x80"}',False))
 source='import Guest.ReleaseClaims\nset_option maxRecDepth 8192\nset_option maxHeartbeats 0\nnamespace ReleaseClaimsCheck\ndef check (initial : UInt64) : UInt64 :=\n  let t := initial\n'+stores(0x410000,bytes(header))+stores(0x410400,logical)+stores(0x414000,locked)
 for index,(label,data,accepted) in enumerate(cases):
  data=canonical(data)if isinstance(data,dict)else data
  source+=stores(0x411000,data)
  source+=f'  if Guest.ReleaseClaims.check 0x410000 0x411000 {len(data)} 0x414000 {len(locked)} 0x410400 t != {str(accepted).lower()} then {index+1} else\n'
 source+='  0\nend ReleaseClaimsCheck\n';path=B/'ReleaseClaimsCheck.lean';path.write_text(source)
 live_build.compile_module('Guest.ReleaseClaims');driver.lean(['-o',path.with_suffix('.olean'),path])
 # Compiler lookup is confined to the test directory and already compiled native
 # predicate dependencies. This test creates no signing approval or release.
 assembly=B/'check.S';env=dict(__import__('os').environ,LEAN_PATH=str(B)+':'+str(ROOT),PATH=str(Path(driver.tool('lean')).parent)+':'+__import__('os').environ['PATH'])
 driver.run([driver.tool('lean'),'-Dcompiler.extract_closed=false','--run','Compiler/Main.lean','ReleaseClaimsCheck',assembly,'ReleaseClaimsCheck.check'],env=env)
 boot=B/'boot.S';boot.write_text(BOOT.replace('lt_Examples_StructuredConsumer_check','lt_ReleaseClaimsCheck_check'));objects=[]
 for i,part in enumerate([assembly,boot,ROOT/'runtime/primitives.S']):
  obj=B/f'{i}.o';driver.asm(part,obj);objects.append(obj)
 elf=B/'check.elf';binary=B/'check.bin';driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf]);driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary])
 import subprocess
 result=subprocess.run([driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',str(binary)],capture_output=True,timeout=45)
 if result.returncode:raise AssertionError(f'native predicate case failed exit{result.returncode}: '+result.stderr.decode())
 report=dict(schema=1,status='pass',environment='QEMU RV64; actual compiled Guest.ReleaseClaims predicates',binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),checks=[x[0]for x in cases],assumptions=['caller passes actual authorized frozen source lock bytes and logical project identity','release signature/header and actual source/artifact/evidence commitments checked separately'])
 (B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
