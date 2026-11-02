"""Run the shipped project declaration authorization predicates on RV64."""
import sys,json,struct,hashlib,subprocess,os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import driver,live_build
from structured_runtime import BOOT
from release_claims import stores
B=driver.BUILD/'campaign010-project-declaration';B.mkdir(exist_ok=True)
h=bytearray(512);struct.pack_into('<Q',h,64,895);struct.pack_into('<Q',h,384,1);struct.pack_into('<Q',h,400,2)
m={'project':'project-notes','facet':'NativeApplication','license':'MIT','provenance':{'declaration':'I authorize this source.'},'machine':'LT-Dev-v2','recipe':{'module':'Main','entry':'Main.main'}}
p={'schema':1,'name':'project-notes','facet':'NativeApplication','license':'MIT','distribution_authority':'I authorize this source.','rights':895,'profile':2,'machine':'LT-Dev-v2','module':'Main','entry':'Main.main','extra':{'b':'two','a':[1,2]}}
manifest=json.dumps(m,sort_keys=True,separators=(',',':')).encode()
cases=[('editable unordered pretty declaration',json.dumps(p,indent=2).encode(),True),('declaration rights escalation',json.dumps({**p,'rights':8191}).encode(),False),('declaration license substitution',json.dumps({**p,'license':'NOASSERTION'}).encode(),False),('distribution authority substitution',json.dumps({**p,'distribution_authority':'Someone else authorized it.'}).encode(),False),('duplicate rights',json.dumps(p).encode().replace(b'"rights": 895',b'"rights": 895,"rights":895'),False),('escaped authority key',json.dumps(p).encode().replace(b'"rights"',b'"ri\\u0067hts"'),False),('nested rights cannot supply authority',json.dumps({k:v for k,v in p.items()if k!='rights'}).encode(),False),('string whitespace preserved',json.dumps({**p,'name':'project notes'}).encode(),False)]
s='import Guest.ProjectDeclaration\nset_option maxRecDepth 8192\nset_option maxHeartbeats 0\nnamespace DeclarationCheck\ndef check (t : UInt64) : UInt64 :=\n'+stores(0x410000,h)+stores(0x411000,manifest)
for i,(name,data,ok)in enumerate(cases):
 s+=stores(0x412000,data)+f'  let n := Guest.ProjectDeclaration.normalize 0x412000 {0x412000+len(data)} 0x414000 0 0 0 t\n  if n == Guest.LiveSDK.error || Guest.ProjectDeclaration.consistent 0x410000 0x411000 {len(manifest)} 0x414000 n n != {str(ok).lower()} then {i+1} else\n'
s+='  0\nend DeclarationCheck\n';p=B/'DeclarationCheck.lean';p.write_text(s)
live_build.compile_module('Guest.ProjectDeclaration');driver.lean(['-o',p.with_suffix('.olean'),p])
env=dict(os.environ,LEAN_PATH=str(B)+':'+str(driver.ROOT),PATH=str(Path(driver.tool('lean')).parent)+':'+os.environ['PATH']);assembly=B/'check.S';driver.run([driver.tool('lean'),'-Dcompiler.extract_closed=false','--run','Compiler/Main.lean','DeclarationCheck',assembly,'DeclarationCheck.check'],env=env)
boot=B/'boot.S';boot.write_text(BOOT.replace('lt_Examples_StructuredConsumer_check','lt_DeclarationCheck_check'));objs=[]
for i,part in enumerate([assembly,boot,driver.ROOT/'runtime/primitives.S']):
 obj=B/f'{i}.o';driver.asm(part,obj);objs.append(obj)
elf=B/'check.elf';binary=B/'check.bin';driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',driver.ROOT/'runtime/kernel.ld',*objs,'-o',elf]);driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary]);r=subprocess.run([driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',binary],capture_output=True,timeout=45)
if r.returncode:raise AssertionError((r.returncode,r.stdout,r.stderr))
report=dict(schema=1,result='pass',binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),checks=[x[0]for x in cases],scope='actual compiled native project declaration parser and signing prerequisites; signature/graph authority checked separately');(B/'execution.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
