"""Incremental freestanding live-image build; no application release is embedded."""
import hashlib,json,os,re
from pathlib import Path
import driver
ROOT=driver.ROOT
B=ROOT/'build/live'
MODULES=['Primitives','Policy','DevicePrimitives','Devices','GraphicsDevice','Effects','Structured','LiveMemory','ServiceSHA256','ServiceHash','ServiceSignature','LiveSDK','VaultCrypto','VaultPolicy','Vault','Objects','LiveApps','LiveKernel','Launcher','Raster','Labels','Compositor','BuildJobs','Desktop','TextTools','Network']
def service_image_bounds(pid):
 if pid not in range(1,7):raise ValueError('unknown built-in service')
 return (0x480000,393216) if pid==2 else (0x300000+(pid-1)*262144,262144)
def check_service_layout():
 ranges=sorted((*service_image_bounds(pid),pid) for pid in range(1,7))
 for i,(start,size,pid) in enumerate(ranges):
  if start<0x300000 or start+size>0x600000 or (i and ranges[i-1][0]+ranges[i-1][1]>start):
   raise ValueError('built-in image regions overlap or exceed the common image')
  code_bytes=393216 if pid==2 else 262144
  data_offset=393216 if pid==2 else 262144
  stack_offset=458752 if pid==2 else 327680
  if code_bytes>data_offset or data_offset+65536>stack_offset or stack_offset+16384>524288:
   raise ValueError('built-in private code/data/stack exceed or overlap their512KiB physical slot')
def content(paths):
 h=hashlib.sha256()
 for p in paths:h.update(str(p.relative_to(ROOT)).encode());h.update(p.read_bytes())
 return h.hexdigest()
def imports(source):
 # Lean permits whitespace and nested comments between import and its module.
 # Remove comments while retaining newlines and token separation.
 data=source.read_text();out=[];i=0;depth=0;quoted=False
 while i<len(data):
  pair=data[i:i+2];char=data[i]
  if depth:
   if pair=='/-':depth+=1;out.extend('  ');i+=2;continue
   if pair=='-/':depth-=1;out.extend('  ');i+=2;continue
   out.append('\n' if char=='\n' else ' ');i+=1;continue
  if quoted:
   if char=='\\':out.extend('  ');i+=2;continue
   if char=='"':quoted=False
   out.append('\n' if char=='\n' else ' ');i+=1;continue
  if pair=='--':
   end=data.find('\n',i)
   if end<0:break
   out.extend(' '*(end-i));i=end;continue
  if pair=='/-':depth=1;out.extend('  ');i+=2;continue
  if char=='"':quoted=True;out.append(' ');i+=1;continue
  out.append(char);i+=1
 return re.findall(r'^\s*(?:public\s+)?import\s+([A-Za-z_][A-Za-z0-9_.]*)',''.join(out),re.M)
def build_identity():
 return content([ROOT/'tools/driver.py',ROOT/'tools/live_build.py',ROOT/'toolchain.lock.json',ROOT/'lean-toolchain'])+repr([driver.tool(n) for n in ['lean','clang','ld.lld','llvm-objcopy']])
def module_inputs(module_name,seen=None):
 seen=set() if seen is None else seen
 if module_name in seen:return []
 seen.add(module_name);source=ROOT/(module_name.replace('.','/')+'.lean')
 if not source.exists():return []
 files=[source,source.with_suffix('.olean')]
 for imported in imports(source):files+=module_inputs(imported,seen)
 return files
def compile_module(module_name):
 path=ROOT/(module_name.replace('.','/')+'.lean');output=path.with_suffix('.olean')
 if not path.resolve().is_relative_to(ROOT) or not path.is_file():raise ValueError('module source must exist inside checkout: '+module_name)
 deps=[]
 for imported in imports(path):
  p=ROOT/(imported.replace('.','/')+'.olean')
  source=p.with_suffix('.lean')
  if source.exists():compile_module(imported)
  if p.exists():deps.append(p)
 stamp=B/(module_name+'.module.sha256');key=content([path,*deps,ROOT/'lean-toolchain'])+build_identity()
 if not output.exists() or not stamp.exists() or stamp.read_text()!=key:
  driver.lean(['-o',str(output),str(path)]);stamp.write_text(key)
def artifact(module_name,entry,prefix,kernel=False,wide=False,objects_profile=False):
 if objects_profile and (kernel or not wide or module_name!='Guest.Objects' or entry!='Guest.Objects.main'):
  raise ValueError('extended built-in profile is restricted to the Objects service')
 assembly=B/(prefix+'.S');elf=B/(prefix+'.elf');binary=B/(prefix+'.bin')
 linker=ROOT/('runtime/kernel.ld' if kernel else 'runtime/service3.ld' if objects_profile else 'runtime/app2.ld' if wide else 'runtime/app.ld')
 files=[*module_inputs(module_name),ROOT/'Compiler/Main.lean',ROOT/'runtime/primitives.S',ROOT/'runtime/live_boot.S' if kernel else ROOT/'runtime/app.S',linker]
 key=content(files)+entry+str(wide)+str(objects_profile)+build_identity();stamp=B/(prefix+'.sha256')
 if binary.exists() and stamp.exists() and stamp.read_text()==key:return binary
 driver.lean(['--run','Compiler/Main.lean',module_name,str(assembly),entry,*(['Guest.Live.trapDispatch'] if kernel else [])])
 startup=ROOT/'runtime/live_boot.S'
 if not kernel:
  startup=B/(prefix+'.entry.S');startup.write_text('.option norvc\n.section .text.boot\n.globl _start\n_start:\n li a0,0\n call lt_'+entry.replace('.','_')+'\n mv a1,a0\n li a0,10\n call lt_syscall\n1: j 1b\n')
 objects=[]
 for i,src in enumerate([assembly,startup,ROOT/'runtime/primitives.S']):
  out=B/f'{prefix}.{i}.o';driver.asm(src,out);objects.append(out)
 driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',linker,*objects,'-o',elf])
 undefined=driver.run([driver.tool('llvm-nm'),'-u',elf],capture_output=True,text=True).stdout
 if undefined.strip():raise RuntimeError('unresolved live guest symbols:'+undefined)
 driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary]);stamp.write_text(key);return binary
def build(clean=False):
 B.mkdir(parents=True,exist_ok=True);driver.validate_toolchain();check_service_layout()
 if clean:
  for path in B.iterdir():
   if path.is_file() and path.suffix in ('.sha256','.S','.bin','.o','.elf'):path.unlink()
  for path in (ROOT/'Guest').glob('*.olean'):path.unlink()
 for name in MODULES:compile_module('Guest.'+name)
 kernel=artifact('Guest.LiveKernel','Guest.Live.kernelMain','kernel',True)
 services=[artifact('Guest.Launcher','Guest.Launcher.main','launcher',wide=True),artifact('Guest.Objects','Guest.Objects.main','objects',wide=True,objects_profile=True),artifact('Guest.Vault','Guest.Vault.appMain','vault',wide=True),artifact('Guest.Compositor','Guest.Compositor.main','compositor',wide=True),artifact('Guest.BuildJobs','Guest.BuildJobs.main','build-jobs',wide=True),artifact('Guest.Network','Guest.Network.main','network',wide=True)]
 for name in ['workbench','inspector','worker']:artifact('Guest.LiveApps','Guest.LiveApps.'+name+'Main',name)
 data=bytearray(0x600000)
 part=kernel.read_bytes();data[:len(part)]=part
 import struct
 for pid,path in enumerate(services,1):
  part=path.read_bytes()
  offset,limit=service_image_bounds(pid)
  if len(part)>limit:raise RuntimeError(f'{path.name} exceeds its explicit{limit}-byte built-in code profile')
  data[offset:offset+len(part)]=part
  rights={1:0x1000000ff,2:0,3:127,4:127,5:127,6:0}[pid]
  struct.pack_into('<4Q',data,0x200000+pid*32,len(part),rights,2,limit)
 try:
  import build_jobs
  compiler_id=bytes.fromhex(build_jobs.compiler_identity())
 except (OSError,RuntimeError):compiler_id=bytes(32)
 data[0x200400:0x200420]=compiler_id
 (B/'compiler.sha256').write_text(compiler_id.hex()+'\n')
 image=B/'guest.bin';image.write_bytes(data);identity=hashlib.sha256(data).hexdigest()
 (B/'image.sha256').write_text(identity+'  guest.bin\n');print('LIVE IMAGE',identity,flush=True)
 return image

def app(module_name,entry,name,profile=1):
 B.mkdir(parents=True,exist_ok=True);driver.validate_toolchain()
 if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*',module_name) or not re.fullmatch(r'[a-zA-Z0-9_-]+',name):raise ValueError('invalid module/output name')
 compile_module(module_name)
 (B/'apps').mkdir(parents=True,exist_ok=True)
 return artifact(module_name,entry,'apps/'+name,wide=profile==2)
