"""Trusted namespace runner. Only build_jobs.py may construct its configuration."""
import base64,ctypes,json,os,resource,subprocess,sys
from pathlib import Path

libc=ctypes.CDLL(None,use_errno=True)
MS_RDONLY=1;MS_NOSUID=2;MS_NODEV=4;MS_NOEXEC=8;MS_REMOUNT=32;MS_BIND=4096;MS_REC=16384;MS_PRIVATE=1<<18

def mount(source,target,kind=None,flags=0,data=None):
 def b(v):return v.encode() if v is not None else None
 if libc.mount(b(source),b(str(target)),b(kind),ctypes.c_ulong(flags),b(data)):
  raise OSError(ctypes.get_errno(),f'mount {target}')

def bind(source,target,directory=True,device=False):
 target=Path(target);target.parent.mkdir(parents=True,exist_ok=True)
 if directory:target.mkdir(exist_ok=True)
 else:target.touch()
 mount(source,target,flags=MS_BIND|MS_REC)
 mount(None,target,flags=MS_BIND|MS_REMOUNT|MS_NOSUID|(0 if device else MS_RDONLY|MS_NODEV))

def lower_authority(process_limit):
 # Empty capabilities and prohibit gaining them again through executables.
 class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
 class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
 hdr=Header(0x20080522,0);data=(Data*2)()
 if libc.capset(ctypes.byref(hdr),ctypes.byref(data)) or libc.prctl(38,1,0,0,0):raise OSError(ctypes.get_errno(),'drop authority')
 resource.setrlimit(resource.RLIMIT_AS,(16*1024*1024*1024,16*1024*1024*1024))
 resource.setrlimit(resource.RLIMIT_CPU,(60,60))
 resource.setrlimit(resource.RLIMIT_FSIZE,(8*1024*1024,8*1024*1024))
 resource.setrlimit(resource.RLIMIT_NPROC,(process_limit,process_limit))
 resource.setrlimit(resource.RLIMIT_NOFILE,(128,128))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))

def main(config_path):
 cfg=json.loads(Path(config_path).read_text());root=Path(cfg['root'])
 mount(None,'/',flags=MS_REC|MS_PRIVATE)
 mount('tmpfs',root,'tmpfs',MS_NOSUID|MS_NODEV,'size=16m,mode=755')
 for path in cfg['closure']:bind(path,root/path.lstrip('/'))
 bind(cfg['input'],root/'input');bind(cfg['sdk'],root/'sdk')
 for name in ['work','tmp','proc','dev','home']: (root/name).mkdir(exist_ok=True)
 mount('tmpfs',root/'work','tmpfs',MS_NOSUID|MS_NODEV,'size=128m,nr_inodes=16384,mode=700')
 mount('tmpfs',root/'tmp','tmpfs',MS_NOSUID|MS_NODEV,'size=16m,nr_inodes=1024,mode=700')
 for name in ['null','zero','urandom']:bind('/dev/'+name,root/'dev'/name,False,True)
 mount('proc',root/'proc','proc',MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC)
 mount(None,root,flags=MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV)
 os.chroot(root);os.chdir('/input')
 os.environ.clear();os.environ.update({'HOME':'/home','TMPDIR':'/tmp','PATH':str(Path(cfg['tools']['lean']).parent),'LANG':'C.UTF-8','LEAN_PATH':'/work/sdk:/work/project','LEAN_NUM_THREADS':'2'})
 lower_authority(cfg['uid_process_limit'])
 (Path('/work')/'sdk/Guest').mkdir(parents=True);(Path('/work')/'project').mkdir()
 log=Path('/work/diagnostics.txt')
 tools=cfg['tools'];steps=[]
 def run(args):
  with log.open('ab') as out:
   result=subprocess.run([str(x) for x in args],stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,close_fds=True)
  steps.append({'tool':Path(args[0]).name,'exit':result.returncode})
  if result.returncode:raise RuntimeError('build command failed')
 def lean(args):run([tools['lean'],'-j2','-M4096','-Dcompiler.extract_closed=false',*args])
 status='ok';artifact=None
 try:
  for name in cfg['sdk_modules']:
   dest=Path('/work/sdk')/(name.replace('.','/')+'.olean');dest.parent.mkdir(parents=True,exist_ok=True)
   lean(['-R','/sdk','-o',dest,Path('/sdk')/(name.replace('.','/')+'.lean')])
  # The compiler runs from its own immutable source, with every project module
  # elaborated inside this same sandbox and no ambient import directories.
  for name in cfg['modules']:
   dest=Path('/work/project')/(name.replace('.','/')+'.olean');dest.parent.mkdir(parents=True,exist_ok=True)
   lean(['-o',dest,Path('/input')/(name.replace('.','/')+'.lean')])
  lean(['-R','/sdk','--run','/sdk/Compiler/Main.lean',cfg['module'],'/work/app.S',cfg['entry']])
  startup='.option norvc\n.section .text.boot\n.globl _start\n_start:\n li a0,0\n call lt_'+cfg['entry'].replace('.','_')+'\n mv a1,a0\n li a0,10\n call lt_syscall\n1: j 1b\n'
  Path('/work/start.S').write_text(startup)
  objects=[]
  for i,src in enumerate(['/work/app.S','/work/start.S','/sdk/runtime/primitives.S']):
   obj=f'/work/{i}.o';run([tools['clang'],'-target','riscv64-unknown-elf','-march=rv64im','-mabi=lp64','-mno-relax','-c',src,'-o',obj]);objects.append(obj)
  run([tools['ld.lld'],'-m','elf64lriscv','--no-relax','-T',('/sdk/runtime/app2.ld' if cfg['profile']==2 else '/sdk/runtime/app.ld'),*objects,'-o','/work/app.elf'])
  run([tools['llvm-objcopy'],'-O','binary','/work/app.elf','/work/app.bin'])
  binary=Path('/work/app.bin').read_bytes()
  if not 0<len(binary)<=(262144 if cfg['profile']==2 else 65536):raise RuntimeError('native code exceeds profile code limit')
  artifact=base64.b64encode(binary).decode()
 except (OSError,RuntimeError) as error:
  status='error'
  with log.open('ab') as out:out.write(('\nbuild: '+str(error)+'\n').encode())
 diagnostics=log.read_bytes()[:65536].decode('utf-8','replace') if log.exists() else ''
 print(json.dumps({'sandbox_protocol':1,'sandbox_ready':True,'status':status,'diagnostics':diagnostics,'steps':steps,'binary_base64':artifact},separators=(',',':')),flush=True)

if __name__=='__main__':
 try:main(sys.argv[1])
 except BaseException as error:
  print(json.dumps({'sandbox_protocol':1,'status':'unavailable','diagnostics':str(error)[:2048]}),flush=True);sys.exit(2)
