import argparse, hashlib, json, os, shutil, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
LOCK = json.loads((ROOT/'toolchain.lock.json').read_text())
BUILD = ROOT/'build'

def tool(name):
    candidate = os.environ.get('LT_'+name.upper().replace('-','_').replace('.','_')) or LOCK['nix_store'].get(name)
    if candidate and Path(candidate).exists(): return candidate
    candidate = shutil.which(name)
    if candidate: return candidate
    raise RuntimeError(f'Missing {name}; install version pinned in toolchain.lock.json or set LT_{name.upper().replace("-","_").replace(".","_")}')

def validate_toolchain():
    requirements={'lean':LOCK['lean'],'clang':LOCK['llvm'],'ld.lld':LOCK['llvm'],
                  'llvm-objcopy':LOCK['llvm'],'qemu-system-riscv64':LOCK['qemu'],'openssl':LOCK['openssl']}
    versions={}
    for name,expected in requirements.items():
        r=subprocess.run([tool(name), 'version' if name=='openssl' else '--version'],capture_output=True,text=True,check=True)
        version=(r.stdout+r.stderr).strip()
        if expected not in version: raise RuntimeError(f'{name}: expected pinned{expected}, got {version}')
        versions[name]=version
    return versions

def run(args, **kw):
    return subprocess.run([str(x) for x in args], cwd=ROOT, check=True, **kw)

def lean(args):
    env = dict(os.environ, LEAN_PATH=str(ROOT), PATH=str(Path(tool('lean')).parent)+':'+os.environ['PATH'])
    run([tool('lean'), '-Dcompiler.extract_closed=false', *args], env=env)

def asm(src, out, target='riscv64-unknown-elf'):
    opts = ['-march=rv64im', '-mabi=lp64', '-mno-relax'] if target.startswith('riscv') else []
    run([tool('clang'), '-target', target, *opts, '-c', src, '-o', out])

def compile_guest(module, roots, prefix, startup, script):
    src = BUILD/(prefix+'.S')
    lean(['--run','Compiler/Main.lean',module,str(src),*roots])
    objects=[]
    for i,path in enumerate([src,ROOT/startup,ROOT/'runtime/primitives.S']):
        out=BUILD/f'{prefix}.{i}.o';asm(path,out);objects.append(out)
    elf=BUILD/(prefix+'.elf')
    run([tool('ld.lld'), '-m','elf64lriscv','--no-relax','-T',script,*objects,'-o',elf])
    undefined=run([tool('llvm-nm'),'-u',elf],capture_output=True,text=True).stdout
    if undefined.strip(): raise RuntimeError('Unresolved guest symbols: '+undefined)
    run([tool('llvm-objcopy'),'-O','binary',elf,BUILD/(prefix+'.bin')])

def build(text='LemmaTrix source objects\n', package=None, policy=None):
    BUILD.mkdir(exist_ok=True)
    versions=validate_toolchain()
    (BUILD/'toolchain-versions.json').write_text(json.dumps(versions,indent=2)+'\n')
    lean(['-o','Guest/Primitives.olean','Guest/Primitives.lean'])
    lean(['-o','Guest/SDK.olean','Guest/SDK.lean'])
    lean(['-o','Guest/Policy.olean','Guest/Policy.lean'])
    lean(['-o','Guest/SHA256.olean','Guest/SHA256.lean'])
    lean(['-o','Guest/Signature.olean','Guest/Signature.lean'])
    lean(['-o','Guest/Package.olean','Guest/Package.lean'])
    for module in ['Kernel','Workbench','Observer']:
        lean(['-o',f'Guest/{module}.olean',f'Guest/{module}.lean'])
    compile_guest('Guest.Kernel',['Guest.kernelMain','Guest.trapDispatch'],'kernel','runtime/boot.S','runtime/kernel.ld')
    for module,prefix in [('Workbench','workbench'),('Observer','observer')]:
        compile_guest('Guest.'+module,['Guest.appMain'],prefix,'runtime/app.S','runtime/app.ld')
    compile_guest('Guest.Workbench',['Guest.appV2'],'workbench-v2','runtime/app2.S','runtime/app.ld')
    content=text.encode('utf-8')
    if len(content)>256: raise RuntimeError('Import text exceeds 256 bytes')
    data=bytearray(0xaa0000+0x10200)
    for off,name in [(0,'kernel'),(0x500000,'observer')]:
        part=(BUILD/(name+'.bin')).read_bytes();data[off:off+len(part)]=part
    data[0x800000:0x800008]=len(content).to_bytes(8,'little');data[0x800008:0x800008+len(content)]=content
    import capsule
    key=capsule.development_key()
    trust=capsule.modulus(key)
    data[0x810000:0x810100]=trust
    data[0x811000:0x811008]=(7).to_bytes(8,'little')
    data[0x811008:0x811010]=(1).to_bytes(8,'little')
    for offset,name,version,opts in [(0xa00000,'workbench',1,{}),(0xa20000,'workbench-v2',2,{}),(0xa40000,'workbench-v2',3,{'tamper':True}),(0xa60000,'workbench-v2',3,{'caps':15}),(0xa80000,'workbench-v2',3,{'runtime':99}),(0xaa0000,'workbench-v2',3,{'signature_tamper':True})]:
        raw=(BUILD/(name+'.bin')).read_bytes()
        record=bytearray(capsule.build_capsule(raw,version,opts.get('caps',7),opts.get('runtime',1),key))
        if opts.get('tamper'): record[128]^=1
        if opts.get('signature_tamper'): record[capsule.SIGNATURE_OFFSET]^=1
        data[offset:offset+len(record)]=record
        (BUILD/(name+('-bad' if opts else '')+'.ltcap')).write_bytes(record)
    if package is not None:
        policy=policy or {}
        record=capsule.from_package(package,1,key,**policy)
        data[0xa00000:0xa00000+len(record)]=record
        mask=int.from_bytes(record[48:56],'little')
        data[0x811000:0x811008]=mask.to_bytes(8,'little')
        data[0x811008:0x811010]=(0).to_bytes(8,'little')
    (BUILD/'guest.bin').write_bytes(data)
    digest=hashlib.sha256(data).hexdigest()
    (BUILD/'image.sha256').write_text(digest+'  guest.bin\n')
    print('IMAGE',digest,flush=True)

def emulators():
    for arch,target in [('x86_64','x86_64-linux-gnu'),('aarch64','aarch64-linux-gnu')]:
        obj=BUILD/(arch+'.o');asm(ROOT/f'emulator/{arch}.S',obj,target)
        run([tool('ld.lld'),'-static','-e','_start',obj,'-o',BUILD/('lt-'+arch)])

def backend(name):
    image=BUILD/'guest.bin'
    if name=='qemu':
        args=[tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','16M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',image]
    elif name=='x86_64':args=[BUILD/'lt-x86_64',image]
    else:args=[tool('qemu-aarch64'),BUILD/'lt-aarch64',image]
    r=subprocess.run([str(x) for x in args],cwd=ROOT,timeout=45,capture_output=True,text=True)
    print(r.stdout,end='');print(r.stderr,end='',file=sys.stderr)
    if r.returncode:raise RuntimeError(f'{name} guest exited{r.returncode}')
    return r.stdout

def main():
    os.chdir(ROOT)
    if len(sys.argv)==1 or sys.argv[1] in ('-h','--help'):
        print('LemmaTrix live development commands (docs/development.html)\n'
              '  setup / doctor           pinned host dependencies\n'
              '  build / emulators        incremental guest image / assembly backends\n'
              '  run --socket PATH        long-lived session; --backend, --vault supported\n'
              '  ctl --socket PATH ...    trusted guest management; use ctl --help\n'
              '  app --module M --entry E --name N   independent native client build\n'
              '  release keygen/create/inspect      publisher-signed envelopes\n'
              '  vault-init IMAGE [--key-out KEY]   explicit development storage\n'
              '  project / project-vault / display   graphical creator graph/build/vault tools\n'
              '  network / forge / federation       encrypted peer setup and guest discovery/admission\n'
              '  server-store / node                explicit durable backing and isolated node roles\n'
              '  remote-build                       guest-approved executor and real verifier comparison\n'
              '  rel-live ...             native edit / host build / live reimport loop\n'
              '  check                    live integrated acceptance\n'
              '  fixture-build/run/check  historical finite campaign-001 regression')
        return
    if len(sys.argv)>1 and sys.argv[1] in ('package','capsule','rel','release'):
        import importlib
        module=importlib.import_module({'package':'packaging','capsule':'capsule','rel':'rel','release':'releases'}[sys.argv[1]])
        sys.exit(module.main(sys.argv[2:]))
    if len(sys.argv)>1 and sys.argv[1] in ('session','ctl','vault-init'):
        import live
        try:sys.exit(live.main(sys.argv[1:]))
        except (ValueError,OSError,EOFError,TimeoutError) as error:
            print('lt:',error,file=sys.stderr);sys.exit(1)
    if len(sys.argv)>1 and sys.argv[1] in ('build','live-build'):
        import live_build
        p=argparse.ArgumentParser(description='Incremental live-image build')
        p.add_argument('--clean',action='store_true');a=p.parse_args(sys.argv[2:])
        live_build.build(clean=a.clean);return
    if len(sys.argv)>1 and sys.argv[1] in ('app','live-app'):
        p=argparse.ArgumentParser(description='Incremental native client build; no machine image rebuild')
        p.add_argument('--profile',type=int,choices=(1,2),default=1);p.add_argument('--module',required=True);p.add_argument('--entry',required=True);p.add_argument('--name',required=True)
        a=p.parse_args(sys.argv[2:]);import live_build
        print(live_build.app(a.module,a.entry,a.name,a.profile));return
    if len(sys.argv)>1 and sys.argv[1]=='display':
        p=argparse.ArgumentParser(description='Thin raw pixel/input adapter for assembly backends')
        p.add_argument('--graphics',type=Path,required=True);a=p.parse_args(sys.argv[2:])
        python=os.environ.get('LT_PRESENTER_PYTHON',sys.executable)
        os.execv(python,[python,str(ROOT/'tools/pixel_presenter.py'),'--frame',str(a.graphics)+'.bgrx','--events',str(a.graphics)+'.evdev'])
    if len(sys.argv)>1 and sys.argv[1]=='project-vault':
        import project_vault
        sys.exit(project_vault.main(sys.argv[2:]))
    if len(sys.argv)>1 and sys.argv[1]=='server-store':
        import server_store
        sys.exit(server_store.main(sys.argv[2:]))
    if len(sys.argv)>1 and sys.argv[1]=='node':
        import nodes
        sys.exit(nodes.main(sys.argv[2:]))
    if len(sys.argv)>1 and sys.argv[1]=='network':
        import network
        sys.exit(network.main(sys.argv[2:]))
    if len(sys.argv)>1 and sys.argv[1]=='forge':
        import forge
        sys.exit(forge.main(sys.argv[2:]))
    if len(sys.argv)>1 and sys.argv[1]=='federation':
        import federation
        sys.exit(federation.main(sys.argv[2:]))
    if len(sys.argv)>1 and sys.argv[1]=='remote-build':
        import remote_build
        sys.exit(remote_build.main(sys.argv[2:]))
    if len(sys.argv)>1 and sys.argv[1]=='project':
        import projects
        sys.exit(projects.main(sys.argv[2:]))
    if len(sys.argv)>1 and sys.argv[1]=='rel-live':
        import live_rel
        sys.exit(live_rel.main(sys.argv[2:]))
    if len(sys.argv)>1 and sys.argv[1]=='run':
        import live
        sys.exit(live.main(['session',*sys.argv[2:]]))
    if len(sys.argv)>1 and sys.argv[1] in ('check','demo'):
        sys.path.insert(0,str(ROOT/'tests'))
        import live_acceptance
        sys.exit(live_acceptance.main(sys.argv[2:]))
    if len(sys.argv)>1 and sys.argv[1].startswith('fixture-'):
        sys.argv[1]=sys.argv[1][8:]

    p=argparse.ArgumentParser(description='LemmaTrix live native workbench; see docs/development.html', epilog='Live commands: build; emulators; run/session --backend qemu|x86_64|aarch64 --socket PATH [--vault IMAGE]; ctl --socket PATH COMMAND; app --module MODULE --entry ENTRY --name NAME; release keygen|create|inspect; vault-init IMAGE [--key-out KEY]; rel-live --help; check. Historical batch commands use fixture-build/run/demo/check/app.')
    p.add_argument('command',choices=['doctor','build','run','demo','check','emulators','app','setup'])
    p.add_argument('--backend',choices=['qemu','x86_64','aarch64'],default='qemu')
    p.add_argument('--text',default='LemmaTrix source objects\n')
    p.add_argument('--text-file',type=Path)
    p.add_argument('--package',type=Path)
    p.add_argument('--trust-key',type=Path,action='append',default=[])
    p.add_argument('--approve-cap',action='append',default=[])
    p.add_argument('--allow-development',action='store_true')
    p.add_argument('--module',default='Examples.NativeUtility')
    p.add_argument('--name',default='native-utility')
    a=p.parse_args()
    try:
        if a.text_file:
            with a.text_file.open('rb') as stream: content=stream.read(257)
            if len(content)>256: raise RuntimeError('Import exceeds256bytes')
            a.text=content.decode('utf-8')
        policy=dict(allow_development=a.allow_development,trust_keys=a.trust_key,
                    approved_caps=a.approve_cap,require_signature=True)
        if a.command=='doctor':
            for name,version in validate_toolchain().items():print(name,version,tool(name))
        elif a.command=='setup':
            try:
                validate_toolchain()
                print('Pinned dependencies ready; ordinary builds perform no downloads')
                return
            except RuntimeError:pass
            paths=sorted(set(str(Path(value).parent.parent) for value in LOCK['nix_store'].values()))
            missing=[path for path in paths if not Path(path).exists()]
            if missing:
                nix=shutil.which('nix-store')
                if not nix:raise RuntimeError('Install Nix or supply exact pinned tools via LT_* variables; see docs/development.html')
                run([nix,'--realise',*missing])
            validate_toolchain()
            print('Pinned dependencies ready; ordinary builds perform no downloads')
        elif a.command=='build':build(a.text,a.package,policy)
        elif a.command=='emulators':emulators()
        elif a.command=='app':
            if not a.name.replace('-','').isalnum(): raise RuntimeError('App output name must use letters, digits and hyphens')
            source=Path(a.module.replace('.','/')+'.lean')
            if not source.resolve().is_relative_to(ROOT) or not source.is_file(): raise RuntimeError('Module source must exist inside this checkout')
            BUILD.mkdir(exist_ok=True)
            for part in ['Primitives','SDK']:
                lean(['-o',f'Guest/{part}.olean',f'Guest/{part}.lean'])
            lean(['-o',str(source.with_suffix('.olean')),str(source)])
            compile_guest(a.module,['Guest.appMain'],a.name,'runtime/app.S','runtime/app.ld')
        elif a.command=='run':
            if a.package:build(a.text,a.package,policy)
            backend(a.backend)
        elif a.command=='demo':
            build(a.text);emulators()
            sys.path.insert(0,str(ROOT/'tests'))
            import acceptance
            acceptance.main()
        elif a.command=='check':
            build(a.text);emulators()
            sys.path.insert(0,str(ROOT/'tests'))
            import acceptance
            acceptance.main()
            from Compiler.check import check
            import driver
            check(driver)
            from Compiler.signature_check import check as signature_check
            signature_check(driver)
            import package_checks
            package_checks.main()
            import rel
            print(rel.check())
    except (RuntimeError,ValueError,AssertionError,OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
        print('lt:',e,file=sys.stderr);sys.exit(1)
