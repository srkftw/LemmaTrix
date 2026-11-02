"""Resolve the same immutable Linux toolchain used by ordinary app builders."""
import json,os,platform,shutil,subprocess,sys
from pathlib import Path
import driver
CONFIG=driver.ROOT/'build/toolchain-host.json'

def setup():
 machine=platform.machine();system={'x86_64':'x86_64-linux','aarch64':'aarch64-linux','arm64':'aarch64-linux'}.get(machine)
 if platform.system()!='Linux' or not system:raise RuntimeError('supported setup hosts are x86-64 and ARM64 Linux')
 nix=shutil.which('nix-build')
 if not nix:raise RuntimeError('Nix with nix-build is required for the declared immutable SDK build closure; install Nix and rerun ./lt setup')
 command=[nix,str(driver.ROOT/'tools/toolchain.nix'),'--no-out-link','--argstr','system',system]
 # Nix builds/substitutes immutable dependencies before any app is imported.
 path=subprocess.run(command,check=True,capture_output=True,text=True).stdout.strip().splitlines()[-1]
 data=json.loads(Path(path).read_bytes())
 if data.get('schema')!=1 or data.get('system')!=system:raise RuntimeError('unexpected resolved toolchain descriptor')
 CONFIG.parent.mkdir(parents=True,exist_ok=True);CONFIG.write_text(json.dumps(data,sort_keys=True,indent=2)+'\n')
 return doctor()

def doctor():
 import build_jobs
 tools,closure=build_jobs._toolchain()
 unshare=shutil.which('unshare')
 if not unshare:raise RuntimeError('unshare is required for isolated app builds')
 probe=subprocess.run([unshare,'--user','--map-root-user','--mount','--net','--pid','--fork','true'],capture_output=True,text=True,timeout=10)
 if probe.returncode:raise RuntimeError('Linux user/mount/network/PID namespace setup is unavailable: '+probe.stderr.strip())
 return {'schema':1,'status':'ok','host':platform.machine()+' Linux','tools':tools,'readonly_closure_paths':len(closure),'isolation':'Linux user/mount/network/PID namespaces; no unsandboxed fallback','native_emulator':'x86_64' if platform.machine()=='x86_64' else 'aarch64','qemu':'optional: only QEMU RV64 or explicitly cross-architecture emulator execution','publisher_key_required':False}
