"""Focused native Feed framing/signature/scope tests; not a connected product claim."""
import hashlib,json,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import driver,live_build
sys.path.insert(0,str(driver.ROOT/'tests'))
from structured_runtime import BOOT
ROOT=driver.ROOT
B=ROOT/'build/feed-boundaries'

def stores(address,raw):
    lines=[]
    for i in range(0,len(raw),8):
        q=raw[i:i+8]
        if len(q)==8:lines.append(f'  let t := store64 {address+i} {int.from_bytes(q,"little")} t')
        else:
            for j,x in enumerate(q):lines.append(f'  let t := store8 {address+i+j} {x} t')
    return '\n'.join(lines)

def main():
    B.mkdir(parents=True,exist_ok=True)
    body=b'Community build notes: the signed release keeps inspection and local execution approval separate.\n'
    p=0x680000;c=0x681000;seed=0x683000;public=0x683100
    source='''import Guest.FeedFederation
namespace build.FeedBoundaries
open Guest Guest.LiveSDK
def check (t : UInt64) : UInt64 :=
'''+stores(c,body)+'\n'+stores(seed,bytes(range(32)))+f'''
  let t := zero {p} 60 t
  let t := store64 {p} Guest.FeedEvent.signingMagic (store64 {p+8} 1 t)
  let t := store64 {p+16} 5 (store64 {p+24} 4 t)
  let t := store64 {p+32} 1 (store64 {p+40} 256 t)
  let t := store64 {p+48} 1 (store64 {p+80} 7 t)
  let t := store64 {p+160} Guest.FeedEvent.magic (store64 {p+168} 1 t)
  let t := store64 {p+176} 1 (store64 {p+184} 1 t)
  let t := store64 {p+256} {len(body)} (store64 {p+272} 1 t)
  let t := store64 {p+304} 2 t
  let t := Guest.ServiceHash.sha256At Guest.FeedEvent.hashScratch {c} {len(body)} {p+224} t
  let t := Guest.Ed25519.publicKey {seed} {public} t
  let t := copy {public} {p+112} 32 t
  let t := Guest.Ed25519.sign {seed} {public} {p} 416 {p+416} t
  if !Guest.FeedEvent.valid {p} t then 1 else
  if !Guest.FeedEvent.contentValid {p} {c} {len(body)} t then 2 else
  let t := store64 (Guest.FeedFederation.active+64) 1 (store64 (Guest.FeedFederation.active+96) 2 t)
  if !Guest.FeedFederation.allowedScope {p} t then 3 else
  let t := store64 (Guest.FeedFederation.active+96) 3 t
  if Guest.FeedFederation.allowedScope {p} t then 4 else
  let t := store64 (Guest.FeedFederation.active+96) 2 t
  let t := store8 {p+416} (load8 {p+416} t ^^^ 1) t
  if Guest.FeedEvent.valid {p} t then 5 else
  let t := store8 {p+416} (load8 {p+416} t ^^^ 1) t
  let t := store8 {c} 192 t
  if Guest.FeedEvent.contentValid {p} {c} {len(body)} t then 6 else
  let t := store64 {p+256} 16385 t
  if Guest.FeedEvent.framingValid {p} t then 7 else
  let t := store64 {p+256} {len(body)} (store64 {p+176} 8 t)
  if Guest.FeedEvent.framingValid {p} t then 8 else
  let t := store64 {p+176} 1 (store64 {p+168} 2 t)
  if Guest.FeedEvent.framingValid {p} t then 9 else
  if Guest.FeedPolicy.visible true 3 then 10 else 0
end build.FeedBoundaries
'''
    target=ROOT/'build/FeedBoundaries.lean';target.write_text(source)
    live_build.compile_module('build.FeedBoundaries')
    assembly=B/'check.S'
    driver.lean(['--run','Compiler/Main.lean','build.FeedBoundaries',assembly,'build.FeedBoundaries.check'])
    boot=BOOT.replace('lt_Examples_StructuredConsumer_check','lt_build_FeedBoundaries_check')
    boot=boot.replace(' li t1,0x40000cf',' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf')
    boot=boot.replace(' call lt_finish\nfatal:\n li a0,2\n call lt_finish',''' beqz a0,passed
 slli a0,a0,16
 li t0,0x100000
 li t1,0x3333
 or t1,t1,a0
 sw t1,0(t0)
1: j 1b
passed:
 li t0,0x10000000
 li t1,80
 sb t1,0(t0)
 li a0,0
 call lt_finish
fatal:
 li t0,0x100000
 li t1,0x00403333
 sw t1,0(t0)
1: j 1b''')
    (B/'boot.S').write_text(boot)
    objects=[]
    for i,src in enumerate([assembly,B/'boot.S',ROOT/'runtime/primitives.S']):
        out=B/f'{i}.o';driver.asm(src,out);objects.append(out)
    elf=B/'check.elf';binary=B/'check.bin'
    driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf])
    driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary])
    result=subprocess.run([driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',binary],cwd=ROOT,capture_output=True,timeout=90)
    if result.returncode or result.stdout!=b'P':raise RuntimeError(f'Feed native check failed exit{result.returncode}: {result.stdout!r} {result.stderr!r}')
    report=dict(schema=1,environment='QEMU RV64 system emulation',binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),native_ed25519_feed_framing='pass',tampered_signature='reject',wrong_audience='reject',malformed_utf8='reject',oversized_body='reject',author_role_cannot_moderate='reject',unknown_version='reject',appeal_reversal_preserves_local_block='pass',scope='focused boundary checks; no connected service or persistence claim')
    (B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
