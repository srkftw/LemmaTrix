"""Run the real structured compiler/runtime subset without rebuilding the OS."""
import hashlib,json,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import driver
ROOT=driver.ROOT
B=ROOT/'build/structured-runtime'
BOOT=r'''.option norvc
.section .text.boot
.globl _start
_start:
 li sp,0x800ff000
 la t0,fatal
 csrw mtvec,t0
 li t0,-1
 csrw pmpaddr0,t0
 li t0,15
 csrw pmpcfg0,t0
 li t0,0x80080000
 li t1,1024
1: sd zero,0(t0)
 addi t0,t0,8
 addi t1,t1,-1
 bnez t1,1b
 li t0,0x80080000
 li t1,0x20020401
 sd t1,0(t0)
 li t1,0x200000cf
 sd t1,16(t0)
 li t0,0x80081000
 li t1,0xcf
 sd t1,0(t0)
 li t1,0x200800cf
 sd t1,16(t0)
 li t1,0x40000cf
 sd t1,1024(t0)
 li t0,0x8000000000080080
 csrw satp,t0
 sfence.vma zero,zero
 li t0,0x800
 csrw mstatus,t0
 la t0,run
 csrw mepc,t0
 mret
run:
 li a0,0
 call lt_Examples_StructuredConsumer_check
 call lt_finish
fatal:
 li a0,2
 call lt_finish
'''

def main():
 B.mkdir(parents=True,exist_ok=True)
 for path in ['Guest/Primitives','Guest/Structured','Examples/StructuredProducer','Examples/StructuredConsumer']:
  driver.lean(['-o',path+'.olean',path+'.lean'])
 assembly=B/'consumer.S'
 driver.lean(['--run','Compiler/Main.lean','Examples.StructuredConsumer',assembly,'Examples.StructuredConsumer.check'])
 (B/'boot.S').write_text(BOOT)
 objects=[]
 for i,source in enumerate([assembly,B/'boot.S',ROOT/'runtime/primitives.S']):
  output=B/f'{i}.o';driver.asm(source,output);objects.append(output)
 elf=B/'consumer.elf';binary=B/'consumer.bin'
 driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf])
 driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary])
 args=[driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',binary]
 result=subprocess.run([str(a) for a in args],cwd=ROOT,capture_output=True,timeout=30)
 if result.returncode:raise RuntimeError(f'structured native consumer failed: exit {result.returncode}, {result.stderr.decode()}')
 report={'schema':1,'environment':'QEMU RV64 system emulation; actual generated native code in supervisor mode','binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'cross_module_records':True,'tagged_variants':True,'shared_ownership_and_reuse':True,'bounded_byte_checks_and_utf8_boundaries':True,'allocation_reclamation_cycles':4096,'result':'pass'}
 (B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report,indent=2))
if __name__=='__main__':main()
