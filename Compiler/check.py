"""Focused source/IR/backend and SHA checks, called by the platform command driver."""
import hashlib, subprocess

def check(d):
    root, build = d.ROOT, d.BUILD
    build.mkdir(exist_ok=True)
    d.lean(['-o','Guest/Primitives.olean','Guest/Primitives.lean'])
    d.lean(['-o','Guest/SHA256.olean','Guest/SHA256.lean'])
    d.lean(['-o','Guest/Effects.olean','Guest/Effects.lean'])
    d.lean(['-o','Compiler/Checks.olean','Compiler/Checks.lean'])
    d.lean(['--run','Compiler/Main.lean','Compiler.Checks',str(build/'compiler-check.S'),
            'CompilerChecks.checkScalar','CompilerChecks.checkEffects','Guest.Hash.sha256'])
    fixture=bytes((i*37+11)%256 for i in range(65536))
    (build/'compiler-input.bin').write_bytes(fixture)
    lengths=[0,3,55,56,64,256,65536]
    commands=[]
    for n in lengths:
        commands.extend(['  la a0, input',f'  li a1, {n}','  li a2, 0x80981000','  li a3, 0',
                         '  call lt_Guest_Hash_sha256','  call print_hash'])
    commands.extend(['  li t0, 0x80981000','  li t1, 90','  sb t1, 0(t0)',
                     '  la a0, input','  li a1, 65537','  li a2, 0x80981000','  li a3, 0',
                     '  call lt_Guest_Hash_sha256','  call print_word',
                     '  li t0, 0x80981000','  lbu a0, 0(t0)','  call print_word'])
    startup='''
.option norvc
.option norelax
.section .text.start,"ax"
.global _start
_start:
  li sp, 0x80f00000
  li a0, 17
  call lt_CompilerChecks_checkScalar
  call print_word
  li a0, 0x80982000
  li a1, 0
  call lt_CompilerChecks_checkEffects
  call print_word
'''+ '\n'.join(commands)+'''
  li a0, 0
  call lt_finish
print_hash:
  addi sp, sp, -32
  sd ra, 24(sp)
  sd s0, 16(sp)
  sd s1, 8(sp)
  li s0, 0
  li s1, 0x80981000
1:
  add t0, s0, s1
  lbu a0, 0(t0)
  li a1, 2
  call print_digits
  addi s0, s0, 1
  li t0, 32
  bltu s0, t0, 1b
  li t0, 0x10000000
  li t1, 10
  sb t1, 0(t0)
  ld s1, 8(sp)
  ld s0, 16(sp)
  ld ra, 24(sp)
  addi sp, sp, 32
  ret
print_word:
  addi sp, sp, -16
  sd ra, 8(sp)
  li a1, 16
  call print_digits
  li t0, 0x10000000
  li t1, 10
  sb t1, 0(t0)
  ld ra, 8(sp)
  addi sp, sp, 16
  ret
print_digits:
  li t5, 0x10000000
2:
  addi a1, a1, -1
  slli t0, a1, 2
  srl t1, a0, t0
  andi t1, t1, 15
  li t0, 10
  bltu t1, t0, 3f
  addi t1, t1, 87
  j 4f
3:
  addi t1, t1, 48
4:
  sb t1, 0(t5)
  bnez a1, 2b
  ret
.section .rodata,"a"
input:
.incbin "build/compiler-input.bin"
'''
    (build/'compiler-start.S').write_text(startup)
    objects=[]
    for i,src in enumerate([build/'compiler-check.S',build/'compiler-start.S',root/'runtime/primitives.S']):
        obj=build/f'compiler-check.{i}.o';d.asm(src,obj);objects.append(obj)
    elf=build/'compiler-check.elf'
    d.run([d.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',root/'Compiler/check.ld',*objects,'-o',elf])
    qemu=[d.tool('qemu-system-riscv64'),'-M','virt','-m','16M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',elf]
    result=d.run(qemu,timeout=30,capture_output=True,text=True)
    mask=(1<<64)-1;x=17
    def arithmetic(a,b):
        a&=mask
        numerator=(a*0xfffffffffffffff1+71)&mask
        return (numerator//b if b else 0)^(((a+9)&mask)%b if b else (a+9)&mask)
    narrowed=(((x+0xffffffff)&255)+250)&255
    narrowed ^= ((((x+0xffffffff)&0xffffffff)*0xfffffffb)&0xffffffff)
    expected=(100000*100001//2+x)^arithmetic(x,0)^arithmetic(x+5,7)^narrowed^((x+31)*7)^(((x<<((x+48)%64))&mask)>>5)
    expected_lines=[f'{expected:016x}','0000000000000016']+[hashlib.sha256(fixture[:n]).hexdigest() for n in lengths]+['ffffffffffffffff','000000000000005a']
    actual=result.stdout.splitlines()
    (build/'compiler-check.log').write_text(result.stdout+result.stderr)
    if actual!=expected_lines:
        raise RuntimeError('Compiler/SHA check mismatch:\nexpected '+repr(expected_lines)+'\nactual '+repr(actual))
    # A concrete unsupported String root must fail at the compiler boundary.
    bad=build/'CompilerRejected.lean'
    bad.write_text('def rejectedString : String := "unsupported runtime heap"\n')
    d.lean(['-o',str(build/'CompilerRejected.olean'),str(bad)])
    env=dict(__import__('os').environ,LEAN_PATH=str(build)+':'+str(root),PATH=str(__import__('pathlib').Path(d.tool('lean')).parent)+':'+__import__('os').environ['PATH'])
    rejected=subprocess.run([d.tool('lean'),'--run','Compiler/Main.lean','CompilerRejected',str(build/'rejected.S'),'rejectedString'],cwd=root,env=env,capture_output=True,text=True)
    if rejected.returncode==0 or 'fixed-width scalar ABI' not in rejected.stderr:
        raise RuntimeError('Unsupported runtime String was not rejected: '+rejected.stdout+rejected.stderr)
    print('PASS: typed wrappers+inline StateM do effects, scalar source→IR→RV64 execution, 100000 tail calls, seven SHA256 boundary vectors through 65536 bytes, oversize no-write, unsupported String rejection')
