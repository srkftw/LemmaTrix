"""Execute RFC 8439 section 2.8.2 and authenticate-before-release checks in RV64 guest code."""

def check(d):
    root, build=d.ROOT,d.BUILD;build.mkdir(exist_ok=True)
    d.lean(['-o','Guest/Primitives.olean','Guest/Primitives.lean'])
    d.lean(['-o','Guest/VaultCrypto.olean','Guest/VaultCrypto.lean'])
    d.lean(['--run','Compiler/Main.lean','Guest.VaultCrypto',str(build/'aead-check.S'),'Guest.VaultCrypto.encrypt','Guest.VaultCrypto.decrypt'])
    key=bytes(range(128,160));nonce=bytes.fromhex('070000004041424344454647');aad=bytes.fromhex('50515253c0c1c2c3c4c5c6c7')
    msg=b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    expected=bytes.fromhex('d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691')
    ro=[]
    for name,data in [('key',key),('nonce',nonce),('aad',aad),('message',msg)]:
        p=build/f'aead-{name}.bin';p.write_bytes(data);ro.extend([name+':',f'.incbin "build/{p.name}"','.balign 8'])
    args=lambda fn,inp,out: f'''  la a0, key
  la a1, nonce
  la a2, aad
  li a3, {len(aad)}
  {inp}
  li a5, {len(msg)}
  li a6, {out}
  li a7, 0
  call lt_Guest_VaultCrypto_{fn}
'''
    startup='''.option norvc
.option norelax
.section .text.start,"ax"
.global _start
_start:
  li sp, 0x80f00000
  li t0, -1
  csrw pmpaddr0, t0
  li t0, 15
  csrw pmpcfg0, t0
  li t0, 0x80100000
  li t1, 0x20040401
  sd t1, 0(t0)
  li t1, 0x200000cf
  sd t1, 16(t0)
  li t0, 0x80101000
  li t1, 0x201800cf
  sd t1, 24(t0)
  li t0, 0x8000000000080100
  csrw satp, t0
  sfence.vma zero, zero
  li t0, 0x800
  csrw mstatus, t0
  la t0, test_start
  csrw mepc, t0
  mret
test_start:
'''+args('encrypt','la a4, message','0x80640000')+f'''  call print_word
  li a0, 0x80640000
  li a1, {len(expected)}
  call print_bytes
'''+args('decrypt','li a4, 0x80640000','0x80650000')+f'''  call print_word
  li a0, 0x80650000
  li a1, {len(msg)}
  call print_bytes
  li t0, {0x80640000+len(msg)}
  lbu t1, 0(t0)
  xori t1, t1, 1
  sb t1, 0(t0)
  li t0, 0x80650000
  li t1, 90
  sb t1, 0(t0)
'''+args('decrypt','li a4, 0x80640000','0x80650000')+'''  call print_word
  li t0, 0x80650000
  lbu a0, 0(t0)
  call print_word
  li a0, 0
  call lt_finish
print_bytes:
  addi sp, sp, -32
  sd ra, 24(sp)
  sd s0, 16(sp)
  sd s1, 8(sp)
  mv s0, a0
  add s1, a0, a1
1:
  beq s0, s1, 2f
  lbu a0, 0(s0)
  li a1, 2
  call print_digits
  addi s0, s0, 1
  j 1b
2:
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
3:
  addi a1, a1, -1
  slli t0, a1, 2
  srl t1, a0, t0
  andi t1, t1, 15
  li t0, 10
  bltu t1, t0, 4f
  addi t1, t1, 87
  j 5f
4:
  addi t1, t1, 48
5:
  sb t1, 0(t5)
  bnez a1, 3b
  ret
.section .rodata,"a"
.balign 8
'''+ '\n'.join(ro)+'\n'
    # The low service-private scratch pages are mapped to RAM while this standalone
    # supervisor harness invokes the exact service crypto code.
    startup=startup.replace('li t0, 0x10000000','li t0, 0x10000000')
    # UART must be supervisor mapped too.
    startup=startup.replace('  li t0, 0x8000000000080100','  li t1, 0x40000cf\n  sd t1, 1024(t0)\n  li t0, 0x8000000000080100')
    # The finisher uses MMIO 0x100000, covered by an additional low superpage.
    startup=startup.replace('  li t1, 0x201800cf','  li t1, 0xcf\n  sd t1, 0(t0)\n  li t1, 0x201800cf')
    (build/'aead-start.S').write_text(startup)
    objs=[]
    for i,p in enumerate([build/'aead-check.S',build/'aead-start.S',root/'runtime/primitives.S']):
        o=build/f'aead-check.{i}.o';d.asm(p,o);objs.append(o)
    elf=build/'aead-check.elf'
    d.run([d.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',root/'Compiler/check.ld',*objs,'-o',elf])
    result=d.run([d.tool('qemu-system-riscv64'),'-M','virt','-m','16M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',elf],timeout=20,capture_output=True,text=True)
    (build/'aead-check.log').write_text(result.stdout+result.stderr)
    want=['0000000000000000',expected.hex(),'0000000000000000',msg.hex(),'ffffffffffffffff','000000000000005a']
    if result.stdout.splitlines()!=want:raise RuntimeError('AEAD guest mismatch: expected '+repr(want)+' actual '+repr(result.stdout))
    print('PASS: RFC8439 ChaCha20-Poly1305 ciphertext+tag, authenticated decryption, tamperedtag rejected before plaintext release')


def reference(key,nonce,aad,message):
    """Separate byte-oriented RFC algorithm; Python integers handle Poly1305 modulo p."""
    import struct
    def block(counter):
        initial=list(struct.unpack('<4I',b'expand 32-byte k'))+list(struct.unpack('<8I',key))+[counter]+list(struct.unpack('<3I',nonce))
        state=initial[:]
        def qr(a,b,c,d):
            def rotate(x,n):return ((x<<n)|(x>>(32-n)))&0xffffffff
            state[a]=(state[a]+state[b])&0xffffffff;state[d]=rotate(state[d]^state[a],16)
            state[c]=(state[c]+state[d])&0xffffffff;state[b]=rotate(state[b]^state[c],12)
            state[a]=(state[a]+state[b])&0xffffffff;state[d]=rotate(state[d]^state[a],8)
            state[c]=(state[c]+state[d])&0xffffffff;state[b]=rotate(state[b]^state[c],7)
        for _ in range(10):
            for indices in [(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)]:qr(*indices)
        return struct.pack('<16I',*((a+b)&0xffffffff for a,b in zip(state,initial)))
    cipher=bytearray()
    for offset in range(0,len(message),64):cipher.extend(a^b for a,b in zip(message[offset:offset+64],block(1+offset//64)))
    mac=aad+bytes((-len(aad))%16)+cipher+bytes((-len(cipher))%16)+struct.pack('<QQ',len(aad),len(cipher))
    polykey=block(0)[:32];r=int.from_bytes(polykey[:16],'little')&0x0ffffffc0ffffffc0ffffffc0fffffff;s=int.from_bytes(polykey[16:],'little')
    accumulator=0
    for offset in range(0,len(mac),16):accumulator=((accumulator+int.from_bytes(mac[offset:offset+16]+b'\x01','little'))*r)%((1<<130)-5)
    return bytes(cipher)+((accumulator+s)% (1<<128)).to_bytes(16,'little')


def check_boundaries(d):
    root,build=d.ROOT,d.BUILD
    existing=(build/'aead-start.S').read_text()
    startup=existing.split('test_start:')[0]+'test_start:\n'
    routines=existing[existing.index('print_bytes:'):existing.index('.section .rodata')]
    key=bytes(range(32));nonce=bytes(range(12));vectors=[(b'',b''),(bytes(range(17)),bytes(range(17))),(bytes(range(256)),bytes((i*29+7)%256 for i in range(65536)))]
    ro=[];commands=[];want=[]
    for i,(aad,msg) in enumerate(vectors):
        for name,data in [('key',key),('nonce',nonce),('aad',aad),('message',msg)]:
            p=build/f'aead-boundary-{i}-{name}.bin';p.write_bytes(data);ro.extend([f'{name}_{i}:',f'.incbin "build/{p.name}"','.balign 8'])
        for operation,input_expr,out in [('encrypt',f'la a4, message_{i}',0x80640000),('decrypt','li a4, 0x80640000',0x80660000)]:
            commands.extend([f'  la a0, key_{i}',f'  la a1, nonce_{i}',f'  la a2, aad_{i}',f'  li a3, {len(aad)}','  '+input_expr,f'  li a5, {len(msg)}',f'  li a6, {out}','  li a7, 0',f'  call lt_Guest_VaultCrypto_{operation}','  call print_word',f'  li a0, {out}',f'  li a1, {len(msg)+16 if operation=="encrypt" else len(msg)}','  call print_bytes'])
            want.extend(['0000000000000000',(reference(key,nonce,aad,msg) if operation=='encrypt' else msg).hex()])
    # Both public bounds must reject before touching even the first output byte.
    for alen,length in [(0,65537),(257,0)]:
        commands.extend(['  li t0, 0x80640000','  li t1, 90','  sb t1, 0(t0)','  la a0, key_0','  la a1, nonce_0','  la a2, aad_0',f'  li a3, {alen}','  la a4, message_0',f'  li a5, {length}','  li a6, 0x80640000','  li a7, 0','  call lt_Guest_VaultCrypto_encrypt','  call print_word','  li t0, 0x80640000','  lbu a0, 0(t0)','  call print_word'])
        want.extend(['ffffffffffffffff','000000000000005a'])
    startup+='\n'.join(commands)+'\n  li a0, 0\n  call lt_finish\n'+routines+'.section .rodata,"a"\n.balign 8\n'+'\n'.join(ro)+'\n'
    path=build/'aead-boundary-start.S';path.write_text(startup)
    obj=build/'aead-boundary-start.o';d.asm(path,obj)
    elf=build/'aead-boundary.elf';d.run([d.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',root/'Compiler/check.ld',build/'aead-check.0.o',obj,build/'aead-check.2.o','-o',elf])
    r=d.run([d.tool('qemu-system-riscv64'),'-M','virt','-m','16M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',elf],timeout=30,capture_output=True,text=True)
    (build/'aead-boundary.log').write_text(r.stdout+r.stderr)
    if r.stdout.splitlines()!=want:raise RuntimeError('AEAD boundary check mismatch (see build/aead-boundary.log)')
    print('PASS: AEAD empty/17-byte/65536-byte messages, AAD0/17/256, independent integer oracle; oversize no-write rejection')
