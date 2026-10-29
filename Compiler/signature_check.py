"""Guest RSA verification crosschecks against OpenSSL and strict RFC 8017 encoding."""
import hashlib, time

def check(d):
    from tools import capsule
    root, build = d.ROOT, d.BUILD
    build.mkdir(exist_ok=True)
    for module in ['Primitives','SHA256','Signature']:
        d.lean(['-o',f'Guest/{module}.olean',f'Guest/{module}.lean'])
    d.lean(['--run','Compiler/Main.lean','Guest.Signature',str(build/'signature-check.S'),'Guest.Signature.verify'])
    message=b'LemmaTrix independent guest RSA-2048 verification fixture\n'
    message_file=build/'signature-message.bin';message_file.write_bytes(message)
    key=capsule.development_key()
    modulus=capsule.modulus(key)
    signature=capsule.pkg.crypto(['dgst','-sha256','-sign',key,message_file]).stdout
    tampered=bytearray(signature);tampered[127]^=1
    digest_info=bytes.fromhex('3031300d060960864801650304020105000420')+hashlib.sha256(message).digest()
    encoded=b'\x00\x01'+b'\xff'*202+b'\x00'+digest_info
    malformed=bytearray(encoded);malformed[100]=0
    (build/'signature-malformed-em.bin').write_bytes(malformed)
    malformed_signature=capsule.pkg.crypto(['pkeyutl','-decrypt','-inkey',key,'-pkeyopt','rsa_padding_mode:none','-in',build/'signature-malformed-em.bin']).stdout
    assert pow(int.from_bytes(malformed_signature,'big'),65537,int.from_bytes(modulus,'big')).to_bytes(256,'big')==malformed
    cases=[('valid',message,signature,modulus,1),('message',message+b'!',signature,modulus,0),
           ('signature',message,bytes(tampered),modulus,0),('range',message,modulus,modulus,0),
           ('padding',message,malformed_signature,modulus,0)]
    commands=[];rodata=[]
    for label,msg,sig,mod,expected in cases:
        for kind,data in [('msg',msg),('sig',sig),('mod',mod)]:
            p=build/f'signature-{label}-{kind}.bin';p.write_bytes(data)
            rodata.extend([f'{label}_{kind}:',f'.incbin "build/{p.name}"','.balign 8'])
        commands.extend([f'  la a0, {label}_msg',f'  li a1, {len(msg)}',f'  la a2, {label}_sig',
                         f'  la a3, {label}_mod','  li a4, 0','  call lt_Guest_Signature_verify',
                         '  addi a0, a0, 48','  li t0, 0x10000000','  sb a0, 0(t0)',
                         '  li t1, 10','  sb t1, 0(t0)'])
    startup='''.option norvc
.option norelax
.section .text.start,"ax"
.global _start
_start:
  li sp, 0x80f00000
'''+ '\n'.join(commands)+'''
  li a0, 0
  call lt_finish
.section .rodata,"a"
.balign 8
'''+ '\n'.join(rodata)+'\n'
    (build/'signature-start.S').write_text(startup)
    objects=[]
    for i,src in enumerate([build/'signature-check.S',build/'signature-start.S',root/'runtime/primitives.S']):
        obj=build/f'signature-check.{i}.o';d.asm(src,obj);objects.append(obj)
    elf=build/'signature-check.elf'
    d.run([d.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',root/'Compiler/check.ld',*objects,'-o',elf])
    started=time.monotonic()
    result=d.run([d.tool('qemu-system-riscv64'),'-M','virt','-m','16M','-smp','1','-bios','none',
                  '-nographic','-monitor','none','-kernel',elf],timeout=60,capture_output=True,text=True)
    (build/'signature-check.log').write_text(result.stdout+result.stderr)
    expected=[str(c[-1]) for c in cases]
    if result.stdout.splitlines()!=expected:
        raise RuntimeError('Guest RSA check mismatch: expected '+repr(expected)+' actual '+repr(result.stdout))
    print(f'PASS: guest RSA2048 valid signature accepted; changed message, changed signature, out-of-range representative and malformed PKCS1 padding rejected ({time.monotonic()-started:.2f}s QEMU)')
