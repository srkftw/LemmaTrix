"""Tor Project's published C/Rust ntor-v3 primitive transcript in compiled RV64.
The application profile accepts canonical empty extension lists; this component
check uses Tor's published opaque test messages to verify its core transcript.
"""
import argparse,hashlib,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import onion_crypto as native
from network_crypto import store_bytes
import driver
SOURCE_URL='https://tpo.pages.torproject.net/core/doc/rust/src/tor_proto/crypto/handshake/ntor_v3.rs.html#819-899'
FIRST=bytes.fromhex('9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2f8307a2bc1870b00b828bb74dbb8fd88e632a6375ab3bcd1ae706aaa8b6cdd1d252fe9ae91264c91d4ecb8501f79d0387e34ad8ca0f7c995184f7d11d5da4f463bebd9151fd3b47c180abc9e044d53565f04d82bbb3bebed3d06cea65db8be9c72b68cd461942088502f67')
SECOND=bytes.fromhex('4bf4814326fdab45ad5184f5518bd7fae25dc59374062698201a50a22954246d2fc5f8773ca824542bc6cf6f57c7c29bbf4e5476461ab130c5b18ab0a91276651202c3e1e87c0d32054c')
KEYS=bytes.fromhex('9c19b631fd94ed86a817e01f6c80b0743a43f5faebd39cfaa8b00fa8bcc65c3bfeaa403d91acbd68a821bf6ee8504602b094a254392a07737d5662768c7a9fb1b2814bb34780eaee6e867c773e28c212ead563e98a1cd5d5b4576f5ee61c59bde025ff2851bb19b721421694f263818e3531e43a9e4e3e2c661e2ad547d8984caa28ebecd3e4525452299be26b9185a20a90ce1eac20a91f2832d731b54502b09749b5a2a2949292f8cfcbeffb790c7790ed935a9d251e7e336148ea83b063a5618fcff674a44581585fd22077ca0e52c59a24347a38d1a1ceebddbf238541f226b8f88d0fb9c07a1bcd2ea764bbbb5dacdaf5312a14c0b9e4f06309b0333b4a')
PRIVATE=bytes.fromhex('b825a3719147bcbe5fb1d0b0fcb9c09e51948048e2e3283d2ab7b45b5ef38b49')

def source():
 s='import Guest.TorNtor\nnamespace build.OnionNtorPublished\ndef check (t : UInt64) : UInt64 :=\n'
 for p,raw in [(0x700000,PRIVATE),(0x701000,FIRST),(0x702000,SECOND),(0x703000,KEYS),(0x704000,b'hello world'),(0x705000,b'Hola Mundo'),(0x706000,b'xyzzy')]:s+=store_bytes(p,raw)+'\n'
 s+='''  let st : UInt64 := 0x709000
  let args : UInt64 := 0x708000
  let s : UInt64 := 0x6c0000
  let t := Guest.TorNtor.copy 0x700000 st 32 t
  let t := Guest.TorNtor.copy 0x701000 (st+96) 32 t
  let t := Guest.TorNtor.copy 0x701020 (st+64) 32 t
  let t := Guest.TorNtor.copy 0x701040 (st+32) 32 t
  let t := Guest.TorNtor.copy 0x70106b (st+160) 32 t
  let t := Guest.store64 (args+24) 0x706000 t
  let t := Guest.store64 (args+32) 5 t
  let t := Guest.Noise25519.x25519 st (st+64) (st+128) t
  let t := Guest.TorNtor.phase1 s st args t
  let t := Guest.AES.init (s+4096) (s+2048) 32 t
  let t := Guest.AES.crypt (s+4096) 0x704000 0x70a000 11 t
  if Guest.TorNtor.difference 0x70a000 0x701060 11 0 t != 0 then 1 else
  let t := Guest.TorNtor.messageMac s st 0x70a000 11 0x70a100 t
  if Guest.TorNtor.difference 0x70a100 (st+160) 32 0 t != 0 then 2 else
  let t := Guest.Noise25519.x25519 st 0x702000 (s+2304) t
  let t := Guest.TorNtor.finalKeys s st 0x702000 args t
  if Guest.TorNtor.difference (s+2080) 0x703000 92 0 t != 0 then 3 else
  let t := Guest.TorNtor.authenticator s st 0x702000 0x702040 10 0x70a100 t
  if Guest.TorNtor.difference 0x70a100 0x702020 32 0 t != 0 then 4 else
  let t := Guest.AES.init (s+4096) (s+2048) 32 t
  let t := Guest.AES.crypt (s+4096) 0x702040 0x70a000 10 t
  if Guest.TorNtor.difference 0x70a000 0x705000 10 0 t != 0 then 5 else
  Guest.TorNtor.clear (s) t
end build.OnionNtorPublished
''';return s

def main():
 p=argparse.ArgumentParser();p.add_argument('--backend',action='append',choices=('qemu','x86_64','aarch64'));a=p.parse_args();native.B=driver.ROOT/'build/onion-ntor-published';driver.lean(['-o','Guest/TorNtor.olean','Guest/TorNtor.lean']);binary=native.build(source(),'OnionNtorPublished');report=dict(schema=1,profile='ntor-v3 published Tor Project primitive transcript',source=SOURCE_URL,image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),checks=[native.execute(binary,b) for b in a.backend or ['qemu']],checks_executed=['published phase1 encrypted client message andMAC','published final first92 keystreambytes','published serverAUTH','published decrypted servermessage'],limits='Primitive transcript only; opaque fixture messages bypass selected application extension parser, no Tor interoperability claim. All private scalars are published fixtures.');(native.B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
