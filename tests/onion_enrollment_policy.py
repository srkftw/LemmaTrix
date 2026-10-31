"""Execute native pin approval/revocation with staged public component fixtures.

Certificate verification is covered by the actual multi-guest enrollment run;
these fixtures exercise the live post-verification approval transition itself.
"""
import argparse, hashlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import onion_crypto as native
import driver

SOURCE = '''import Guest.NodeEnrollment
namespace build.OnionEnrollmentPolicy
def staged (identity generation scope t : UInt64) : UInt64 :=
  let p := Guest.NodeEnrollment.candidate
  let t := Guest.LiveSDK.zero p 68 t
  let t := Guest.store64 p 1 t
  let t := Guest.store64 (p+80) 123 t
  let t := Guest.store64 (p+112) scope t
  let t := Guest.store64 (p+144) identity t
  let t := Guest.store64 (p+352) generation t
  let t := Guest.store64 (p+512) 456 t
  Guest.LiveSDK.copy (p+512) (Guest.LiveSDK.command+64) 32 t
def check (t : UInt64) : UInt64 :=
  let p := Guest.NodeEnrollment.peer 0
  let t := Guest.LiveSDK.zero p 68 t
  let t := staged 1 3 321 t
  let t := Guest.NodeEnrollment.approve 0 96 t
  if Guest.load64 Guest.LiveSDK.wire t != 0 || Guest.load64 p t != 1 then 1 else
  let t := staged 2 1 321 t
  let t := Guest.NodeEnrollment.approve 0 96 t
  if Guest.load64 Guest.LiveSDK.wire t != 3 || Guest.load64 (p+144) t != 1 then 2 else
  let t := Guest.NodeEnrollment.dispatch 24 0 64 t
  if Guest.load64 p t != 2 then 3 else
  let t := Guest.NodeEnrollment.approve 0 96 t
  if Guest.load64 Guest.LiveSDK.wire t != 0 || Guest.load64 p t != 1 || Guest.load64 (p+144) t != 2 then 4 else
  let t := staged 2 1 321 t
  let t := Guest.NodeEnrollment.approve 0 96 t
  if Guest.load64 Guest.LiveSDK.wire t != 3 then 5 else
  let t := Guest.NodeEnrollment.dispatch 24 0 64 t
  let t := Guest.NodeEnrollment.approve 0 96 t
  if Guest.load64 Guest.LiveSDK.wire t != 3 || Guest.load64 p t != 2 then 6 else
  let t := staged 2 2 999 t
  let t := Guest.NodeEnrollment.approve 0 96 t
  if Guest.load64 Guest.LiveSDK.wire t != 3 then 7 else
  let t := staged 2 2 321 t
  let t := Guest.store64 (Guest.LiveSDK.command+64) 457 t
  let t := Guest.NodeEnrollment.approve 0 96 t
  if Guest.load64 Guest.LiveSDK.wire t != 2 || Guest.load64 p t != 2 then 8 else
  let t := staged 2 2 321 t
  let t := Guest.NodeEnrollment.approve 0 96 t
  if Guest.load64 Guest.LiveSDK.wire t != 0 || Guest.load64 p t != 1 || Guest.load64 (p+352) t != 2 then 9 else
  0
end build.OnionEnrollmentPolicy
'''

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--backend', action='append', choices=('qemu', 'x86_64', 'aarch64'))
    a = p.parse_args()
    native.B = driver.ROOT/'build/onion-enrollment-policy'
    for name in ('NodeEnrollmentPolicy', 'NodeEnrollment'):
        driver.lean(['-o', f'Guest/{name}.olean', f'Guest/{name}.lean'])
    binary = native.build(SOURCE, 'OnionEnrollmentPolicy')
    report = dict(schema=1, profile='Native staged pin approval and explicit revoked replacement',
                  image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  checks=[native.execute(binary, b) for b in a.backend or ['qemu']],
                  checks_executed=['active identity substitution denied',
                                   'explicit revoke permits separately approved new identity',
                                   'same-identity stale generation denied before and after revoke',
                                   'same-identity federation/scope substitution denied',
                                   'changed staged fingerprint denied',
                                   'same-identity newer scoped generation accepted'],
                  fixture_scope='Synthetic staged public values; no operational private keys. Actual signature verification and enrollment execute in separate multi-guest evidence.')
    (native.B/'evidence.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
