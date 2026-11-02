"""Actual native Registry policy/signature over an exported native release.

This focused component journey uses normal authorized graph import and operator
interfaces. It does not claim network discovery or second-user installation.
"""
import argparse, base64, hashlib, json, os, struct, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import federation, forge, identity, live_acceptance as accept, live_build, projects, releases

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',type=Path,required=True);p.add_argument('--archive',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--backend',choices=('qemu','x86_64','aarch64'),default='qemu')
    p.add_argument('--policy',choices=('portable','restricted','consumer'),default='portable')
    p.add_argument('--allowed-rights',type=int);a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False);os.environ['LT_GUEST_IMAGE']=str(a.image.resolve())
    key=ROOT/'tests/keys/development-rsa.pem';public=ROOT/'tests/keys/development-rsa-public.pem'
    def package(module,name,rights):
        binary=live_build.app('Guest.'+module,'Guest.'+module+'.main',name,2)
        raw,_=releases.make(binary,name,'1.0.0',rights,key,profile=2)
        path=a.output/(name+'.ltrel');path.write_bytes(raw);return path,releases.inspect(raw)
    signer_path,signer_info=package('Identity','native-federation-identity',0)
    registry_path,registry_info=package('Registry','native-federation-registry',2175)
    doc=json.loads(a.archive.read_bytes());nodes=[dict(n,payload=base64.b64decode(n['payload'],validate=True))for n in doc['nodes']]
    release=next(n['payload']for n in nodes if n['kind']==13)
    count=struct.unpack_from('<Q',release,16)[0];header=release[32+count*128+64:]
    publisher=header[576:608];publication=header[128:160]
    record=dict(schema=1,scope=__doc__,backend=a.backend,image=hashlib.sha256(a.image.read_bytes()).hexdigest(),checks=[],result='running')
    began=time.monotonic()
    def passed(label,**fields):
        record['checks'].append(dict(check=label,result='pass',**fields));record['elapsed_seconds']=time.monotonic()-began
        (a.output/'execution.json').write_text(json.dumps(record,indent=2)+'\n');print('PASS',label,flush=True)
    try:
        with accept.Session(a.backend,a.output/'operator')as c:
            service=identity.start(c,signer_path,public)
            c.request(10,registry_path.read_bytes()[128:160]+releases.public_modulus(public))
            slot,_=c.install(registry_path)
            registry=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',slot)),8)[0]
            configured=federation.configure_native(c,registry,a.policy,service['release'],registry_info['release_id'],allowed_rights=a.allowed_rights)
            passed('independent guest-owned finite Registry signing authority',configuration=configured)
            root=projects.import_records(c,doc['selected'],nodes)[0]['cap']
            federation.call(c,registry,3,data=publication+publisher)
            delegated=c.objects(27,root,registry,25)[0][1]
            queued,_=federation.call(c,registry,2,h=delegated)
            deadline=time.monotonic()+120
            while True:
                state,descriptor=federation.call(c,registry,7,h=queued[2])
                if state[1]==2:break
                if state[1]>2:raise AssertionError(('native signing unavailable',state,federation.call(c,registry,14)[0]))
                if time.monotonic()>deadline:raise TimeoutError('native evaluated admission did not complete')
                time.sleep(.05)
            assert len(descriptor)==768 and struct.unpack_from('<Q',descriptor,8)[0]==2
            assert descriptor[128:160]==header[160:192] and descriptor[288:320].hex()==configured['federation_id']
            assert descriptor[608:]==bytes(160)
            # Verification is a fresh actual native Registry operation; no host
            # publisher or federation private key has ever been provisioned.
            verified,_=federation.call(c,registry,11,data=descriptor+descriptor[320:352])
            result=forge.admission_record(descriptor)
            passed('actual graph policy evaluation and native signed decision verification',decision=result,verified_classification=verified[1])
            damaged=bytearray(descriptor);damaged[40]^=1
            try:federation.call(c,registry,11,data=bytes(damaged)+descriptor[320:352])
            except ValueError:pass
            else:raise AssertionError('tampered admission decision verified')
            passed('changed decision material fails native verification')
        record['result']='pass'
    except BaseException as error:
        record.update(result='failure',error=repr(error));raise
    finally:
        record['elapsed_seconds']=time.monotonic()-began;(a.output/'execution.json').write_text(json.dumps(record,indent=2)+'\n')
    return 0

if __name__=='__main__':raise SystemExit(main())
