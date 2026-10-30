"""Publisher-owned RSA release envelopes for the live Lean guest."""
import argparse, hashlib, json, re, struct, sys, tempfile
from pathlib import Path
try:
    from . import capsule
    from . import packaging as pkg
except ImportError:
    import capsule
    import packaging as pkg
MAGIC=0x3253454c544c
HEADER=512
PREFIX=768
RIGHTS={'object.read':1,'object.create':2,'object.revise':4,'object.share':8,'object.revoke':16,'object.enumerate':32,'object.export':64,'console.write':128,'display.surface':256,'input.focus':512,'network.broker':1024,'server.store':2048,'audio.output':4096}
def digest(data):return hashlib.sha256(data).digest()
def project(name):
    if not re.fullmatch('[a-z0-9][a-z0-9._-]{0,47}',name):raise ValueError('project must be1..48 lowercase ASCII name characters')
    return digest(name.encode())
def publication(logical_project_id,publisher_key_id):
    if not all(isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) for value in (logical_project_id,publisher_key_id)):raise ValueError('canonical logical Project and publisher key IDs required')
    return digest(b'LT-PUBLICATION-3\0'+bytes.fromhex(logical_project_id)+bytes.fromhex(publisher_key_id))

def _require(condition,message):
    if not condition:raise ValueError(message)

def public_modulus(path):
    """Load a public PEM key, or an explicit exact256-byte modulus, never a default identity."""
    raw=Path(path).read_bytes()
    if len(raw)==256 and not raw.startswith(b'-----'):return raw
    der=pkg.crypto(['pkey','-pubin','-in',path,'-pubout','-outform','DER']).stdout
    tag,sequence,end=capsule._tlv(der)
    _require(tag==0x30 and end==len(der),'invalid public SubjectPublicKeyInfo')
    tag,algorithm,cursor=capsule._tlv(sequence)
    _require(tag==0x30 and algorithm==bytes.fromhex('06092a864886f70d0101010500'),'RSA public key required')
    tag,bits,end=capsule._tlv(sequence,cursor)
    _require(tag==3 and end==len(sequence) and bits[:1]==b'\0','invalid RSA public bitstring')
    tag,public,end=capsule._tlv(bits[1:])
    _require(tag==0x30 and end==len(bits)-1,'invalid RSA public key')
    tag,number,cursor=capsule._tlv(public)
    _require(tag==2 and len(number)==257 and number[0]==0 and number[1]&128 and number[-1]&1,'full-width odd RSA2048 modulus required')
    tag,exponent,end=capsule._tlv(public,cursor)
    _require(tag==2 and exponent==b'\x01\0\x01' and end==len(public),'RSA exponent65537 required')
    return number[1:]

def make(binary,name,version,rights,key,sources=(),parent=None,license='NOASSERTION',evidence=(),profile=1,source_base=None,source_records_override=None,logical_project_id=None):
    _require(key is not None,'an explicit publisher signing key is required')
    project_id=project(name)
    _require(profile in (1,2),'supported resource profile is1 or2')
    _require(type(rights) is int and 0<=rights<=8191,'rights must be the known13-bit capability mask')
    _require(re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',version) is not None,'canonical major.minor.patch version required')
    major,minor,patch=map(int,version.split('.'))
    _require(max(major,minor,patch)<=0xffffffff,'bounded semantic version required')
    _require(isinstance(license,str) and bool(license),'explicit license or NOASSERTION required')
    parent_bytes=bytes(32)
    if parent is not None:
        _require(isinstance(parent,str) and re.fullmatch('[0-9a-fA-F]{64}',parent) is not None,'parent must be an exact32-byte release hash')
        parent_bytes=bytes.fromhex(parent);parent=parent_bytes.hex()
    data=Path(binary).read_bytes()
    _require(0<len(data)<=(262144 if profile==2 else 65536) and len(data)%4==0,'executable must be nonempty, aligned and <=65536 bytes')
    modulus=capsule.modulus(key)
    publisher_id=digest(modulus).hex()
    if logical_project_id is not None:project_id=publication(logical_project_id,publisher_id)
    source_records=[]
    for path in sorted(map(Path,sources)):
        source=path.read_bytes()
        relative=path.resolve().relative_to(Path(source_base).resolve()) if source_base else Path(path.name)
        _require(not relative.is_absolute() and '..' not in relative.parts,'portable source-relative name required')
        source_records.append({'path':relative.as_posix(),'sha256':digest(source).hex(),'size':len(source)})
    if source_records_override is not None:
        _require(not sources,'choose source records or paths')
        source_records=source_records_override
        for record in source_records:
            path=Path(record['path'])
            _require(not path.is_absolute() and '..' not in path.parts and type(record['size']) is int and 0<=record['size']<=65536 and re.fullmatch('[0-9a-f]{64}',record['sha256']) is not None,'invalid portable source record')
    source_records=sorted(source_records,key=lambda record:record['path'])
    _require(len({record['path'] for record in source_records})==len(source_records),'duplicate canonical source path')
    source_root=digest(pkg.canonical(source_records))
    manifest={'schema':2,'project':name,'version':version,'rights':rights,'license':license,'sources':source_records,'evidence':list(evidence),'parent':parent,'persistence':'ephemeral; retention only through separately approved Objects broker','network':'explicit broker grants required; encrypted bulk only' if rights&1024 else 'unavailable','dependency_closure':'static; no runtime dependencies','machine':'LT-Dev-v2','runtime':'LT-structured-v3' if profile==2 else 'LT-U64-effects-v2','resource_profile':profile,'limitations':['source-to-binary chain unverified','local authorization is separate from catalog admission']}
    if logical_project_id is not None:
        manifest['schema']=3
        manifest['identity_mapping']={'scheme':3,'logical_project_id':logical_project_id,'publication_id':project_id.hex(),'publisher_key_id':publisher_id}
    header=bytearray(HEADER)
    for offset,value in {0:MAGIC,8:2,16:512,24:len(data),32:(0x200000 if profile==2 else 0x400000),40:2,48:2,56:2,64:rights,72:major,80:minor,88:patch,384:0,392:0,400:profile,408:65536+(2097152 if profile==2 else 0),416:16384,424:len(name),480:65537}.items():struct.pack_into('<Q',header,offset,value)
    header[96:128]=digest(modulus);header[128:160]=project_id;header[192:224]=digest(data)
    header[224:256]=source_root;header[256:288]=digest(pkg.canonical(manifest));header[288:320]=parent_bytes
    header[320:352]=digest(pkg.canonical({'license':license,'distribution_authority':'explicit local author declaration'}))
    header[352:384]=digest(pkg.canonical(list(evidence)));header[432:432+len(name)]=name.encode()
    if logical_project_id is not None:struct.pack_into('<Q',header,488,3)
    identity=digest(header);header[160:192]=identity
    with tempfile.TemporaryDirectory(prefix='lt-release-') as tmp:
        path=Path(tmp)/'header';path.write_bytes(header)
        signature=pkg.crypto(['dgst','-sha256','-sign',key,path]).stdout
    _require(len(signature)==256,'RSA2048 signature required')
    release=bytes(header)+signature+data
    inspect(release,modulus,manifest)
    return release,manifest

def inspect(data,trusted_modulus=None,manifest=None):
    _require(isinstance(data,bytes) and PREFIX<=len(data)<=PREFIX+262144,'invalid envelope size')
    q=lambda n:struct.unpack_from('<Q',data,n)[0]
    _require(q(0)==MAGIC and q(8)==2 and q(16)==HEADER,'incompatible release schema')
    _require(0<q(24)<=(262144 if q(400)==2 else 65536) and q(24)%4==0 and len(data)==PREFIX+q(24),'invalid executable length/alignment')
    _require(q(32)==(0x200000 if q(400)==2 else 0x400000) and all(q(x)==2 for x in (40,48,56)),'incompatible entry/machine/runtime/ABI')
    _require(q(64)<=8191 and all(q(x)<=0xffffffff for x in (72,80,88)),'unknown capabilities or version overflow')
    _require(q(384)==0 and q(392)==0 and q(400) in (1,2) and q(408)==65536+(2097152 if q(400)==2 else 0) and q(416)==16384,'unsupported dependencies or memory profile')
    _require(1<=q(424)<=48 and data[432+q(424):480]==bytes(48-q(424)) and q(480)==65537 and q(488) in (0,3) and data[496:512]==bytes(16),'invalid name/padding/signature profile')
    try:name=data[432:432+q(424)].decode('ascii')
    except UnicodeDecodeError as exc:raise ValueError('project name must be ASCII') from exc
    if q(488)==0:_require(project(name)==data[128:160],'legacy project identity mismatch')
    header=bytearray(data[:HEADER]);header[160:192]=bytes(32)
    _require(digest(header)==data[160:192],'release identity mismatch')
    _require(digest(data[PREFIX:])==data[192:224],'executable content hash mismatch')
    if trusted_modulus is not None:
        _require(isinstance(trusted_modulus,bytes) and len(trusted_modulus)==256 and trusted_modulus[0]&128 and trusted_modulus[-1]&1,'invalid trusted RSA2048 modulus')
        _require(digest(trusted_modulus)==data[96:128],'publisher key identity mismatch')
        n=int.from_bytes(trusted_modulus,'big');signature=int.from_bytes(data[HEADER:PREFIX],'big')
        _require(signature<n,'RSA signature representative out of range')
        encoded=pow(signature,65537,n).to_bytes(256,'big')
        expected=b'\x00\x01'+b'\xff'*202+b'\x00'+bytes.fromhex('3031300d060960864801650304020105000420')+digest(data[:HEADER])
        _require(encoded==expected,'publisher RSA signature verification failed')
    if manifest is not None:
        _require(isinstance(manifest,dict) and manifest.get('schema')==(3 if q(488)==3 else 2),'invalid manifest schema')
        if q(488)==3:
            mapping=manifest.get('identity_mapping',{})
            _require(mapping.get('scheme')==3 and mapping.get('publisher_key_id')==data[96:128].hex() and mapping.get('publication_id')==data[128:160].hex() and publication(mapping.get('logical_project_id'),mapping.get('publisher_key_id'))==data[128:160],'stable publication identity mapping mismatch')
        _require(digest(pkg.canonical(manifest))==data[256:288],'manifest commitment mismatch')
        _require(manifest.get('project')==name and manifest.get('version')=='.'.join(str(q(x)) for x in (72,80,88)) and manifest.get('rights')==q(64),'manifest identity/capabilities mismatch')
        _require(digest(pkg.canonical(manifest.get('sources')))==data[224:256],'source lineage commitment mismatch')
        _require(digest(pkg.canonical(manifest.get('evidence')))==data[352:384],'evidence commitment mismatch')
        _require(digest(pkg.canonical({'license':manifest.get('license'),'distribution_authority':'explicit local author declaration'}))==data[320:352],'rights metadata commitment mismatch')
        _require((manifest.get('parent') or '00'*32)==data[288:320].hex(),'parent lineage mismatch')
    return {'project':name,'version':'.'.join(str(q(x)) for x in (72,80,88)), 'release_id':data[160:192].hex(),'publisher_key_id':data[96:128].hex(),'project_id':data[128:160].hex(),'rights':q(64),'executable_sha256':data[192:224].hex(),'source_root':data[224:256].hex(),'manifest_root':data[256:288].hex(),'parent':data[288:320].hex(),'size':q(24),'signature_verified':trusted_modulus is not None,'manifest_checked':manifest is not None,'identity_scheme':q(488),'logical_project_id':manifest.get('identity_mapping',{}).get('logical_project_id') if manifest else None}
def main(argv=None):
    p=argparse.ArgumentParser(description='Original-publisher RSA envelopes (no intermediary signing)')
    sub=p.add_subparsers(dest='cmd',required=True)
    k=sub.add_parser('keygen');k.add_argument('--private',type=Path,required=True);k.add_argument('--public',type=Path,required=True)
    c=sub.add_parser('create');c.add_argument('--binary',required=True,type=Path);c.add_argument('--project',required=True);c.add_argument('--version',required=True);c.add_argument('--right',action='append',choices=RIGHTS,default=[]);c.add_argument('--sign-key',type=Path,required=True);c.add_argument('--source',type=Path,action='append',default=[]);c.add_argument('--profile',type=int,choices=(1,2),default=1);c.add_argument('--source-base',type=Path);c.add_argument('--logical-project-id');c.add_argument('--parent');c.add_argument('--license',default='NOASSERTION');c.add_argument('--output',type=Path,required=True)
    i=sub.add_parser('inspect');i.add_argument('release',type=Path);i.add_argument('--public-key',type=Path);i.add_argument('--manifest',type=Path)
    args=p.parse_args(argv)
    if args.cmd=='keygen':print(capsule.generate_key(args.private,args.public));return 0
    if args.cmd=='inspect':
        manifest=args.manifest or Path(str(args.release)+'.manifest.json')
        metadata=json.loads(manifest.read_text()) if manifest.exists() else None
        if args.manifest and metadata is None:raise ValueError('selected manifest does not exist')
        modulus=public_modulus(args.public_key) if args.public_key else None
        print(json.dumps(inspect(args.release.read_bytes(),modulus,metadata),indent=2));return 0
    mask=sum(RIGHTS[r] for r in set(args.right))
    data,manifest=make(args.binary,args.project,args.version,mask,args.sign_key,args.source,args.parent,args.license,profile=args.profile,source_base=args.source_base,logical_project_id=args.logical_project_id)
    pkg.write_new(args.output,data);pkg.write_new(Path(str(args.output)+'.manifest.json'),pkg.canonical(manifest))
    print(json.dumps(inspect(data),indent=2));return 0
if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError,RuntimeError,OSError) as error:
        print('release:',error,file=sys.stderr);sys.exit(1)
