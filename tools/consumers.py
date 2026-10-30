"""Explicit original-publisher bootstrap for canonical guest consumer records.

This signs only explicitly supplied metadata/resources. Catalog policy, parser
admission, acquisition authority and collection state remain in Lean guests.
"""
import argparse,hashlib,json,struct,tempfile
from pathlib import Path
import capsule,live,projects,releases
MAGIC=0x31534e4f434c544c

def digest(raw):return hashlib.sha256(raw).digest()
def identity(value):
 if isinstance(value,bytes) and len(value)==32:return value
 if isinstance(value,str) and len(value)==64:
  try:return bytes.fromhex(value)
  except ValueError:pass
 raise ValueError('explicit exact32-byte identity required')

def create(*,key,project,collection,item,edition,title,resource,facet='media',sequence=1,edition_version=1,supersedes=None,total_bytes=None,frames=0,channels=0,license_id=1,executable=None,limitations=1,publication_id=None):
 resource=bytes(resource);game=facet=='game'
 if facet not in ('media','game'):raise ValueError('supported facet is media or game')
 if not 1<=sequence<=0xffffffff or not 1<=edition_version<=0xffffffff:raise ValueError('bounded nonzero sequence and edition version required')
 try:title=title.encode('ascii')
 except UnicodeEncodeError as error:raise ValueError('v1 title supports printable ASCII') from error
 if not 1<=len(title)<=64 or any(c<32 or c>126 for c in title):raise ValueError('bounded printable title required')
 if license_id not in (1,2) or not 0<=limitations<=15:raise ValueError('unsupported license or limitations declaration')
 modulus=capsule.modulus(key);publication=identity(publication_id) if publication_id is not None else releases.project(project)
 if game:
  if executable is None:raise ValueError('game requires exact signed executable release')
  info=releases.inspect(bytes(executable),modulus)
  if publication_id is None:publication=bytes.fromhex(info['project_id'])
  if bytes.fromhex(info['project_id'])!=publication:raise ValueError('game consumer publication differs from executable project')
  if not 112<=len(resource)<=448:raise ValueError('bounded selected level-pack resource required')
  content=digest(resource);total_bytes=info['size'];frames=channels=0
 else:
  if executable is not None or len(resource)!=256:raise ValueError('media requires exact ContentManifest-v1 and no executable')
  q=lambda n:struct.unpack_from('<Q',resource,n)[0]
  if q(0)!=0x31544e434d544c or q(8) not in (1,2) or q(16)!=4096 or q(40)!=1:raise ValueError('supported PCM content manifest required')
  total_bytes=q(24);content=resource[64:96]
  if not 1<=frames<=(3145728 if q(8)==1 else 33554432) or channels not in (1,2):raise ValueError('explicit measurable PCM duration/channels required')
 if not 1<=total_bytes<=67108864:raise ValueError('declared bytes exceed profile')
 raw=bytearray(512)
 for offset,value in {0:MAGIC,8:2 if not game and q(8)==2 else 1,16:2 if game else 1,24:2 if game else 1,288:sequence,296:edition_version,336:len(title),408:total_bytes,416:frames,424:channels,432:0 if game else 48000,440:0 if game else 16,448:license_id,456:1,464:limitations,472:3,480:1 if game else 0}.items():struct.pack_into('<Q',raw,offset,value)
 for offset,value in [(32,publication),(64,digest(modulus)),(96,identity(collection)),(128,identity(item)),(160,identity(edition)),(192,digest(resource)),(224,content),(256,bytes(executable)[160:192] if game else bytes(32)),(304,identity(supersedes) if supersedes else bytes(32))]:raw[offset:offset+32]=value
 raw[344:344+len(title)]=title
 with tempfile.TemporaryDirectory(prefix='lt-consumer-sign-') as temporary:
  path=Path(temporary)/'metadata';path.write_bytes(raw)
  signature=releases.pkg.crypto(['dgst','-sha256','-sign',key,path]).stdout
 if len(signature)!=256:raise ValueError('RSA2048 required')
 return bytes(raw)+signature

def inspect(raw,public=None):
 if len(raw)!=768:raise ValueError('exact ConsumerRelease-v1 record required')
 q=lambda n:struct.unpack_from('<Q',raw,n)[0]
 if q(0)!=MAGIC or q(8) not in (1,2):raise ValueError('unsupported consumer format')
 if public is not None:
  modulus=releases.public_modulus(public);number=int.from_bytes(modulus,'big');signature=int.from_bytes(raw[512:],'big')
  expected=b'\0\1'+b'\xff'*202+b'\0'+bytes.fromhex('3031300d060960864801650304020105000420')+digest(raw[:512])
  if digest(modulus)!=raw[64:96] or signature>=number or pow(signature,65537,number).to_bytes(256,'big')!=expected:raise ValueError('consumer publisher signature invalid')
 return dict(schema=q(8),facet=q(16),format=q(24),publication=raw[32:64].hex(),publisher=raw[64:96].hex(),collection=raw[96:128].hex(),item=raw[128:160].hex(),edition=raw[160:192].hex(),manifest_sha256=raw[192:224].hex(),content_id=raw[224:256].hex(),executable_release=raw[256:288].hex(),sequence=q(288),edition_version=q(296),title=raw[344:344+q(336)].decode('ascii'),total_bytes=q(408),duration_frames=q(416),channels=q(424),sample_rate=q(432),sample_bits=q(440),license=q(448),provider_policy=q(456),limitations=q(464),network_mode=q(472),save_schema=q(480),record_sha256=digest(raw).hex(),signature_verified=public is not None)

def attach(client,raw,resource,*,name,root=None):
 metadata=inspect(raw)
 if digest(resource).hex()!=metadata['manifest_sha256']:raise ValueError('selected resource does not match signed consumer commitment')
 entries=[];parent=0;expected=bytes(32)
 if root is not None:
  parent=client.objects(24,root)[0][1];expected=client.objects(29,root)[1][:32]
  entries=projects.decode_manifest(client.read_object(parent))
 if metadata['facet']==2 and not any(kind==13 for _,kind,_ in entries):raise ValueError('game consumer needs an existing canonical executable Release graph')
 resource_name='content.manifest' if metadata['facet']==1 else 'game.levels'
 entries=[entry for entry in entries if entry[0] not in ('consumer.release',resource_name)]
 for path,content in [('consumer.release',raw),(resource_name,resource)]:
  _,node_id=projects.node(client,content,10);entries.append((path,10,node_id))
 handle,head=projects.node(client,projects.manifest(entries),11,parent)
 fields,_=client.objects(22,handle,root or 0,len(name),data=expected+name.encode('ascii').ljust(64,b'\0'))
 return dict(root=fields[1],head=head,metadata=metadata,metadata_only=True,payload_transferred=False,retained=False)

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
 c=sub.add_parser('create');c.add_argument('--key',type=Path,required=True);c.add_argument('--project',required=True);c.add_argument('--facet',choices=('media','game'),required=True);c.add_argument('--collection',required=True);c.add_argument('--item',required=True);c.add_argument('--edition',required=True);c.add_argument('--title',required=True);c.add_argument('--resource',type=Path,required=True);c.add_argument('--executable',type=Path);c.add_argument('--sequence',type=int,default=1);c.add_argument('--edition-version',type=int,default=1);c.add_argument('--supersedes');c.add_argument('--frames',type=int,default=0);c.add_argument('--channels',type=int,default=0);c.add_argument('--license-id',type=int,choices=(1,2),required=True);c.add_argument('--limitations',type=int,default=1);c.add_argument('--output',type=Path,required=True)
 c=sub.add_parser('inspect');c.add_argument('record',type=Path);c.add_argument('--public',type=Path)
 c=sub.add_parser('import');c.add_argument('--socket',type=Path,required=True);c.add_argument('--record',type=Path,required=True);c.add_argument('--resource',type=Path,required=True);c.add_argument('--name',required=True);c.add_argument('--root',type=int)
 a=p.parse_args(argv)
 if a.command=='create':
  raw=create(key=a.key,project=a.project,facet=a.facet,collection=a.collection,item=a.item,edition=a.edition,title=a.title,resource=a.resource.read_bytes(),executable=a.executable.read_bytes() if a.executable else None,sequence=a.sequence,edition_version=a.edition_version,supersedes=a.supersedes,frames=a.frames,channels=a.channels,license_id=a.license_id,limitations=a.limitations)
  releases.pkg.write_new(a.output,raw);result=inspect(raw)
 elif a.command=='inspect':result=inspect(a.record.read_bytes(),a.public)
 else:
  c=live.Client(a.socket)
  try:result=attach(c,a.record.read_bytes(),a.resource.read_bytes(),name=a.name,root=a.root)
  finally:c.close()
 print(json.dumps(result,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
