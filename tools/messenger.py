"""Install and invoke native Messenger owners; host handles public adapter bytes."""
from __future__ import annotations
import argparse,hashlib,json,struct,time,os,resource
from pathlib import Path
import live,nodes,releases,server_store

# Mailbox-v1 maxima, encoded by the native MailboxSDK too. Per-recipient
# enrollment can only tighten these bounds. Contract1 is bounded retention,
# never a civil-time expiry promise.
MAILBOX_TERMS=struct.pack('<8Q',1,1,8388608,65536,8192,16,8,1)
MAILBOX_TERMS_HASH=hashlib.sha256(MAILBOX_TERMS).digest()

def launcher(client):
    raw=client.request(2)
    return next(struct.unpack_from('<Q',raw,i)[0] for i in range(0,len(raw),32) if struct.unpack_from('<Q',raw,i)[0]&255==1)

def bind(client,role,service,caller,operation,sid,cid=bytes(32),prior=0):
    raw=client.request(171,struct.pack('<6Q',1,role,service,caller,operation,prior)+sid+cid+bytes(16))
    return struct.unpack('<Q',raw)[0]

def endpoint(client,role,operation):
    who=struct.unpack('<Q',client.request(172,struct.pack('<2Q',role,operation)))[0]
    if who==2**64-1:raise ValueError('no current exact native service binding')
    return who

def invoke(client,role,operation,h=0,a=0,b=0,c=0,data=b'',timeout=600,allowed_status=(0,)):
    who=endpoint(client,role,operation)
    request=struct.pack('<Q8Q',who,operation,h,a,b,c,0,0,1)+data
    token=struct.unpack('<Q',client.request(175,request))[0]
    until=time.monotonic()+timeout
    try:
        while time.monotonic()<until:
            raw=client.request(176,struct.pack('<Q',token))
            if len(raw)==8:time.sleep(.05);continue
            f=struct.unpack_from('<8Q',raw)
            if f[0] not in allowed_status:raise ValueError(f'native service status{f[0]}')
            return f,raw[64:]
        raise TimeoutError('bounded native completion wait; operation remains separately committed if already accepted')
    except BaseException:
        try:client.request(177,struct.pack('<Q',token))
        except (ValueError,OSError,EOFError):pass
        raise

def install(client,path,public,rights):
    raw=path.read_bytes();info=releases.inspect(raw)
    if info['rights']!=rights or struct.unpack_from('<Q',raw,400)[0]!=2:raise ValueError('wrong exact package rights or profile')
    service=nodes.start_package(client,nodes.approved_package(path,public,info['release_id'],rights),raw)
    return service,bytes.fromhex(info['release_id'])

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--socket',type=Path)
    sub=p.add_subparsers(dest='command',required=True)
    q=sub.add_parser('package');q.add_argument('--publisher-private',type=Path,required=True);q.add_argument('--output',type=Path,required=True)
    q=sub.add_parser('vault-init');q.add_argument('image',type=Path)
    q=sub.add_parser('start');q.add_argument('--owner',type=Path,required=True);q.add_argument('--public',type=Path,required=True);q.add_argument('--ui',type=Path);q.add_argument('--delivery',type=Path)
    q=sub.add_parser('certify-contact');q.add_argument('--identity-release',type=Path,required=True);q.add_argument('--public',type=Path,required=True);q.add_argument('--scope',required=True);q.add_argument('--output',type=Path,required=True)
    q=sub.add_parser('delivery-start');q.add_argument('--release',type=Path,required=True);q.add_argument('--public',type=Path,required=True);q.add_argument('--ui',type=int,required=True);q.add_argument('--ui-release',type=Path,required=True);q.add_argument('--owner-release',type=Path,required=True)
    q=sub.add_parser('create');q.add_argument('--federation',required=True);q.add_argument('--output',type=Path,required=True)
    q=sub.add_parser('configure');q.add_argument('--ui',type=int,required=True);q.add_argument('--federation',required=True)
    q=sub.add_parser('export');q.add_argument('--output',type=Path,required=True);profile=q.add_mutually_exclusive_group();profile.add_argument('--extended',action='store_true');profile.add_argument('--certified',action='store_true')
    q=sub.add_parser('mailbox-authority');q.add_argument('--output',type=Path,required=True)
    q=sub.add_parser('select-mailbox');q.add_argument('--fingerprint',required=True)
    sub.add_parser('status')
    q=sub.add_parser('authorize-retention');q.add_argument('--owner',type=int,required=True)
    q=sub.add_parser('unlock');q.add_argument('--key',type=Path,required=True);q.add_argument('--mode',choices=['create','recover','history-import'],required=True);q.add_argument('--retain-history',action='store_true')
    for name in ['lock','forget']:sub.add_parser(name)
    q=sub.add_parser('stage-contact');q.add_argument('--ui',type=int,required=True);q.add_argument('invitation',type=Path)
    q=sub.add_parser('receive-ciphertext');q.add_argument('ciphertext',type=Path)
    q=sub.add_parser('inbox');q.add_argument('--cursor',type=int,default=0)
    q=sub.add_parser('mailbox-start');q.add_argument('--release',type=Path,required=True);q.add_argument('--public',type=Path,required=True);q.add_argument('--namespace',required=True)
    q=sub.add_parser('mailbox-enroll');q.add_argument('authority_hashes',type=Path);q.add_argument('--bytes',type=int,default=1048576);q.add_argument('--attempts',type=int,default=256)
    q=sub.add_parser('mailbox-inventory');q.add_argument('--index',type=int,default=0)
    q=sub.add_parser('mailbox-receipts');q.add_argument('--identity-release',type=Path,required=True);q.add_argument('--mailbox-release',type=Path,required=True);q.add_argument('--node-key',type=int,required=True);q.add_argument('--receipt-key',type=int);q.add_argument('--authorizations',type=int,default=4096);q.add_argument('--output',type=Path,required=True)
    a=p.parse_args(argv)
    if a.command=='vault-init':
        sectors=5396000;size=sectors*512
        soft,hard=resource.getrlimit(resource.RLIMIT_FSIZE)
        if soft!=resource.RLIM_INFINITY and soft<size and (hard==resource.RLIM_INFINITY or hard>=size):resource.setrlimit(resource.RLIMIT_FSIZE,(size,hard))
        fd=os.open(a.image,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:os.ftruncate(fd,size);os.fsync(fd)
        finally:os.close(fd)
        print(json.dumps(dict(path=str(a.image),sectors=sectors,bytes=size,purpose='new personal backing; prefix reserved for separately initialized Objects',messenger_domain=2,authorized=False,private_keys_created=False),indent=2));return 0
    if a.command=='package':
        import live_build
        a.output.mkdir(parents=True,exist_ok=False)
        items=[]
        for name,module,entry,rights in [('identity','Guest.Identity','main',0),('messenger-session','Guest.MessengerSession','main',0),('messenger','Guest.Messenger','main',799),('messenger-delivery','Guest.MessengerDelivery','main',1024),('mailbox','Guest.Mailbox','main',2048)]:
            binary=live_build.app(module,module+'.'+entry,name,2)
            raw,_=releases.make(binary,name,'0.8.0',rights,a.publisher_private,profile=2,license='NOASSERTION')
            path=a.output/(name+'.ltrel');path.write_bytes(raw)
            items.append(dict(name=name,path=str(path),rights=rights,code_bytes=binary.stat().st_size,code_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),package_sha256=hashlib.sha256(raw).hexdigest(),release_id=releases.inspect(raw)['release_id']))
        report=dict(schema=1,packages=items,publisher='explicit host RSA bootstrap',messaging_private_keys_generated=False)
        (a.output/'packages.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2));return 0
    if a.socket is None:raise ValueError('--socket is required for native service commands')
    client=live.Client(a.socket,timeout=600)
    try:
        if a.command=='start':
            owner,sid=install(client,a.owner,a.public,0);who=launcher(client)
            operations=range(420,436) if not a.ui else (420,421,422,429,431,432,433,434)
            try:
                for op in operations:bind(client,2,owner,who,op,sid)
                ui=None;delivery=None
                if a.ui:
                    ui,uid=install(client,a.ui,a.public,799)
                    for op in range(420,436):bind(client,2,owner,ui,op,sid,uid)
                if a.delivery:
                    if not a.ui:raise ValueError('delivery requires native UI caller')
                    delivery,did=install(client,a.delivery,a.public,1024)
                    for op in (427,428,434):bind(client,2,owner,delivery,op,sid,did)
                    for op in range(460,464):bind(client,4,delivery,ui,op,did,uid)
                    bind(client,4,delivery,who,464,did)
                    invoke(client,4,464,h=owner)
            except BaseException:
                client.request(26,struct.pack('<Q',owner));raise
            result=dict(owner=owner,owner_release=sid.hex(),ui=ui,delivery=delivery,retention='ephemeral until separately authorized and unlocked',route_configured=False)
        elif a.command=='authorize-retention':
            client.request(174,struct.pack('<2Q',a.owner,1));result=dict(domain=2,authorized_owner=a.owner,unlocked=False)
        elif a.command=='certify-contact':
            import identity
            # Admission order intentionally leaves room for three temporary
            # signer grants before the eight coordinator grants fill the32.
            try:
                endpoint(client,4,464)
            except ValueError:pass
            else:raise ValueError('certify the local contact before delivery-start; all32 coordinator/UI bindings are already admitted')
            try:
                identity.endpoint(client,400)
            except ValueError:pass
            else:raise ValueError('an Identity service is already bound; this command requires a separate temporary personal signer')
            _,bundle=invoke(client,2,422)
            if len(bundle)!=256:raise ValueError('create the native messaging device first')
            signer,sid=install(client,a.identity_release,a.public,0)
            try:
                for operation in (400,405,402):identity.bind(client,signer,launcher(client),sid,bytes(32),operation)
                fields,_=identity.invoke(client,400,a=2,data=bundle[192:224]+identity.digest(a.scope));key=fields[1]
                device_generation=struct.unpack_from('<Q',bundle,16)[0]
                subject=bundle[32:64]+bundle[192:224]+bundle[224:256]
                body=struct.pack('<4Q',identity.CONTACT_MAGIC,1,device_generation,1)+bundle[32:64]+bundle[224:256]+hashlib.sha256(subject).digest()
                permit=identity.invoke(client,405,h=key,a=launcher(client),b=1,c=128,data=hashlib.sha256(body).digest())[0][1]
                _,certificate=identity.invoke(client,402,h=permit,data=body)
                invoke(client,2,434,a=26,data=certificate)
                _,invitation=invoke(client,2,434,a=27)
                if len(invitation)!=672:raise ValueError('native bound invitation must be672 bytes')
                a.output.write_bytes(invitation)
                result=dict(public_invitation=str(a.output),bytes=len(invitation),certificate_sha256=hashlib.sha256(certificate).hexdigest(),fingerprint=hashlib.sha256(subject).hexdigest(),private_keys_exported=False,certification_seed_retention='ephemeral; temporary signer is stopped after its public certificate is committed')
            finally:client.request(26,struct.pack('<Q',signer))
        elif a.command=='delivery-start':
            owner=endpoint(client,2,434);who=launcher(client)
            ui_info=releases.inspect(a.ui_release.read_bytes());owner_info=releases.inspect(a.owner_release.read_bytes())
            uid=bytes.fromhex(ui_info['release_id']);owner_sid=bytes.fromhex(owner_info['release_id'])
            if ui_info['rights']!=799 or owner_info['rights']!=0:raise ValueError('exact native Messenger UI799 and rights-zero owner releases required')
            delivery,did=install(client,a.release,a.public,1024)
            try:
                for op in (427,428,434):bind(client,2,owner,delivery,op,owner_sid,did)
                for op in range(460,464):bind(client,4,delivery,a.ui,op,did,uid)
                bind(client,4,delivery,who,464,did)
                invoke(client,4,464,h=owner)
            except BaseException:
                client.request(26,struct.pack('<Q',delivery));raise
            result=dict(owner=owner,ui=a.ui,delivery=delivery,delivery_release=did.hex(),route_configured=False,exact_grant_count=32)
        elif a.command=='unlock':
            key=a.key.read_bytes()
            if len(key)!=32:raise ValueError('explicit Messenger credential must be32 high-entropy bytes')
            f,_=invoke(client,2,432,h=['create','recover','history-import'].index(a.mode),a=int(a.retain_history),data=key)
            result=dict(status=list(f),domain=2)
        elif a.command=='configure':
            import identity
            raw=client.request(150,struct.pack('<Q8Q',a.ui,781,0,0,0,0,0,0,1)+identity.digest(a.federation))
            f=struct.unpack_from('<8Q',raw)
            if f[0]:raise ValueError('native graphical federation configuration denied')
            result=dict(ui=a.ui,federation=a.federation,identity_created=False)
        elif a.command=='mailbox-authority':
            f,raw=invoke(client,2,434,a=10);a.output.write_bytes(raw);result=dict(public_authority=str(a.output),bytes=len(raw))
        elif a.command=='select-mailbox':
            pin=bytes.fromhex(a.fingerprint)
            if len(pin)!=32 or not any(pin):raise ValueError('accepted mailbox fingerprint32 required')
            f,_=invoke(client,2,434,a=13,data=pin);result=dict(selected_mailbox=a.fingerprint,status=list(f))
        elif a.command in ('create','export'):
            data=bytes.fromhex(a.federation) if a.command=='create' else b''
            if a.command=='create' and (len(data)!=32 or not any(data)):raise ValueError('nonzero federation32 required')
            extended=getattr(a,'extended',False);certified=getattr(a,'certified',False)
            f,public=invoke(client,2,434 if extended or certified else 421 if a.command=='create' else 422,a=27 if certified else 12 if extended else 0,data=data)
            a.output.write_bytes(public);result=dict(invitation=str(a.output),bytes=len(public),status=list(f),private_keys_exported=False)
        elif a.command=='stage-contact':
            raw=a.invitation.read_bytes()
            if len(raw) not in (256,320,672):raise ValueError('versioned invitation must be256,320or672bytes')
            response=client.request(150,struct.pack('<Q8Q',a.ui,780,0,0,0,0,0,0,1)+raw)
            result=dict(staged=True,approval='inspect fingerprint and press F5 in native Messenger',status=list(struct.unpack_from('<8Q',response)))
        elif a.command=='mailbox-start':
            owner,sid=install(client,a.release,a.public,2048);who=launcher(client)
            try:
                for op in (440,441):bind(client,3,owner,who,op,sid)
                network_owner=next(row[0] for row in __import__('identity').instances(client) if row[0]&255==6)
                bind(client,3,owner,network_owner,441,sid)
                server_store.call(client,230)
                ns=bytes.fromhex(a.namespace)
                if len(ns)!=32 or not any(ns):raise ValueError('namespace32 required')
                grant=server_store.call(client,231,owner,1,1048576,ns)[0][1]
                f,_=invoke(client,3,440,h=0,a=grant)
            except BaseException:
                client.request(26,struct.pack('<Q',owner));raise
            result=dict(mailbox=owner,release=sid.hex(),namespace=a.namespace,status=list(f))
        elif a.command=='mailbox-enroll':
            raw=a.authority_hashes.read_bytes()
            if len(raw)!=96:raise ValueError('recipient id32,depositHash32,fetchHash32 required')
            f,_=invoke(client,3,440,h=1,a=a.bytes,b=a.attempts,data=raw,allowed_status=(0,6))
            while f[0]==6:
                time.sleep(.05);f,_=invoke(client,3,441,h=4,allowed_status=(0,6))
            result=dict(durably_enrolled=True,status=list(f))
        elif a.command=='mailbox-inventory':
            f,raw=invoke(client,3,440,h=2,a=a.index);result=dict(status=list(f),opaque_record=raw.hex())
        elif a.command=='mailbox-receipts':
            import identity,onion
            if not 1<=a.authorizations<=65536:raise ValueError('finite receipt authorization count must be1..65536')
            service=endpoint(client,3,440);signer=identity.endpoint(client,409)
            signer_release=releases.inspect(a.identity_release.read_bytes());mailbox_release=releases.inspect(a.mailbox_release.read_bytes())
            if signer_release['rights']!=0 or mailbox_release['rights']!=2048:raise ValueError('exact Identity and Mailbox package rights required')
            identity.bind(client,signer,service,bytes.fromhex(signer_release['release_id']),bytes.fromhex(mailbox_release['release_id']),409)
            _,description=onion.call(client,25,h=4);node=description[:480];node_hash=description[480:]
            if len(node)!=480 or len(node_hash)!=32 or struct.unpack_from('<Q',node,176)[0]!=8:raise ValueError('local enrolled mailbox certificate required')
            receipt=a.receipt_key
            if receipt is None:
                fields,public=identity.invoke(client,400,a=4,data=node[48:112]);receipt=fields[1]
            else:_,public=identity.invoke(client,401,h=receipt)
            if len(public)!=288 or struct.unpack_from('<Q',public,16)[0]!=4 or public[32:96]!=node[48:112]:raise ValueError('receipt key must match accepted node federation and scope')
            generation=struct.unpack_from('<Q',public,24)[0]
            declaration=struct.pack('<2Q',0x314b52544c,1)+public[96:128]+node_hash+struct.pack('<2Q',generation,1)+bytes(32)
            permit=identity.invoke(client,405,h=a.node_key,a=launcher(client),b=3,c=128,data=hashlib.sha256(declaration).digest())[0][1]
            _,certificate=identity.invoke(client,402,h=permit,data=declaration)
            if len(certificate)!=352 or certificate[48:144]!=node[48:144]:raise ValueError('declaration must be certified by the accepted local node key')
            grant=identity.invoke(client,409,a=receipt,b=service,c=a.authorizations,data=MAILBOX_TERMS_HASH+node_hash)[0][1]
            profile=certificate+MAILBOX_TERMS_HASH+node_hash
            f,_=invoke(client,3,440,h=4,a=grant,data=profile,allowed_status=(0,6))
            deadline=time.monotonic()+600
            while f[0]==6:
                if time.monotonic()>deadline:raise TimeoutError('native receipt-profile publication remains pending')
                time.sleep(.05);f,_=invoke(client,3,441,h=4,allowed_status=(0,6))
            a.output.write_bytes(profile)
            result=dict(mailbox=service,native_node_key=a.node_key,native_receipt_key=receipt,finite_authorizations=a.authorizations,terms_sha256=MAILBOX_TERMS_HASH.hex(),public_profile=str(a.output),profile_sha256=hashlib.sha256(profile).hexdigest(),private_keys_exported=False,restart='recover both sealed Identity keys, then reauthorize this exact current service')
        elif a.command=='receive-ciphertext':
            raw=a.ciphertext.read_bytes();f,_=invoke(client,2,428,a=len(raw),data=raw);result=dict(status=list(f))
        elif a.command=='inbox':
            f,raw=invoke(client,2,429,h=a.cursor);result=dict(status=list(f),text=raw.decode('utf-8',errors='replace'))
        else:
            f,_=invoke(client,2,{'status':420,'lock':431,'forget':433}[a.command]);result=dict(status=list(f))
        print(json.dumps(result,indent=2));return 0
    finally:client.close()
if __name__=='__main__':raise SystemExit(main())
