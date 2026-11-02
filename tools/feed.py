"""Install native Feed packages and provision explicit bounded federation roles.

The host packages software, selects public configurations, and grants native
services. Events, signatures, moderation, indexes, and replication execute in
RV64 guest code. No social history or Feed private key is generated here.
"""
from __future__ import annotations
import argparse, hashlib, json, struct, time
from pathlib import Path
import identity, live, messenger, network, releases, server_store

ROLE=6

def digest(value):
    return identity.digest(value)

def invoke(client, operation, action=0, handle=0, offset=0, count=0, data=b'', allowed=(0,)):
    return messenger.invoke(client, ROLE, operation, h=action, a=handle,
                            b=offset, c=count, data=data, allowed_status=allowed)

def install_or_launch(client,path,public,rights):
    """Relaunch an already admitted exact release through normal Launcher checks."""
    raw=path.read_bytes();info=releases.inspect(raw)
    if info['rights']!=rights or struct.unpack_from('<Q',raw,400)[0]!=2:
        raise ValueError('wrong exact Feed package rights or profile')
    selected=bytes.fromhex(info['release_id'])
    for index in range(16):
        try:header=client.request(13,struct.pack('<Q',index))
        except ValueError as error:
            if str(error)!='guest rejected command13, status1':raise
            continue
        if len(header)>=192 and header[160:192]==selected:
            answer=client.request(25,struct.pack('<Q',index+1))
            return struct.unpack_from('<Q',answer,8)[0],selected
    return messenger.install(client,path,public,rights)

def package(output, publisher, account_parent=None, federation_parent=None, ui_parent=None, ui_version='0.9.4', account_version='0.9.4'):
    import live_build
    if ui_version not in('0.9.1','0.9.2','0.9.3','0.9.4'):raise ValueError('unsupported Feed UI version')
    if account_version not in('0.9.1','0.9.2','0.9.3','0.9.4'):raise ValueError('unsupported Feed account version')
    if account_parent is not None:
        if not isinstance(account_parent,str)or len(account_parent)!=64 or any(c not in'0123456789abcdefABCDEF'for c in account_parent)or not any(bytes.fromhex(account_parent)):
            raise ValueError('account parent must be a nonzero exact32-byte release hash')
        account_parent=account_parent.lower()
    if federation_parent is not None:
        if not isinstance(federation_parent,str)or len(federation_parent)!=64 or any(c not in'0123456789abcdefABCDEF'for c in federation_parent)or not any(bytes.fromhex(federation_parent)):
            raise ValueError('federation parent must be a nonzero exact32-byte release hash')
        federation_parent=federation_parent.lower()
    if ui_parent is not None:
        if not isinstance(ui_parent,str)or len(ui_parent)!=64 or any(c not in'0123456789abcdefABCDEF'for c in ui_parent)or not any(bytes.fromhex(ui_parent)):
            raise ValueError('UI parent must be a nonzero exact32-byte release hash')
        ui_parent=ui_parent.lower()
    output.mkdir(parents=True, exist_ok=False)
    rows=[]
    for name,module,rights in [('identity','Guest.Identity',0),('feed-account','Guest.FeedAccount',1024),
                              ('feed','Guest.Feed',799),('feed-federation','Guest.FeedFederation',3072)]:
        binary=live_build.app(module,module+'.main',name,2)
        version=ui_version if name=='feed'else account_version if name=='feed-account'else'0.9.1'if name=='feed-federation'else'0.9.0'
        parent=account_parent if name=='feed-account'else federation_parent if name=='feed-federation'else ui_parent if name=='feed'else None
        raw,_=releases.make(binary,name,version,rights,publisher,parent=parent,profile=2,license='NOASSERTION')
        path=output/(name+'.ltrel');path.write_bytes(raw)
        rows.append(dict(name=name,path=str(path.resolve()),rights=rights,code_bytes=binary.stat().st_size,
                         code_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                         release_id=releases.inspect(raw)['release_id'],package_sha256=hashlib.sha256(raw).hexdigest()))
    report=dict(schema=1,packages=rows,account_parent=account_parent,federation_parent=federation_parent,ui_parent=ui_parent,ui_version=ui_version,account_version=account_version,publisher='existing disclosed host RSA release bootstrap',
                feed_private_keys_exported=False,authoritative_host_database=False)
    (output/'packages.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

def start(client,a):
    who=messenger.launcher(client)
    try: signer=identity.endpoint(client,410)
    except ValueError:
        try: signer=identity.endpoint(client,400)
        except ValueError: signer=identity.start(client,a.identity,a.public)['service']
    owner,oid=install_or_launch(client,a.owner,a.public,1024)
    ui,uid=install_or_launch(client,a.ui,a.public,799)
    sid=bytes.fromhex(releases.inspect(a.identity.read_bytes())['release_id'])
    for operation in (402,410):identity.bind(client,signer,owner,sid,oid,operation)
    messenger.bind(client,5,owner,ui,480,oid,uid)
    messenger.bind(client,5,owner,who,481,oid)
    raw=client.request(150,struct.pack('<Q8Q',ui,790,0,0,0,0,0,0,1)+digest(a.federation)+digest(a.peer))
    if len(raw)!=64 or struct.unpack_from('<Q',raw)[0]:raise ValueError('native Feed UI configuration refused')
    return dict(identity=signer,owner=owner,ui=ui,rights=[1024,799],
                federation=a.federation,selected_peer=a.peer,default_retention='ephemeral',
                controls='native Feed window: create identity, compose, select audience, publish, timeline and reply',
                transport='selected native mode1 circuit and Feed terminal required; no direct fallback')

def federation_start(client,a):
    who=messenger.launcher(client)
    owner,sid=install_or_launch(client,a.release,a.public,3072)
    try:
        for operation in (490,491):messenger.bind(client,ROLE,owner,who,operation,sid)
        network_owner=next(r[0] for r in identity.instances(client) if r[0]&255==6)
        messenger.bind(client,ROLE,owner,network_owner,491,sid)
        moderator=digest(a.moderator) if a.moderator else None
        try: signer=identity.endpoint(client,410)
        except ValueError:
            try: signer=identity.endpoint(client,400)
            except ValueError: signer=identity.start(client,a.identity,a.public)['service']
        signer_release=bytes.fromhex(releases.inspect(a.identity.read_bytes())['release_id'])
        for operation in (402,410):identity.bind(client,signer,owner,signer_release,sid,operation)
        if moderator is None:
            scope=hashlib.sha256(b'LemmaTrix federation moderation v1\0'+digest(a.namespace)).digest()
            invoke(client,490,action=4,data=digest(a.federation)+scope,allowed=(0,6))
            until=time.monotonic()+600
            while True:
                f,public=invoke(client,490,action=6,allowed=(0,6))
                if f[0]==0:
                    if len(public)!=256:raise ValueError('native moderator public descriptor256 required')
                    moderator=public[96:128];break
                if time.monotonic()>until:raise TimeoutError('native moderator initialization')
                time.sleep(.05)
        server_store.call(client,230)
        namespace=digest(a.namespace)
        grants=[]
        for i in range(8):
            selected=hashlib.sha256(b'LemmaTrix Feed segment v1\0'+namespace+bytes([i])).digest()
            quota=37888 if i==0 else 131072
            grants.append(server_store.call(client,231,owner,6,quota,selected)[0][1])
        data=struct.pack('<8Q',*grants)+digest(a.federation)+digest(a.peer)+moderator+struct.pack('<4Q',a.events,a.bytes,a.policy,0)
        f,_=invoke(client,490,data=data)
        if getattr(a,'recover_key',None):
            credential=a.recover_key.read_bytes()
            if len(credential)!=32:raise ValueError('operator unlock credential32 required')
            f,_=invoke(client,490,action=8,data=credential,allowed=(0,6))
            until=time.monotonic()+600
            while f[0]==6:
                f,_=invoke(client,490,action=6,allowed=(0,6))
                if time.monotonic()>until:raise TimeoutError('native recovered moderator generation commit')
                if f[0]==6:time.sleep(.05)
    except BaseException:
        client.request(26,struct.pack('<Q',owner));raise
    return dict(instance=owner,release_id=sid.hex(),federation=a.federation,peer=a.peer,
                moderator_public=moderator.hex(),namespace=a.namespace,status=list(f),
                storage_grants=grants,storage_grants_are_live_session_handles=True,
                capacity=dict(events=a.events,content_bytes=a.bytes,stages=4,content_max=16384,segments=7,per_author_events=16,per_author_content_bytes=262144),
                persistence='native purpose2 ServerStore; index commit follows immutable content segment commit',
                lifecycle='long-running native listener; no per-client handoff or host replication loop')

def replication(client,a):
    # Both ordered public node certificates must already be explicitly enrolled.
    # Native Network48 derives transport material from native node keys; this
    # portal never supplies a shared master secret or a new host private key.
    endpoint=getattr(a,'endpoint',None)
    endpoint=endpoint.encode('ascii') if endpoint else b''
    if not 1<=len(endpoint)<=64:raise ValueError('explicit numeric bulk endpoint1..64 bytes required')
    side=1 if a.side=='client' else 2
    configured=False
    try:
        status,_=network.call(client,7,slot=a.slot)
        _,current=network.call(client,15,slot=a.slot)
        configured=(status[2]==side and len(current)==512 and
                    struct.unpack_from('<Q',current,160)[0]==len(endpoint) and current[168:168+len(endpoint)]==endpoint)
    except ValueError:pass
    if not configured:network.call(client,48,h=a.peer,a=side,b=len(endpoint),data=endpoint,slot=a.slot)
    network.call(client,13,slot=a.slot)
    _,descriptor=network.call(client,15,slot=a.slot)
    if len(descriptor)!=512:raise ValueError('native Feed replication descriptor512 required')
    peer=descriptor[96:128] if side==1 else descriptor[64:96]
    pins=peer+hashlib.sha256(descriptor).digest()+digest(a.scope)
    auto_renew=bool(getattr(a,'auto_renew',False))
    data=pins+struct.pack('<3Q',a.bytes,a.rate,a.lifetime)+(struct.pack('<Q',1)if auto_renew else b'')
    until=time.monotonic()+600
    while True:
        answer,_=invoke(client,490,action=2,handle=a.slot,data=data,allowed=(0,6))
        if answer[0]==0:break
        if time.monotonic()>until:raise TimeoutError('native durable replication allowance admission')
        time.sleep(.1)
    return dict(peer=peer.hex(),network_slot=a.slot,grant=answer[1],mode=3,
                bytes=a.bytes,rate=a.rate,lifetime=a.lifetime,scope=a.scope,status=list(answer),auto_renew=auto_renew,
                disclosure='explicit direct encrypted inter-operator bulk relationship; client requests still require mode1',
                durable_allowance='exact policy total persists; fresh transport allocation at most1MiB is burned before grant; exact event reserves bytes/work and nine attempts before replication',
                scheduling='native guest replication; host controller may now exit')

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--socket',type=Path)
    sub=p.add_subparsers(dest='command',required=True)
    q=sub.add_parser('package');q.add_argument('--publisher-private',type=Path,required=True);q.add_argument('--output',type=Path,required=True);q.add_argument('--account-parent',help='nonzero exact previous Feed account release hash for a normal native upgrade');q.add_argument('--federation-parent',help='nonzero exact previous Feed federation release hash for a normal native upgrade');q.add_argument('--ui-parent',help='nonzero exact previous Feed UI release hash for a normal native upgrade');q.add_argument('--ui-version',choices=('0.9.1','0.9.2','0.9.3','0.9.4'),default='0.9.4',help='Feed UI version (default0.9.4); older versions require explicit selection');q.add_argument('--account-version',choices=('0.9.1','0.9.2','0.9.3','0.9.4'),default='0.9.4',help='Feed account version (default0.9.4); older versions require explicit selection')
    q=sub.add_parser('vault-init');q.add_argument('image',type=Path)
    q=sub.add_parser('authorize-retention');q.add_argument('--owner',type=int,required=True)
    q=sub.add_parser('ui-status');q.add_argument('--ui',type=int,required=True)
    q=sub.add_parser('export-profile');q.add_argument('--ui',type=int,required=True);q.add_argument('--output',type=Path,required=True)
    q=sub.add_parser('stage-profile');q.add_argument('--ui',type=int,required=True);q.add_argument('profile',type=Path)
    q=sub.add_parser('start');q.add_argument('--identity',type=Path,required=True);q.add_argument('--owner',type=Path,required=True);q.add_argument('--ui',type=Path,required=True);q.add_argument('--public',type=Path,required=True);q.add_argument('--federation',required=True);q.add_argument('--peer',required=True)
    q=sub.add_parser('federation-start');q.add_argument('--release',type=Path,required=True);q.add_argument('--public',type=Path,required=True);q.add_argument('--namespace',required=True);q.add_argument('--federation',required=True);q.add_argument('--peer',required=True);q.add_argument('--moderator',help='existing native moderator public key; new operators omit and create natively');q.add_argument('--identity',type=Path,required=True);q.add_argument('--recover-key',type=Path,help='recover the native moderator seal from this operator backing');q.add_argument('--events',type=int,default=64);q.add_argument('--bytes',type=int,default=917504);q.add_argument('--policy',type=int,default=1)
    q=sub.add_parser('replication');q.add_argument('--peer',type=int,choices=range(4),required=True);q.add_argument('--side',choices=('client','server'),required=True);q.add_argument('--endpoint',required=True,help='separately approved numeric bulk endpoint, distinct from signed onion endpoint');q.add_argument('--slot',type=int,choices=range(4),default=0);q.add_argument('--scope',required=True);q.add_argument('--bytes',type=int,default=16777216);q.add_argument('--rate',type=int,default=65536);q.add_argument('--lifetime',type=int,default=100000);q.add_argument('--auto-renew',action='store_true',help='explicit finite rolling leases from the same durable policy total; failures stop')
    q=sub.add_parser('read');q.add_argument('--event',required=True);q.add_argument('--offset',type=int,default=0);q.add_argument('--bytes',type=int,default=512);q.add_argument('--moderator',action='store_true')
    q=sub.add_parser('moderator-retain');q.add_argument('--key',type=Path,required=True)
    q=sub.add_parser('moderate');q.add_argument('--target',required=True);q.add_argument('--action',choices=('hide','uphold','reverse'),required=True);q.add_argument('--reason',required=True)
    for name in ('status','federation-status','replication-status','replication-budget','replication-authority','timeline'):

        q=sub.add_parser(name)
        if name=='timeline':q.add_argument('--cursor',type=int,default=0);q.add_argument('--moderator',action='store_true')
    a=p.parse_args(argv)
    if a.command=='package':result=package(a.output,a.publisher_private,a.account_parent,a.federation_parent,a.ui_parent,a.ui_version,a.account_version)
    elif a.command=='vault-init':
        import os,resource
        sectors=5396132;size=sectors*512
        soft,hard=resource.getrlimit(resource.RLIMIT_FSIZE)
        if soft!=resource.RLIM_INFINITY and soft<size and (hard==resource.RLIM_INFINITY or hard>=size):resource.setrlimit(resource.RLIMIT_FSIZE,(size,hard))
        descriptor=os.open(a.image,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:os.ftruncate(descriptor,size);os.fsync(descriptor)
        finally:os.close(descriptor)
        result=dict(path=str(a.image),sectors=sectors,bytes=size,purpose='fresh personal backing; Objects must be independently initialized/unlocked',feed_retention_authorized=False,private_keys_created=False)
    else:
        if a.socket is None:raise ValueError('--socket required')
        c=live.Client(a.socket,timeout=600)
        try:
            if a.command=='authorize-retention':
                c.request(179,struct.pack('<2Q',a.owner,1));result=dict(owner=a.owner,feed_domain=3,authorized=True,objects_unlock='independent native Objects approval required')
            elif a.command=='ui-status':
                raw=c.request(150,struct.pack('<Q8Q',a.ui,791,0,0,0,0,0,0,1))
                aux=c.request(150,struct.pack('<Q8Q',a.ui,793,0,0,0,0,0,0,1))
                result=dict(status=list(struct.unpack_from('<8Q',raw)),public_identity=raw[64:].hex(),retention=list(struct.unpack_from('<8Q',aux)))
            elif a.command=='export-profile':
                raw=c.request(150,struct.pack('<Q8Q',a.ui,794,0,0,0,0,0,0,1))
                f=struct.unpack_from('<8Q',raw)
                if f[0]:raise ValueError('native UI has no explicitly exported profile; use F1 then F8 first')
                try:selected=c.read_object(f[1])
                finally:c.objects(47,f[1])
                if len(selected)!=2048:raise ValueError('native portable profile2048 required')
                releases.pkg.write_new(a.output,selected)
                result=dict(path=str(a.output),bytes=2048,sha256=hashlib.sha256(selected).hexdigest(),private_seeds_exported=False)
            elif a.command=='stage-profile':
                selected=a.profile.read_bytes()
                if len(selected)!=2048 or struct.unpack_from('<2Q',selected)!=(0x3154524f5046544c,1):raise ValueError('native portable profile2048/version1 required')
                handle=c.import_object(selected,kind=6)
                try:
                    delegated=c.objects(6,handle,a.ui,1)[0][1]
                    raw=c.request(150,struct.pack('<Q8Q',a.ui,792,delegated,0,0,0,0,0,1))
                    if struct.unpack_from('<Q',raw)[0]:raise ValueError('native profile staging refused')
                finally:c.objects(47,handle)
                result=dict(staged=True,ui=a.ui,approval='inspect destination scope and use native F1 then F9; no identity or preferences imported yet')
            elif a.command=='start':result=start(c,a)
            elif a.command=='federation-start':result=federation_start(c,a)
            elif a.command=='replication':result=replication(c,a)
            elif a.command=='read':
                f,raw=invoke(c,490 if a.moderator else 491,action=10 if a.moderator else 6,offset=a.offset,count=a.bytes,data=digest(a.event))
                result=dict(status=list(f),utf8=raw.decode('utf-8',errors='replace'),event=a.event,offset=a.offset,moderator=a.moderator)
            elif a.command=='moderator-retain':
                credential=a.key.read_bytes()
                if len(credential)!=32:raise ValueError('operator unlock credential32 required')
                f,_=invoke(c,490,action=7,data=credential,allowed=(0,6))
                until=time.monotonic()+600
                while f[0]==6:
                    if time.monotonic()>until:raise TimeoutError('native moderator sealed retention commit')
                    time.sleep(.05);f,_=invoke(c,490,action=6,allowed=(0,6))
                result=dict(moderator_seed_sealed=True,durably_committed=True,raw_private_keys_exported=False,status=list(f))
            elif a.command=='moderate':
                reason=a.reason.encode('utf-8')
                if not 1<=len(reason)<=512:raise ValueError('moderation reason1..512 UTF-8 bytes required')
                f,_=invoke(c,490,action=5,handle=('hide','uphold','reverse').index(a.action)+1,data=digest(a.target)+reason,allowed=(0,6))
                until=time.monotonic()+600
                while f[0]==6:
                    if time.monotonic()>until:raise TimeoutError('native moderation decision publication')
                    time.sleep(.05);f,raw=invoke(c,490,action=6,allowed=(0,6))
                result=dict(durably_published=True,event_id=raw.hex(),target=a.target,action=a.action,status=list(f),signer='native scoped moderator Identity; no host private key')
            elif a.command=='federation-status':
                f,raw=invoke(c,490,action=9)
                result=dict(events=f[1],content_bytes=f[2],event_limit=f[3],byte_limit=f[4],policy_version=f[5],index_generation=f[6],federation=raw[:32].hex(),peer=raw[32:64].hex(),moderator_public=raw[64:96].hex())
            elif a.command=='replication-status':
                f,_=invoke(c,490,action=3);result=dict(status=list(f),mode=3)
            elif a.command=='replication-authority':
                f,_=invoke(c,490,action=13)
                result=dict(policy_mode=f[1],rolling_armed=bool(f[2]),pending_or_failure=f[3],
                            last_reason=f[4],cached_policy_bytes=f[5],current_grant=f[6],
                            failure='quota4, revoked/grant3 or storage5 stops rolling; fresh authority is explicit')
            elif a.command=='replication-budget':
                f,raw=invoke(c,490,action=12)
                result=dict(total_bytes=f[1],reserved_event_bytes=f[2],transport_allocated_bytes=f[3],
                            total_work_units=f[4],reserved_event_work_units=f[5],policy_generation=f[6],
                            exact_policy_hash=raw.hex(),allocation_max_bytes=1048576,
                            attempts_per_event=9,polls_per_attempt=128,
                            restart='unused old transport allocation is conservatively burned; counters are not renewed')
            elif a.command=='timeline':
                f,raw=invoke(c,490 if a.moderator else 491,action=1 if a.moderator else 5,handle=a.cursor,allowed=(0,6))
                result=dict(status=list(f),event_id=raw[:32].hex() if raw else None,original_signed_bytes=raw[32:].hex() if raw else None)
            else:
                f,_=invoke(c,491,action=8);result=dict(status=list(f))
        finally:c.close()
    print(json.dumps(result,indent=2));return 0

if __name__=='__main__':raise SystemExit(main())
