"""Public-only enrollment adapter; node and certification keys stay in guests."""
import argparse, hashlib, json, struct
from pathlib import Path
import live, identity, network

def call(client,op,h=0,data=b'',a=0,b=0,c=0,d=0,e=0):
    if 20 <= op <= 48:
        import messenger,time
        target=next(row[0] for row in identity.instances(client) if row[0]&255==6)
        token=struct.unpack('<Q',client.request(175,struct.pack('<Q8Q',target,op,h,a,b,c,d,e,2)+data))[0]
        deadline=time.monotonic()+600
        while time.monotonic()<deadline:
            raw=client.request(176,struct.pack('<Q',token))
            if len(raw)==8:time.sleep(.05);continue
            f=struct.unpack_from('<8Q',raw)
            if f[0]:raise ValueError(f'native enrollment status{f[0]}')
            return f,raw[64:]
        client.request(177,struct.pack('<Q',token));raise TimeoutError('native enrollment completion')
    return network.call(client,op,h=h,a=a,b=b,c=c,d=d,e=e,data=data,slot=0)

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--socket',type=Path,required=True)
    sub=p.add_subparsers(dest='command',required=True)
    q=sub.add_parser('create');q.add_argument('--kind',choices=['relay','mailbox','feed'],required=True)
    for f in ['federation','scope','family']:q.add_argument('--'+f,required=True)
    q.add_argument('--endpoint',required=True);q.add_argument('--bytes',type=int,default=1048576);q.add_argument('--work',type=int,default=65536);q.add_argument('--generation',type=int,default=1);q.add_argument('--output',required=True,type=Path)
    q=sub.add_parser('stage');q.add_argument('certificate',type=Path);q.add_argument('--peer',type=int,choices=range(4),required=True)
    q=sub.add_parser('approve');q.add_argument('--peer',type=int,choices=range(4),required=True);q.add_argument('--fingerprint',required=True)
    q=sub.add_parser('revoke');q.add_argument('--peer',type=int,choices=range(4),required=True)
    q=sub.add_parser('listen');q.add_argument('--channel',type=int,choices=range(12),default=0)
    q=sub.add_parser('bulk');q.add_argument('--peer',type=int,choices=range(4),required=True);q.add_argument('--role',choices=['client','server'],required=True);q.add_argument('--slot',type=int,choices=range(4),default=0)
    sub.add_parser('route');sub.add_parser('status');sub.add_parser('stop');sub.add_parser('lock')
    for name in ('retain','recover'):
        q=sub.add_parser(name);q.add_argument('--key',required=True,type=Path)
        if name=='retain':
            q.add_argument('--node-key',type=int);q.add_argument('--receipt-key',type=int)
    q=sub.add_parser('terminal');q.add_argument('--peer',type=int,choices=range(4),default=3);q.add_argument('--owner',required=True,type=int);q.add_argument('--bytes',type=int,default=1048576);q.add_argument('--attempts',type=int,default=4096);q.add_argument('--stream',type=int,default=1)
    q=sub.add_parser('registry-terminal');q.add_argument('--registry',type=int,required=True);q.add_argument('--federation',required=True)
    q=sub.add_parser('export');q.add_argument('--peer',type=int,choices=range(5),default=4);q.add_argument('--output',required=True,type=Path)
    a=p.parse_args(argv);c=live.Client(a.socket,timeout=600)
    try:
        if a.command=='create':
            if not 0<a.bytes<=1073741824 or not 0<a.work<=1000000000 or not 0<a.generation<2**64:raise ValueError('finite positive terms required')
            endpoint=a.endpoint.encode('ascii')
            if not 0<len(endpoint)<=64:raise ValueError('canonical numeric IPv4 endpoint required')
            _,public=call(c,20)
            if len(public)!=64:raise ValueError('truncated native node keys')
            fields,_=identity.invoke(c,400,a=3,data=identity.digest(a.federation)+identity.digest(a.scope))
            key=fields[1];body=bytearray(256)
            struct.pack_into('<8Q',body,0,identity.NODE_MAGIC,2,7 if a.kind=='relay' else 8 if a.kind=='mailbox' else 16,1,1,a.bytes,a.work,1)
            body[64:128]=public;body[128:160]=identity.digest(a.family)
            struct.pack_into('<3Q',body,160,a.generation,0,len(endpoint));body[184:184+len(endpoint)]=endpoint
            launcher=next(row[0] for row in identity.instances(c) if row[0]&255==1)
            permit,_=identity.invoke(c,405,h=key,a=launcher,b=2,c=256,data=hashlib.sha256(body).digest())
            _,certificate=identity.invoke(c,402,h=permit[1],data=body)
            if len(certificate)!=480:raise ValueError('truncated native node certificate')
            _,fingerprint=call(c,21,data=certificate)
            a.output.write_bytes(certificate)
            result=dict(public_certificate=str(a.output),fingerprint=fingerprint.hex(),kind=a.kind,native_identity_key=key,key_retention='ephemeral unless explicitly retained with an operator credential and selected Identity handles',route_available=False)
        elif a.command in ('retain','recover'):
            owner=next(row[0] for row in identity.instances(c) if row[0]&255==6)
            key=a.key.read_bytes()
            if len(key)!=32:raise ValueError('explicit operator unlock credential32 required')
            c.request(178,struct.pack('<2Q',owner,1))
            blob=b'';restored_handles=None
            if a.command=='retain':
                if (a.node_key is None)!=(a.receipt_key is None):raise ValueError('select both --node-key and --receipt-key for sealed Identity retention')
                if a.node_key is not None:
                    _,blob=identity.invoke(c,408,h=0,a=a.node_key,b=a.receipt_key,data=key)
                    if len(blob)!=192:raise ValueError('native Identity did not return exact sealed192-byte retention')
                f,_=call(c,43,data=key+blob)
            else:
                f,blob=call(c,44,data=key)
                if blob and any(blob):
                    if len(blob)!=192:raise ValueError('native operator store returned invalid sealed Identity blob')
                    _,description=call(c,25,h=4)
                    restored,_=identity.invoke(c,408,h=1,data=key+description[112:144]+blob)
                    restored_handles=dict(node_key=restored[1],receipt_key=restored[2])
            result=dict(protected_operator_retention=True,generation=f[1],identity_seeds_sealed=bool(blob and any(blob)),restored_identity_handles=restored_handles,scope='independent operator retention; fresh channel/circuit state each connection')
        elif a.command=='lock':
            f,_=call(c,45);result=dict(locked=True,status=list(f))
        elif a.command in ('listen','route','stop'):
            f,_=call(c,{'listen':30,'route':31,'stop':35}[a.command],h=getattr(a,'channel',0));result=dict(status=list(f),application_fallback=False)
        elif a.command=='bulk':
            f,_=network.call(c,48,h=a.peer,a=1 if a.role=='client' else 2,slot=a.slot)
            result=dict(approved_native_peer=a.peer,slot=a.slot,role=a.role,mode=3,status=list(f),private_keys_exported=False,authentication='native Ed25519 enrollment and X25519 pair possession')
        elif a.command=='terminal':
            f,_=call(c,38,h=a.peer,a=a.stream,b=a.owner,c=a.bytes,d=a.attempts);result=dict(queued=True,owner=a.owner,status=list(f))
        elif a.command=='registry-terminal':
            f,_=call(c,46,h=a.registry,data=identity.digest(a.federation));result=dict(read_only_registry=a.registry,federation=a.federation,status=list(f))
        elif a.command=='status':
            f,_=call(c,32);g,pin=call(c,41);result=dict(circuit=list(f),terminal=list(g),mailbox_descriptor=pin.hex(),direct_fallback=False)
        elif a.command=='stage':
            raw=a.certificate.read_bytes()
            if len(raw)!=480:raise ValueError('native node certificate must be480 bytes')
            f,body=call(c,22,a.peer,raw)
            result=dict(peer=a.peer,fingerprint=body[480:].hex(),generation=f[2],approved=False)
        elif a.command=='approve':
            call(c,23,a.peer,identity.digest(a.fingerprint));result=dict(peer=a.peer,approved=True)
        elif a.command=='revoke':
            call(c,24,a.peer);result=dict(peer=a.peer,revoked=True)
        else:
            f,body=call(c,25,a.peer);a.output.write_bytes(body[:480]);result=dict(peer=a.peer,state=f[2],fingerprint=body[480:].hex(),output=str(a.output))
        print(json.dumps(result,indent=2));return 0
    finally:c.close()
if __name__=='__main__':raise SystemExit(main())
