"""Real graphical contact approval/compose with native session owner and input.

This component campaign deliberately reports absent routed delivery. It uses
public invitations from separate native guests; no host owns messaging keys.
"""
from __future__ import annotations
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
import live
import messenger
import releases
import projects
import identity
from graphical_devices import DeviceInput


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image', required=True, type=Path)
    p.add_argument('--owner', default=ROOT/'build/live/apps/messenger-session.bin', type=Path)
    p.add_argument('--ui', default=ROOT/'build/live/apps/messenger.bin', type=Path)
    p.add_argument('--identity', type=Path, help='also exercise native certified672 contact import and public export paging')
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    image = out/'guest.bin'
    image.write_bytes(a.image.read_bytes())
    public = ROOT/'tests/keys/development-rsa-public.pem'
    key = ROOT/'tests/keys/development-rsa.pem'
    packages = {}
    for name, binary, rights in [('messenger-owner', a.owner, 0), ('messenger-ui', a.ui, 799)]:
        raw, _ = releases.make(binary, name, '1.0.0', rights, key, profile=2, license='NOASSERTION')
        path = out/(name+'.ltrel')
        path.write_bytes(raw)
        packages[name] = (path, releases.inspect(raw))
    if a.identity:
        raw,_=releases.make(a.identity,'messenger-contact-signer','1.0.0',0,key,profile=2,license='NOASSERTION')
        path=out/'contact-signer.ltrel';path.write_bytes(raw);packages['contact-signer']=(path,releases.inspect(raw))
    guests = []
    checks = []
    federation = hashlib.sha256(b'explicit graphical Messenger component federation').digest()

    def passed(label):
        checks.append(label)
        print('PASS', label, flush=True)

    def start(name, graphical):
        socket = out/(name+'.sock')
        graphics = out/(name+'.qmp')
        log = (out/(name+'.log')).open('wb')
        command = [str(ROOT/'lt'), 'run', '--backend', 'qemu', '--image', str(image), '--socket', str(socket)]
        if graphical:
            command += ['--graphics', str(graphics)]
        proc = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=log, start_new_session=True)
        guests.append((proc, log, None))
        end = time.monotonic()+120
        while not socket.exists():
            if proc.poll() is not None:
                raise RuntimeError((out/(name+'.log')).read_text())
            if time.monotonic() > end:
                raise TimeoutError('native graphical guest startup')
            time.sleep(.05)
        client = live.Client(socket, timeout=600)
        guests[-1] = (proc, log, client)
        print('START '+name+' installing native owner', flush=True)
        owner, sid = messenger.install(client, packages['messenger-owner'][0], public, 0)
        launcher = messenger.launcher(client)
        for op in (420, 421, 422, 428, 429, 431, 432, 433, 434):
            messenger.bind(client, 2, owner, launcher, op, sid)
        ui = None
        if graphical:
            ui, uid = messenger.install(client, packages['messenger-ui'][0], public, 799)
            for op in range(420, 436):
                messenger.bind(client, 2, owner, ui, op, sid, uid)
            ui_invoke(client,ui,781,federation)
        print('READY '+name, flush=True)
        return client, owner, ui, graphics

    def ui_invoke(client,ui,op,data=b''):
        # UI is not a registered authority service; generic async133 is
        # intentionally unavailable. Retry only these idempotent read/staging
        # controls when a complete native graphical frame preceded dispatch.
        end=time.monotonic()+240
        while True:
            try:return client.request(150,struct.pack('<Q8Q',ui,op,0,0,0,0,0,0,1)+data)
            except ValueError as error:
                if str(error)!='guest rejected command150, status1' or time.monotonic()>=end:raise
                processes=client.request(2)
                row=struct.unpack_from('<4Q',processes,(ui&255)*32)
                if row[1]>=5:raise AssertionError(('UI terminated',row,bytes(client.events)))
                time.sleep(.1)

    def inspect(client, ui):
        raw = ui_invoke(client,ui,782)
        assert len(raw) == 96
        return struct.unpack_from('<8Q', raw), raw[64:]

    def wait_ui(client, ui, predicate, timeout=240):
        end = time.monotonic()+timeout
        last = None
        while time.monotonic() < end:
            fields, fingerprint = inspect(client, ui)
            if fields != last:
                print('UI', fields, flush=True)
                last = fields
            if predicate(fields):
                return fields, fingerprint
            time.sleep(.1)
        raise TimeoutError(('graphical Messenger state', fields))

    def native(client, owner, op, data=b''):
        # Public bundle export is cheap. Creation is invoked through the genuine
        # native asynchronous portal; it exports only the public invitation.
        return messenger.invoke(client, 2, op, data=data)

    def certify(client,bundle):
        # Temporary native rights-zero signer holds the independent role2 seed.
        # Only its public certificate crosses into the session owner or host.
        signer,sid=messenger.install(client,packages['contact-signer'][0],public,0)
        try:
            for operation in (400,405,402):identity.bind(client,signer,messenger.launcher(client),sid,bytes(32),operation)
            scope=hashlib.sha256(b'graphical contact certification scope').digest()
            key_handle=identity.invoke(client,400,a=2,data=federation+scope)[0][1]
            body=struct.pack('<4Q',identity.CONTACT_MAGIC,1,struct.unpack_from('<Q',bundle,16)[0],1)+bundle[32:64]+bundle[224:256]+hashlib.sha256(bundle[32:64]+bundle[192:256]).digest()
            permit=identity.invoke(client,405,h=key_handle,a=messenger.launcher(client),b=1,c=128,data=hashlib.sha256(body).digest())[0][1]
            certificate=identity.invoke(client,402,h=permit,data=body)[1]
            messenger.invoke(client,2,434,a=13,data=hashlib.sha256(b'public GUI component mailbox descriptor').digest())
            messenger.invoke(client,2,434,a=26,data=certificate)
            extended=messenger.invoke(client,2,434,a=27)[1]
            assert len(extended)==672 and extended[320:]==certificate
            return extended
        finally:client.request(26,struct.pack('<Q',signer))

    def invitation_crop(frame):
        # Compare actual public glyphs, excluding the native pointer position.
        return b''.join(frame.bgrx[(y*frame.width+16)*4:(y*frame.width+112)*4] for y in range(172,260))

    began = time.monotonic()
    try:
        alice, alice_owner, ui, graphics = start('alice', True)
        bob, bob_owner, _, _ = start('bob', False)
        print('CREATE Bob through native async owner', flush=True)
        bob_fields, bob_bundle = native(bob, bob_owner, 421, federation)
        print('CREATED Bob public invitation', flush=True)
        assert len(bob_bundle) == 256
        if a.identity:bob_bundle=certify(bob,bob_bundle)
        with DeviceInput('qemu', graphics, timeout=120) as device:
            time.sleep(2)
            device.chord(56, 15)
            time.sleep(.5)
            device.press(60)
            (out/'create-ready.ppm').write_bytes(device.frame().ppm())
            wait_ui(alice, ui, lambda f: f[4] == 41)
            _, alice_bundle = native(alice, alice_owner, 422)
            assert len(alice_bundle) == 256 and alice_bundle[32:64] != bob_bundle[32:64]
            passed('two separate native guests create distinct messaging identities; Alice uses graphical F2')
            if a.identity:
                certified_alice=certify(alice,alice_bundle)
                device.press(61)
                wait_ui(alice,ui,lambda f:f[2]==3 and f[4]==30)
                time.sleep(.5)
                pages=[]
                for index in range(3):
                    frame=device.frame();(out/f'certified-export-page{index+1}.ppm').write_bytes(frame.ppm())
                    pages.append(invitation_crop(frame));device.press(109);time.sleep(.5)
                assert len(set(pages))==3
                assert invitation_crop(device.frame())==pages[0]
                device.press(104);time.sleep(.5)
                assert invitation_crop(device.frame())==pages[2]
                device.click(180,274);time.sleep(.5)
                assert invitation_crop(device.frame())==pages[0]
                assert len(certified_alice)==672
                passed('native certified672 export remains within three public pages; real PgDn/PgUp and pointer paging wrap without selecting another contact')
            # Native import verifies the XEdDSA prekey before showing a candidate.
            response = ui_invoke(alice,ui,780,bob_bundle)
            assert struct.unpack_from('<Q', response)[0] == 0
            state, fingerprint = wait_ui(alice, ui, lambda f: f[2] == 1)
            assert any(fingerprint) and state[5] == 0
            frame = device.frame()
            (out/'candidate.ppm').write_bytes(frame.ppm())
            # Real pointer button chooses the visible exact-candidate approval.
            device.click(500, 96)
            wait_ui(alice, ui, lambda f: f[5] == 1 and f[4] == 32)
            passed('native '+('certified672 ' if a.identity else '')+'fingerprint candidate requires real graphical pointer approval')
            device.textASCII('hello from the native Messenger', delay=.04)
            state, _ = wait_ui(alice, ui, lambda f: f[3] == 31)
            device.press(28)
            state, _ = wait_ui(alice, ui, lambda f: f[6] != 0)
            # It must fail closed when no real mode1 route coordinator is bound.
            wait_ui(alice, ui, lambda f: f[4] == 21)
            passed('actual graphical compose/send admits an outbox and reports unavailable required route')
            # Input after native public-key validation and fail-closed route admission.
            device.textASCII('still responsive', delay=.04)
            wait_ui(alice, ui, lambda f: f[3] == 16)
            frame = device.frame()
            (out/'compose.ppm').write_bytes(frame.ppm())
            passed('graphical keyboard editing remains usable after asynchronous native owner work')
            # Select actual useful source data through the trusted native
            # picker. This intentionally has no delivery coordinator; the
            # existing unaccepted outbox blocks a new manifest, while source
            # authorization and bounded archive preparation still execute.
            records=[];entries=[];source_bytes=0
            for path in [ROOT/'Guest/Messenger.lean',ROOT/'Guest/MessengerDelivery.lean']:
                data=path.read_bytes();source_bytes+=len(data)
                node_id=projects.canonical_node(10,data)
                records.append(dict(kind=10,id=node_id,payload=data))
                entries.append((path.name,10,node_id))
            manifest=projects.manifest(entries);head=projects.canonical_node(11,manifest)
            records.insert(0,dict(kind=11,id=head,payload=manifest))
            root=projects.import_records(alice,[dict(name='messenger-sources',head=head)],records)[0]['cap']
            shell=next(struct.unpack_from('<Q',alice.request(2),i)[0] for i in range(0,len(alice.request(2)),32) if struct.unpack_from('<Q',alice.request(2),i)[0]&255==4)
            alice.objects(27,root,shell,31)
            device.press(87);time.sleep(1)
            (out/'project-picker.ppm').write_bytes(device.frame().ppm())
            device.press(28)
            def transfer_state():
                raw=ui_invoke(alice,ui,784)
                return struct.unpack_from('<8Q',raw)
            end=time.monotonic()+180
            while time.monotonic()<end:
                transfer=transfer_state()
                if transfer[4]>65536 and transfer[1]==9:break
                time.sleep(.1)
            else:raise TimeoutError(('actual project picker/frozen bundle',transfer))
            assert source_bytes>65536 and transfer[4]>source_bytes
            time.sleep(.3);(out/'project-selected.ppm').write_bytes(device.frame().ppm())
            passed('F11 trusted picker selects more than64KiB of useful source into a frozen bounded bundle; occupied unaccepted outbox fails closed')
            device.press(66)
            wait_ui(alice, ui, lambda f: f[4] == 23 and f[3] == 0 and f[5] == 0)
            fields, _ = native(alice, alice_owner, 420)
            assert fields[1] == 0
            frame = device.frame()
            (out/'locked.ppm').write_bytes(frame.ppm())
            passed('graphical F8 clears accessible plaintext and locks the actual session owner')
        report = dict(schema=1, result='passed-component-only', checks=checks,
                      image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
                      packages={name: info for name, (_, info) in packages.items()},
                      backend='qemu', elapsed_seconds=time.monotonic()-began,
                      selected_source_bytes=source_bytes,selected_bundle_bytes=transfer[4],selected_root=head,
                      incomplete_acceptance=['no three-hop circuit or mailbox delivery',
                                             'no recipient receive/reply or routed Forge request',
                                             'this run authorizes no Messenger vault'])
        (out/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    except BaseException:
        for ordinal,(_,_,client) in enumerate(guests):
            if client:
                with contextlib.suppress(Exception):
                    raw=client.request(2)
                    (out/f'failure-processes-{ordinal}.json').write_text(json.dumps([struct.unpack_from('<4Q',raw,i) for i in range(0,len(raw),32)]))
                    (out/f'failure-events-{ordinal}.txt').write_bytes(bytes(client.events))
        raise
    finally:
        for process, log, client in guests:
            if client:
                client.close()
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(20)
            log.close()


if __name__ == '__main__':
    main()
