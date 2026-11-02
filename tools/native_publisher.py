"""Key-free byte adapter for the native release coordinator.

Only the guest creates publisher keys, validates Build/Evidence, assembles its
Release graph and signs after trusted review. These commands never approve it.
"""
import argparse, hashlib, json, struct, sys
from pathlib import Path
import identity, live, projects, releases


def inspect(client):
    raw = client.request(228)
    if len(raw) != 640:
        raise ValueError('native publisher returned an incompatible summary')
    q = struct.unpack_from('<8Q', raw)
    if q[0]:
        raise ValueError('native publisher status ' + str(q[0]))
    return dict(schema=1, key=q[1], job=q[2], phase=q[3], release_handle=q[4],
                failure=q[6], release_id=raw[224:256].hex(),
                source_root=raw[576:608].hex(), project_id=raw[608:640].hex(),
                header=raw[64:576].hex(), session_only=True)


def prepare(client, *, root, publisher, name, version, output, result_path=None,
            license='NOASSERTION', parent=None, exports=()):
    output = Path(output)
    if output.exists():
        raise ValueError('proposal output exists; choose a new review directory')
    public_fields, public = identity.invoke(client, 401, h=publisher)
    decoded = identity.decode_public(public)
    if decoded['role'] != 1:
        raise ValueError('select an independently initialized project publisher')
    logical = projects.project_identity(client, root)
    job = 0
    code_handle = 0
    executable = b''
    if result_path:
        result = json.loads(Path(result_path).read_bytes())
        if result.get('status') != 'ok' or not result.get('delivered'):
            raise ValueError('select a completed actual guest build result')
        session = result['guest_session']
        job = session['job_id']
        raw = client.request(160, struct.pack('<8Q', 7, job, 0, 0, 0, 0, 0, 1))
        actual = projects.frozen_build(client, raw)
        if actual['project_id'] != logical:
            raise ValueError('selected build belongs to another logical project')
        source_root, files = projects.snapshot(client, actual['source_root_capability'], actual['source_root'])
        if source_root != result['source_root']:
            raise ValueError('build result does not identify this exact frozen source')
        executable = Path(result['artifact']['path']).read_bytes()
        if hashlib.sha256(executable).hexdigest() != result['artifact']['sha256']:
            raise ValueError('actual artifact differs from completed Build/Evidence')
        chunks = []
        for ordinal, offset in enumerate(range(0, len(executable), 65536)):
            _, ident = projects.node(client, executable[offset:offset+65536], 10)
            chunks.append((f'code/chunk-{ordinal:04d}.bin', 10, ident))
        code_handle, _ = projects.node(client, projects.manifest(chunks), 11)
        evidence = [dict(kind='host-sandbox-build', job_id=result['job_id'], source_root=result['source_root'],
                         request_digest=result['request_digest'], toolchain_id=result['toolchain_id'],
                         binary_sha256=result['artifact']['sha256'], source_to_binary='unverified')]
        facet = 'NativeApplication'
        profile = result['runtime_profile']
        build = dict(job=job, source=source_root, artifact=result['artifact']['sha256'],
                     toolchain=result['toolchain_id'], recipe=result['recipe'])
    else:
        source_root, files = projects.snapshot(client, root)
        evidence, build, facet, profile = [], None, 'DevelopmentArtifact', 0
    project = json.loads(files.get('lemma.project.json', b'{}'))
    lock = json.loads(files.get('lemma.lock.json', b'{}'))
    if not lock or not project:
        raise ValueError('public lemma.project.json and exact lemma.lock.json are required')
    if project.get('name') != name or project.get('facet') != facet:
        raise ValueError('requested name/facet differs from the selected project declaration')
    rights = project.get('rights', 0)
    if facet == 'DevelopmentArtifact' and rights:
        raise ValueError('source-only publication cannot request execution authority')
    records = [dict(path=n, sha256=hashlib.sha256(b).hexdigest(), size=len(b)) for n, b in sorted(files.items())]
    public_key = bytes.fromhex(decoded['public_key'])
    # Inert proposal header/metadata. The guest reconstructs the authoritative
    # graph links from its own selected BuildJobs and validated object handles.
    header, manifest = releases.prepare_native(
        Path(result['artifact']['path']) if result_path else None, name, version,
        rights, public_key, decoded['generation'], parent=parent, license=license,
        source_records_override=records, logical_project_id=logical, evidence=evidence,
        facet=facet, profile=profile, sdk=lock.get('sdk'), dependencies=lock.get('dependencies', []),
        build=build, provenance=dict(declaration=project.get('distribution_authority'), source_root=source_root),
        exports=exports, recipe=dict(module=lock.get('module'), entry=lock.get('entry'),
                                    recipe=lock.get('recipe'), toolchain=lock.get('toolchain')))
    parts = [releases.pkg.canonical(manifest), releases.pkg.canonical(manifest['sources']),
             releases.pkg.canonical(manifest['evidence']),
             releases.pkg.canonical(dict(license=manifest['license'], distribution_authority='explicit local author declaration'))]
    proposal = struct.pack('<8Q', 0x31544e43524c544c, 1, 608, *map(len, parts), 0) + header + bytes(64) + public_key + b''.join(parts)
    handle = client.import_object(proposal, 10)
    summary = client.request(226, struct.pack('<5Q', root, publisher, job, handle, code_handle))
    if len(summary) != 640 or struct.unpack_from('<Q', summary)[0]:
        raise ValueError('native coordinator refused proposal: ' + summary[:64].hex())
    output.mkdir(parents=True)
    (output/'manifest.json').write_bytes(releases.pkg.canonical(manifest))
    (output/'artifact.bin').write_bytes(executable)
    (output/'proposal.json').write_text(json.dumps(dict(schema=1, source_root=source_root, root=root,
        publisher=publisher, code_handle=code_handle, proposal_handle=handle, session_only=True,
        name=name, version=version, logical_project_id=logical, release_id=header[160:192].hex()), indent=2)+'\n')
    return {**inspect(client), 'review': 'Alt+F12 trusted publisher panel; Enter signs exact displayed material',
            'signed': False, 'output': str(output)}


def publish_snapshot(client, directory):
    directory = Path(directory)
    proposal = json.loads((directory/'proposal.json').read_bytes())
    state = inspect(client)
    if state['phase'] != 3 or state['release_id'] != proposal['release_id']:
        raise ValueError('select the completed native release for this exact proposal')
    if state['job']:
        raw = client.request(160, struct.pack('<8Q', 7, state['job'], 0, 0, 0, 0, 0, 1))
        source_root = projects.frozen_build(client, raw)['source_root_capability']
    else:
        source_root = proposal['root']
    source_handle = projects.resolve(client, source_root, state['source_root'])
    entries = projects.decode_manifest(client.read_object(source_handle))
    _, ids = client.objects(21, state['release_handle'])
    entries = [e for e in entries if e[1] in (10, 15)]
    if any(e[0] == 'release.ltrel' for e in entries):
        raise ValueError('source member conflicts with reserved release attachment')
    entries.append(('release.ltrel', 13, ids[:32].hex()))
    detail = releases.pkg.canonical(dict(schema=1, kind='native-published-snapshot',
        source_root=state['source_root'], release_id=state['release_id']))
    # Even a separately named snapshot retains its actual source predecessor.
    # Building A never overwrites mutable head B or changes the logical origin.
    head_handle, head = projects.node(client, projects.manifest(entries, detail), 11, source_handle)
    name = f"{proposal['name']}-{proposal['version']}".encode('ascii')
    if len(name) > 63:
        raise ValueError('snapshot name exceeds 63 bytes')
    q, _ = client.objects(22, head_handle, 0, len(name), data=bytes(32)+name.ljust(64, b'\0'))
    root = q[1]
    processes = identity.instances(client)
    shell = next((row[0] for row in processes if row[0] & 255 == 4), 0)
    shell_root = client.objects(27, root, shell, 127)[0][1] if shell else 0
    return dict(root=root, head=head, name=name.decode('ascii'), release_id=state['release_id'],
                source_root=state['source_root'], logical_project_id=proposal['logical_project_id'],
                shell_root=shell_root, signed=True, admitted=False, installed=False, session_only=True)


def export(client, directory, output):
    directory, output = Path(directory), Path(output)
    state = inspect(client)
    proposal = json.loads((directory/'proposal.json').read_bytes())
    if state['phase'] != 3 or state['release_id'] != proposal['release_id']:
        raise ValueError('the selected proposal has not completed native signing')
    payload = client.read_object(state['release_handle'])
    entries = projects.decode_manifest(payload)
    detail = payload[32+128*len(entries):]
    envelope = detail[64:672] + (directory/'artifact.bin').read_bytes()
    manifest = json.loads((directory/'manifest.json').read_bytes())
    info = releases.inspect(envelope, envelope[576:608], manifest)
    releases.pkg.write_new(output, envelope)
    releases.pkg.write_new(Path(str(output)+'.manifest.json'), releases.pkg.canonical(manifest))
    _, ids = client.objects(21, state['release_handle'])
    info['release_node'] = ids[:32].hex()
    info['release_handle'] = state['release_handle']
    Path(str(output)+'.content.json').write_text(json.dumps(dict(schema=1, session_only=True,
        release_handle=state['release_handle'], release_id=info['release_id']), indent=2)+'\n')
    return info


def main(argv=None):
    parser = argparse.ArgumentParser(description='Native guest-owned publisher; no host signing key')
    parser.add_argument('--socket', type=Path, required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init'); init.add_argument('--root', type=int, required=True)
    prep = sub.add_parser('prepare'); prep.add_argument('--root', type=int, required=True)
    prep.add_argument('--publisher', type=int, required=True); prep.add_argument('--name', required=True)
    prep.add_argument('--version', required=True); prep.add_argument('--license', required=True)
    prep.add_argument('--parent'); prep.add_argument('--result', type=Path); prep.add_argument('--export-module', action='append', default=[])
    prep.add_argument('--output', type=Path, required=True)
    sub.add_parser('inspect'); sub.add_parser('cancel')
    publish = sub.add_parser('publish'); publish.add_argument('directory', type=Path)
    exp = sub.add_parser('export'); exp.add_argument('directory', type=Path); exp.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    client = live.Client(args.socket, timeout=300)
    try:
        if args.command == 'init':
            logical = projects.project_identity(client, args.root)
            q, public = identity.invoke(client, 400, a=1,
                data=hashlib.sha256(b'LT-PROJECT-PUBLISHER\0').digest()+bytes.fromhex(logical))
            result = dict(key=q[1], **identity.decode_public(public), session_only=True,
                          retention='ephemeral until explicit typed Objects-domain3 sealing')
        elif args.command == 'prepare':
            result = prepare(client, root=args.root, publisher=args.publisher, name=args.name,
                version=args.version, license=args.license, parent=args.parent, result_path=args.result,
                exports=args.export_module, output=args.output)
        elif args.command == 'export': result = export(client, args.directory, args.output)
        elif args.command == 'publish': result = publish_snapshot(client, args.directory)
        elif args.command == 'cancel': result = {'reply': client.request(229).hex()}
        else: result = inspect(client)
    finally: client.close()
    print(json.dumps(result, indent=2)); return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (ValueError, KeyError, OSError, EOFError, TimeoutError) as error:
        print('lt publisher:', error, file=sys.stderr); raise SystemExit(1)
