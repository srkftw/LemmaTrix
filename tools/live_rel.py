"""Source-first REL through the running user-mode Objects/Workbench services.

The supported source grammar is tools.rel's bounded byte rotation. Host code
validates/imports/builds; all requested edits and native data processing execute
through real compartment IPC. No host result substitutes for native execution.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import tempfile

try:
    from . import rel, releases, capsule, live, live_build
    from . import packaging as pkg
except ImportError:
    import rel, releases, capsule, live, live_build
    import packaging as pkg

MAX_RECORD = 4096
NATIVE_RIGHTS = 127


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic_json(path, value):
    path = Path(path)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.live-rel-', delete=False) as stream:
        stream.write(pkg.canonical(value))
        temporary = Path(stream.name)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def client_for(path):
    return live.Client(Path(path))


def fetch(client, handle, maximum=65536):
    fields, content_hash = client.objects(5, handle)
    pkg.require(fields[2] <= maximum and fields[5] == 2 and len(content_hash) == 32,
                'invalid or oversized committed Objects metadata')
    output = bytearray()
    for offset in range(0, fields[2], 512):
        count = min(512, fields[2] - offset)
        part, data = client.objects(14, handle, offset, count)
        pkg.require(part[1] == count and part[2] == fields[2] and len(data) == count,
                    'inconsistent bounded Objects export')
        output.extend(data)
    output = bytes(output)
    pkg.require(len(output) == fields[2] and hashlib.sha256(output).digest() == content_hash,
                'exported object SHA-256 mismatch')
    return fields, output


def app_call(client, instance, op, handle, a=0, b=0, data=b''):
    pkg.require(len(data) <= 512, 'native command payload exceeds512 bytes')
    raw = client.request(150, struct.pack('<Q8Q', instance, op, handle, a, b, 0, 0, 0, 1) + data)
    pkg.require(len(raw) >= 64, 'short native component reply')
    fields = struct.unpack_from('<8Q', raw)
    pkg.require(fields[0] == 0, f'native component denied command: status{fields[0]}')
    return fields, raw[64:]


def load_live(project):
    metadata, current, source, extracted, baseline = rel.load_project(project)
    state = rel.read_json(Path(project) / 'live.json')
    pkg.exact_keys(state, ('schema', 'source_handle', 'head_handle', 'head_object_id',
                           'head_object_sha256', 'object_content_sha256'), 'live REL state')
    pkg.require(state['schema'] == 1 and state['head_object_sha256'] == current['sha256'],
                'live REL head differs from its explicit local snapshot')
    for field in ('source_handle', 'head_handle', 'head_object_id'):
        pkg.integer(state[field], field, 1, (1 << 64) - 1)
    pkg.digest(state['object_content_sha256'], 'live semantic content hash')
    return metadata, current, source, extracted, baseline, state


def semantic_from_bytes(raw, metadata):
    pkg.require(len(raw) <= MAX_RECORD, 'REL semantic object exceeds4KiB')
    value = pkg.parse_json(raw)
    content = rel.validate_record(value, 'Object')
    pkg.exact_keys(content, ('schema', 'record_type', 'object_schema', 'value',
                             'source_sha256', 'parent_object'), 'live REL semantic object')
    pkg.require(content['object_schema'] == 'REL-ByteRotation-v1'
                and content['source_sha256'] == metadata['content']['source_sha256'],
                'live semantic source/schema binding mismatch')
    rel.validate_semantic(content['value'])
    return value


def authoritative(client, project):
    metadata, current, source, extracted, baseline, state = load_live(project)
    fields, raw = fetch(client, state['head_handle'], MAX_RECORD)
    value = semantic_from_bytes(raw, metadata)
    pkg.require(value == current and fields[7] == state['head_object_id']
                and digest(raw) == state['object_content_sha256'],
                'running Objects head does not match the selected REL project; reimport after an ephemeral reset')
    return metadata, current, source, extracted, baseline, state, fields, raw


def import_source(source, output, license_id, authorization, socket):
    # Validate before creating either project snapshots or service state.
    source = Path(source)
    source_bytes = pkg.bounded_file(source, rel.SOURCE_LIMIT, 'REL source')
    rel.extract(source_bytes)
    output = Path(output).absolute()
    result = rel.import_source(source, output, license_id, authorization)
    metadata, current, _, _, _ = rel.load_project(output)
    client = client_for(socket)
    source_handle = object_handle = None
    try:
        source_handle = client.import_object(source_bytes, 1)
        object_handle = client.import_object(pkg.canonical(current), 2, source_handle)
        fields, raw = fetch(client, object_handle, MAX_RECORD)
        pkg.require(semantic_from_bytes(raw, metadata) == current, 'imported semantic record changed')
        state = {'schema': 1, 'source_handle': source_handle, 'head_handle': object_handle,
                 'head_object_id': fields[7], 'head_object_sha256': current['sha256'],
                 'object_content_sha256': digest(raw)}
        atomic_json(output / 'live.json', state)
        return {**result, **state, 'guest_parent_object_id': fields[3],
                'lifetime': 'guest handles are ephemeral; host source snapshots are explicit project artifacts'}
    except BaseException:
        for handle in (object_handle, source_handle):
            if handle is not None:
                try: client.objects(8, handle)
                except Exception: pass
        # Keep the explicit source snapshot for a useful diagnostic/retry; no
        # live.json is written unless the running-service import succeeded.
        raise
    finally:
        client.close()


def chain_nodes(project, current):
    nodes, node = [], current
    while True:
        pkg.require(len(nodes) < 32, 'REL semantic ancestry exceeds32 records')
        rel.validate_record(node, 'Object')
        nodes.append(node)
        if node['content']['parent_object'] is None:
            return nodes
        node = rel.read_json(Path(project) / 'objects' / (node['content']['parent_object'] + '.json'))


def chain_length(project, current):
    return len(chain_nodes(project, current))


def edit(project, shift, workbench, socket):
    client = client_for(socket)
    try:
        metadata, old, _, _, _, state, old_fields, old_bytes = authoritative(client, project)
        pkg.integer(shift, 'edited shift', 0, old['content']['value']['width'] - 1)
        pkg.require(chain_length(project, old) < 32, 'REL lineage is bounded to32 semantic revisions')
        semantic = dict(old['content']['value'], shift=shift)
        proposed = rel.semantic_record(semantic, metadata['content']['source_sha256'], old['sha256'])
        replacement = pkg.canonical(proposed)
        pkg.require(len(replacement) <= 512, 'semantic patch exceeds the native512-byte replacement bound')
        granted = client.objects(6, state['head_handle'], workbench, 13)[0][1]
        try:
            reply, _ = app_call(client, workbench, 23, granted, 0, len(old_bytes), replacement)
        finally:
            client.objects(7, state['head_handle'], granted)
        handle = reply[1]
        fields, actual = fetch(client, handle, MAX_RECORD)
        validated = semantic_from_bytes(actual, metadata)
        pkg.require(actual == replacement and validated == proposed and fields[3] == old_fields[7],
                    'native Workbench did not produce the requested semantic revision and parent lineage')
        path = Path(project) / 'objects' / (validated['sha256'] + '.json')
        if path.exists():
            pkg.require(path.read_bytes() == actual, 'existing semantic record has mismatched content')
        else:
            pkg.write_new(path, actual)
        # This explicit host snapshot is updated only after authoritative guest
        # bytes and their SHA/lineage have been exported and validated.
        atomic_json(Path(project) / 'head.json', {'object_sha256': validated['sha256']})
        state.update(head_handle=handle, head_object_id=fields[7], head_object_sha256=validated['sha256'],
                     object_content_sha256=digest(actual))
        atomic_json(Path(project) / 'live.json', state)
        return {**state, 'semantic': semantic, 'parent_object': old['sha256'],
                'edited_by': 'native Workbench operation23 through real Objects IPC'}
    finally:
        client.close()


def lean_source(semantic):
    rel.validate_semantic(semantic)
    return f'''import Guest.LiveApps
namespace Guest.LiveREL
open Guest.LiveSDK
def byte (value : UInt64) : UInt64 :=
  if value >= {semantic['lower']} && value <= {semantic['upper']} then
    (value-{semantic['lower']}+{semantic['shift']})%{semantic['width']}+{semantic['lower']}
  else value
partial def bytes (p n t : UInt64) : UInt64 :=
  if n == 0 then t else bytes (p+1) (n-1) (Guest.store8 p (byte (Guest.load8 p t)) t)
partial def chunks (source target offset total t : UInt64) : UInt64 :=
  if offset == total then t else
    let n := if total-offset > 512 then 512 else total-offset
    let result := read source offset n t
    if result == error || status result != 0 then result else
      if Guest.load64 (wire+8) result != n then Guest.LiveApps.fail 2 result else
        let t := copy (wire+64) chunk n result
        let t := bytes chunk n t
        let result := append target offset chunk n t
        if result == error || status result != 0 then result else
          chunks source target (offset+n) total result

def transform (caller rights source t : UInt64) : UInt64 :=
  let result := metadata source t
  if result == error then Guest.LiveApps.fail 7 result else
  if status result != 0 then result else
    let length := Guest.load64 (wire+16) result
    let kind := Guest.load64 (wire+32) result
    if !Guest.LiveApps.allowed (Guest.load64 (wire+48) result) 13 then Guest.LiveApps.fail 1 result else
      let result := stage length kind source result
      if result == error then Guest.LiveApps.fail 7 result else
      if status result != 0 then result else
        let staged := Guest.load64 (wire+8) result
        let result := chunks source staged 0 length result
        if result == error then Guest.LiveApps.abortWith staged 7 result else
        if status result != 0 then Guest.LiveApps.abortWith staged (status result) result else
          Guest.LiveApps.finishStage caller rights staged result
partial def serve (endpoint t : UInt64) : UInt64 :=
  let n := receive endpoint t
  if n == error then serve endpoint n else
    let caller := Guest.load64 incoming n
    let requestToken := Guest.load64 (incoming+8) n
    let rights := Guest.load64 (incoming+16) n
    let abi := Guest.load64 (incoming+24) n
    let result := if n == 96 && abi == 2 && Guest.LiveApps.allowed rights 0x100000000 &&
                     Guest.load64 command n == 24 && Guest.load64 (command+56) n == 1 then
      transform caller rights (Guest.load64 (command+8) n) n else Guest.LiveApps.fail 1 n
    serve endpoint (reply requestToken result result)
def appMain (initial : UInt64) : UInt64 := serve (self initial) initial
end Guest.LiveREL
'''


def previous_release(project, name):
    path = Path(project) / 'live-releases.json'
    if not path.exists(): return {}, None
    history = rel.read_json(path)
    pkg.require(isinstance(history, dict) and len(history) <= 16, 'invalid bounded live release history')
    return history, history.get(name)


def build(project, socket, sign_key, name, version, output, parent=None):
    client = client_for(socket)
    try:
        metadata, semantic, source, extracted, baseline, state, fields, raw = authoritative(client, project)
    finally:
        client.close()
    releases.project(name)
    history, previous = previous_release(project, name)
    publisher = digest(capsule.modulus(sign_key))
    if previous:
        pkg.require(previous['publisher_key_id'] == publisher, 'publisher change requires a separately named fork')
        pkg.require(tuple(map(int, version.split('.'))) > tuple(map(int, previous['version'].split('.'))),
                    'new release version must increase')
        if parent is not None:
            pkg.require(parent == previous['release_id'], 'release parent differs from the current project release')
        parent = previous['release_id']
    else:
        pkg.require(parent is None, 'initial local release has no established parent')
    source_text = lean_source(semantic['content']['value'])
    generated = pkg.ROOT / 'build' / ('RelLive_' + semantic['sha256'][:24] + '.lean')
    generated.parent.mkdir(exist_ok=True)
    if generated.exists():
        pkg.require(generated.read_text() == source_text, 'generated source identity collision')
    else:
        pkg.write_new(generated, source_text.encode())
    prefix = name + '-' + version.replace('.', '-')
    binary = live_build.app('build.' + generated.stem, 'Guest.LiveREL.appMain', prefix)
    sources = [generated, Path(project) / 'source.py', Path(project) / 'project.json',
               Path(project) / 'head.json', Path(project) / 'live.json',
               pkg.ROOT / 'tools/live_rel.py', pkg.ROOT / 'Guest/LiveApps.lean',
               pkg.ROOT / 'Guest/LiveSDK.lean', pkg.ROOT / 'Guest/Effects.lean',
               pkg.ROOT / 'Guest/Primitives.lean', pkg.ROOT / 'Compiler/Main.lean',
               pkg.ROOT / 'runtime/primitives.S', pkg.ROOT / 'runtime/app.ld',
               pkg.ROOT / 'toolchain.lock.json', pkg.ROOT / 'lean-toolchain']
    sources += [Path(project) / 'objects' / (node['sha256'] + '.json') for node in chain_nodes(project, semantic)]
    sources = [path.relative_to(pkg.ROOT) if path.is_absolute() and path.is_relative_to(pkg.ROOT) else path for path in sources]
    evidence = ['original validated source versus extracted model: all256 byte inputs',
                'semantic snapshot exported from actual Objects service, SHA-256 verified',
                'semantic changes require native Workbench patch, then strict bounded host validation',
                'native consumer execution remains a separate live compare/run check']
    envelope, manifest = releases.make(binary, name, version, NATIVE_RIGHTS, sign_key,
                                      sources, parent, metadata['content']['rights']['license'], evidence)
    output = Path(output)
    pkg.write_new(output, envelope)
    pkg.write_new(Path(str(output) + '.manifest.json'), pkg.canonical(manifest))
    info = releases.inspect(envelope, capsule.modulus(sign_key), manifest)
    report = {'schema': 1, 'record_type': 'Build', 'release': info,
              'semantic_object_sha256': semantic['sha256'], 'objects_content_sha256': digest(raw),
              'objects_id': fields[7], 'source_sha256': digest(source),
              'generated_lean': str(generated), 'generated_lean_sha256': digest(source_text.encode()),
              'binary': str(binary), 'host_build_only': True,
              'limit': 'unverified compiler; original-source equivalence applies to extraction, not edited behavior'}
    pkg.write_new(Path(str(output) + '.build.json'), pkg.canonical(report))
    history[name] = info
    atomic_json(Path(project) / 'live-releases.json', history)
    return report


def process(client, instance, data):
    pkg.require(len(data) <= 65536, 'native REL input exceeds64KiB')
    original = client.import_object(data, 1)
    granted = client.objects(6, original, instance, 13)[0][1]
    try:
        fields, _ = app_call(client, instance, 24, granted)
    finally:
        client.objects(7, original, granted)
    output_handle = fields[1]
    output_fields, output = fetch(client, output_handle)
    input_fields = client.objects(5, original)[0]
    pkg.require(output_fields[3] == input_fields[7], 'native consumer lost source object lineage')
    return original, output_handle, output


def compare(project, socket, instance):
    client = client_for(socket)
    original = output_handle = None
    try:
        metadata, current, source, extracted, _, state, _, _ = authoritative(client, project)
        values = bytes(range(256))
        original, output_handle, actual = process(client, instance, values)
        expected = rel.transform(current['content']['value'], values)
        pkg.require(actual == expected, 'actual native consumer differs from the edited semantic object')
        report = {'schema': 1, 'record_type': 'Evidence', 'native_cases': 256,
                  'instance': instance, 'semantic_object_sha256': current['sha256'],
                  'source_sha256': digest(source), 'actual_output_sha256': digest(actual),
                  'original_source_output_sha256': digest(rel.transform(extracted, values)),
                  'edited_semantics': current['content']['value'] != extracted,
                  'scope': 'selected live user process, brokered input/output and all256 byte values; no compiler proof'}
        path = Path(project) / ('live-evidence-' + current['sha256'] + '.json')
        atomic_json(path, report)
        return report
    finally:
        for handle in (output_handle, original):
            if handle is not None:
                try: client.objects(8, handle)
                except Exception: pass
        client.close()


def run(project, socket, instance, input_path, output_path=None):
    if output_path is not None:
        output_path = Path(output_path)
        pkg.require(not output_path.exists() and output_path.parent.is_dir(), 'native export requires a new file in an existing directory')
    data = pkg.bounded_file(input_path, 65536, 'REL native input')
    client = client_for(socket)
    try:
        _, current, _, _, _, _, _, _ = authoritative(client, project)
        original, handle, actual = process(client, instance, data)
        pkg.require(actual == rel.transform(current['content']['value'], data),
                    'native result differs from the selected semantic object')
        if output_path is not None:
            pkg.write_new(output_path, actual)
        return {'input_handle': original, 'result_handle': handle, 'length': len(actual),
                'sha256': digest(actual), 'exported': str(output_path) if output_path is not None else None}
    finally:
        client.close()


def export(project, destination, socket, release=None, public_key=None):
    client = client_for(socket)
    try:
        metadata, current, _, _, _, _, fields, actual = authoritative(client, project)
    finally:
        client.close()
    destination = Path(destination)
    pkg.require(not destination.exists() and destination.parent.is_dir(), 'export requires a new destination directory')
    with tempfile.TemporaryDirectory(prefix='.live-rel-export-', dir=destination.parent) as directory:
        temporary = Path(directory) / 'project'
        (temporary / 'objects').mkdir(parents=True)
        for node in chain_nodes(project, current):
            pkg.write_new(temporary / 'objects' / (node['sha256'] + '.json'), pkg.canonical(node))
        for name in ('source.py', 'project.json', 'head.json', 'live.json', 'live-releases.json'):
            path = Path(project) / name
            if path.exists(): pkg.write_new(temporary / name, pkg.bounded_file(path, 32768, name))
        pkg.write_new(temporary / 'authoritative-object.json', actual)
        pkg.write_new(temporary / 'provenance.json', pkg.canonical({
            'schema': 1, 'source_sha256': metadata['content']['source_sha256'],
            'semantic_sha256': current['sha256'], 'objects_content_sha256': digest(actual),
            'objects_id': fields[7], 'parent_objects_id': fields[3],
            'limit': 'numeric handles are session-local; reimport source after reset'}))
        generated = lean_source(current['content']['value']).encode()
        generated_name = 'RelLive_' + current['sha256'][:24]
        snapshot_files = ['lt', 'lean-toolchain', 'toolchain.lock.json',
            'Guest/LiveApps.lean', 'Guest/LiveSDK.lean', 'Guest/Effects.lean', 'Guest/Primitives.lean',
            'Compiler/Main.lean', 'runtime/primitives.S', 'runtime/app.S', 'runtime/app.ld',
            'tools/driver.py', 'tools/live_build.py', 'tools/live.py', 'tools/releases.py',
            'tools/capsule.py', 'tools/packaging.py', 'tools/rel.py', 'tools/live_rel.py']
        snapshot = temporary / 'reconstruct'
        source_entries = []
        for relative in snapshot_files:
            source = pkg.ROOT / relative
            target = snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            value = pkg.bounded_file(source, 1048576, 'reconstruction source')
            pkg.write_new(target, value)
            source_entries.append({'path': relative, 'sha256': digest(value), 'length': len(value)})
        target = snapshot / 'build' / (generated_name + '.lean')
        target.parent.mkdir(parents=True, exist_ok=True)
        pkg.write_new(target, generated)
        recipe = {'schema': 1, 'module': 'build.' + generated_name, 'entry': 'Guest.LiveREL.appMain',
            'command': ['python3', 'lt', 'live-app', '--module', 'build.' + generated_name,
                        '--entry', 'Guest.LiveREL.appMain', '--name', 'reconstructed-rel'],
            'generated_source_sha256': digest(generated), 'sources': source_entries,
            'requirements': 'install exact toolchain.lock.json versions, or configure matching LT_ tool paths'}
        pkg.write_new(snapshot / 'reconstruction.json', pkg.canonical(recipe))
        if release is not None:
            pkg.require(public_key is not None, 'release export requires an explicit trusted public key')
            envelope = pkg.bounded_file(release, 66304, 'selected native release')
            manifest = pkg.parse_json(pkg.bounded_file(Path(str(release) + '.manifest.json'), 65536, 'release manifest'))
            modulus = releases.public_modulus(public_key)
            info = releases.inspect(envelope, modulus, manifest)
            pkg.require(any(item.get('sha256') == digest(generated) for item in manifest['sources']),
                        'selected release does not commit this generated semantic consumer')
            pkg.write_new(temporary / 'release.ltexe', envelope)
            pkg.write_new(temporary / 'release.ltexe.manifest.json', pkg.canonical(manifest))
            pkg.write_new(temporary / 'publisher-modulus.bin', modulus)
        os.rename(temporary, destination)
    return {'directory' : str(destination), 'semantic_sha256': current['sha256'],
            'objects_content_sha256': digest(actual)}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Source-first REL using actual live Objects and native Workbench')
    commands = parser.add_subparsers(dest='command', required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--socket', type=Path, required=True)
    command = commands.add_parser('import', parents=[common])
    command.add_argument('source', type=Path); command.add_argument('--output', type=Path, required=True)
    command.add_argument('--license', required=True); command.add_argument('--authorization', required=True)
    command = commands.add_parser('edit', parents=[common])
    command.add_argument('project', type=Path); command.add_argument('--shift', type=int, required=True)
    command.add_argument('--workbench', type=lambda value: int(value, 0), required=True)
    command = commands.add_parser('build', parents=[common])
    command.add_argument('project', type=Path); command.add_argument('--sign-key', type=Path, required=True)
    command.add_argument('--name', required=True); command.add_argument('--version', required=True)
    command.add_argument('--output', type=Path, required=True); command.add_argument('--parent')
    for name in ('compare', 'run'):
        command = commands.add_parser(name, parents=[common]); command.add_argument('project', type=Path)
        command.add_argument('--instance', type=lambda value: int(value, 0), required=True)
        if name == 'run':
            command.add_argument('--input', type=Path, required=True); command.add_argument('--output', type=Path)
    command = commands.add_parser('export', parents=[common])
    command.add_argument('project', type=Path); command.add_argument('--output', type=Path, required=True)
    command.add_argument('--release', type=Path); command.add_argument('--public-key', type=Path)
    args = parser.parse_args(argv)
    if args.command == 'import': result = import_source(args.source, args.output, args.license, args.authorization, args.socket)
    elif args.command == 'edit': result = edit(args.project, args.shift, args.workbench, args.socket)
    elif args.command == 'build': result = build(args.project, args.socket, args.sign_key, args.name, args.version, args.output, args.parent)
    elif args.command == 'compare': result = compare(args.project, args.socket, args.instance)
    elif args.command == 'run': result = run(args.project, args.socket, args.instance, args.input, args.output)
    else: result = export(args.project, args.output, args.socket, args.release, args.public_key)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
