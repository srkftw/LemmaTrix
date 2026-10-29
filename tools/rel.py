"""Restricted source-first REL import, semantic editing, native reconstruction.

This host tool accepts one explicit byte-transform grammar, not arbitrary Python.
Its generated Lean component is compiled by the normal freestanding backend and
executes object read/revise IPC inside the real user compartment. It is not the
native IDE or the Luanti/Lugaru release acceptance fixture.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

try:
    from . import packaging as pkg
except ImportError:
    import packaging as pkg

CAPS = ['console.write', 'object.create', 'object.read', 'object.revise']
SOURCE_LIMIT = 16384
PREFIX = 'LT-REL-RESULT:'


def record(kind, value):
    content = {'schema': 1, 'record_type': kind, **value}
    return {'content': content, 'sha256': pkg.sha256(pkg.canonical(content))}


def validate_record(value, kind):
    pkg.exact_keys(value, ('content', 'sha256'), kind + ' record')
    pkg.require(isinstance(value['content'], dict) and value['content'].get('schema') == 1 and type(value['content'].get('schema')) is int
                and value['content'].get('record_type') == kind, 'invalid ' + kind + ' record')
    pkg.digest(value['sha256'], kind + ' hash')
    pkg.require(pkg.sha256(pkg.canonical(value['content'])) == value['sha256'], kind + ' record hash mismatch')
    return value['content']


def _integer(node, constants):
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.Name) and node.id in constants:
        return constants[node.id]
    raise pkg.PackageError('REL source: expected a literal or declared integer constant')


def _name(node, expected):
    pkg.require(isinstance(node, ast.Name) and node.id == expected, 'REL source: unexpected variable')


def _bin(node, operator):
    pkg.require(isinstance(node, ast.BinOp) and isinstance(node.op, operator),
                'REL source: unsupported arithmetic expression')
    return node.left, node.right


def extract(source):
    """Extract a conditional affine/modular byte transform from validated AST."""
    pkg.require(isinstance(source, bytes) and len(source) <= SOURCE_LIMIT, 'REL source exceeds 16 KiB')
    try:
        tree = ast.parse(source.decode('utf-8'))
    except (SyntaxError, UnicodeError, RecursionError) as exc:
        raise pkg.PackageError('REL source must be bounded valid UTF-8 Python') from exc
    constants, function = {}, None
    for statement in tree.body:
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str):
            continue
        if isinstance(statement, ast.Assign):
            pkg.require(len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name)
                        and statement.targets[0].id not in constants and len(constants) < 16,
                        'REL source: unsupported constant assignment')
            value = _integer(statement.value, {})
            pkg.require(0 <= value <= 255, 'REL source constant outside byte range')
            pkg.require(statement.targets[0].id not in ('int', 'transform_byte', '__builtins__'),
                        'REL source: reserved constant name')
            constants[statement.targets[0].id] = value
        elif isinstance(statement, ast.FunctionDef):
            pkg.require(function is None and statement.name == 'transform_byte',
                        'REL source supports exactly one transform_byte function')
            function = statement
        else:
            raise pkg.PackageError('REL source: unsupported top-level statement; no source execution permitted')
    pkg.require(function is not None, 'REL source has no transform_byte function')
    args = function.args
    pkg.require(len(args.args) == 1 and not args.posonlyargs and not args.defaults
                and not args.kwonlyargs and args.vararg is None and args.kwarg is None
                and not function.decorator_list and not getattr(function, 'type_params', []),
                'REL source: unsupported function arguments or decorators')
    for annotation in (args.args[0].annotation, function.returns):
        pkg.require(annotation is None or (isinstance(annotation, ast.Name) and annotation.id == 'int'),
                    'REL source: only int annotations are supported')
    variable = args.args[0].arg
    pkg.require(variable not in constants and variable != function.name,
                'REL source variable collides with a constant/function')
    pkg.require(len(function.body) == 2 and isinstance(function.body[0], ast.If)
                and isinstance(function.body[1], ast.Return), 'REL source: expected conditional transform and identity return')
    branch = function.body[0]
    condition = branch.test
    pkg.require(isinstance(condition, ast.Compare) and len(condition.ops) == 2
                and all(isinstance(op, ast.LtE) for op in condition.ops)
                and len(condition.comparators) == 2, 'REL source: expected lower <= byte <= upper')
    lower = _integer(condition.left, constants)
    _name(condition.comparators[0], variable)
    upper = _integer(condition.comparators[1], constants)
    pkg.require(0 <= lower <= upper <= 255, 'REL source: invalid byte interval')
    pkg.require(len(branch.body) == 1 and isinstance(branch.body[0], ast.Return) and not branch.orelse,
                'REL source: unsupported branch body')
    modulo, origin = _bin(branch.body[0].value, ast.Add)
    addition, width = _bin(modulo, ast.Mod)
    subtraction, shift = _bin(addition, ast.Add)
    operand, base = _bin(subtraction, ast.Sub)
    _name(operand, variable)
    width, shift = _integer(width, constants), _integer(shift, constants)
    pkg.require(_integer(base, constants) == lower and _integer(origin, constants) == lower,
                'REL source: arithmetic origin must equal interval lower bound')
    pkg.require(width == upper - lower + 1 and 0 <= shift < width,
                'REL source: modulus/shift does not match byte interval')
    _name(function.body[1].value, variable)
    semantic = {'kind': 'bounded-byte-rotation', 'lower': lower, 'upper': upper, 'width': width, 'shift': shift}
    # Executing this exact validated AST supplies the actual source baseline.
    # The grammar admits no calls, imports, attributes, loops or arbitrary effects.
    environment = {'__builtins__': {}, 'int': int}
    exec(compile(tree, '<authorized-rel-source>', 'exec'), environment)
    original = environment['transform_byte']
    baseline = bytes(original(value) for value in range(256))
    expected = bytes(transform_byte(semantic, value) for value in range(256))
    pkg.require(baseline == expected, 'REL extractor does not preserve the source on all byte inputs')
    return semantic, baseline


def transform_byte(semantic, value):
    if semantic['lower'] <= value <= semantic['upper']:
        return (value - semantic['lower'] + semantic['shift']) % semantic['width'] + semantic['lower']
    return value


def transform(semantic, data):
    return bytes(transform_byte(semantic, value) for value in data)


def semantic_record(semantic, source_hash, parent=None):
    return record('Object', {'object_schema': 'REL-ByteRotation-v1', 'value': semantic,
                            'source_sha256': source_hash, 'parent_object': parent})


def validate_semantic(value):
    pkg.exact_keys(value, ('kind', 'lower', 'upper', 'width', 'shift'), 'semantic byte transform')
    pkg.require(value['kind'] == 'bounded-byte-rotation', 'unsupported REL semantic object')
    for name in ('lower', 'upper', 'shift'):
        pkg.integer(value[name], 'semantic ' + name, 0, 255)
    pkg.integer(value['width'], 'semantic width', 1, 256)
    pkg.require(value['lower'] <= value['upper'] and value['width'] == value['upper'] - value['lower'] + 1
                and value['shift'] < value['width'], 'semantic rotation bounds are inconsistent')
    return value


def read_json(path, maximum=32768):
    return pkg.parse_json(pkg.bounded_file(path, maximum, 'REL record'))


def load_project(project):
    project = Path(project)
    metadata = read_json(project / 'project.json')
    manifest = validate_record(metadata, 'Project')
    pkg.exact_keys(manifest, ('schema', 'record_type', 'source_sha256', 'source_file',
                            'rights', 'initial_object', 'limitations'), 'REL project')
    pkg.digest(manifest['source_sha256'], 'REL source hash')
    pkg.require(manifest['source_file'] == 'source.py', 'unsupported REL source filename')
    source = pkg.bounded_file(project / 'source.py', SOURCE_LIMIT, 'REL source')
    pkg.require(pkg.sha256(source) == manifest['source_sha256'], 'REL source snapshot hash mismatch')
    extracted, baseline = extract(source)
    head = read_json(project / 'head.json')
    pkg.exact_keys(head, ('object_sha256',), 'REL head')
    pkg.digest(head['object_sha256'], 'REL head')
    current = read_json(project / 'objects' / (head['object_sha256'] + '.json'))
    semantic = validate_record(current, 'Object')
    pkg.exact_keys(semantic, ('schema', 'record_type', 'object_schema', 'value',
                             'source_sha256', 'parent_object'), 'REL semantic object')
    pkg.require(current['sha256'] == head['object_sha256']
                and semantic['source_sha256'] == manifest['source_sha256']
                and semantic['object_schema'] == 'REL-ByteRotation-v1', 'REL provenance/object binding mismatch')
    validate_semantic(semantic['value'])
    # Every edit retains a complete bounded chain to the extracted original.
    pkg.digest(manifest['initial_object'], 'REL initial object')
    ancestor = current
    visited = set()
    while True:
        pkg.require(len(visited) < 32 and ancestor['sha256'] not in visited,
                    'REL semantic lineage is cyclic or exceeds 32 objects')
        visited.add(ancestor['sha256'])
        node = validate_record(ancestor, 'Object')
        pkg.exact_keys(node, ('schema', 'record_type', 'object_schema', 'value',
                             'source_sha256', 'parent_object'), 'REL lineage object')
        pkg.require(node['source_sha256'] == manifest['source_sha256']
                    and node['object_schema'] == 'REL-ByteRotation-v1', 'REL lineage source/schema mismatch')
        validate_semantic(node['value'])
        parent = node['parent_object']
        if parent is None:
            pkg.require(ancestor['sha256'] == manifest['initial_object'] and node['value'] == extracted,
                        'REL lineage does not terminate at the extracted original')
            break
        pkg.digest(parent, 'REL parent object')
        ancestor = read_json(project / 'objects' / (parent + '.json'))
        pkg.require(ancestor['sha256'] == parent, 'REL parent object hash/path mismatch')
    pkg.exact_keys(manifest['rights'], ('license', 'authorization'), 'REL rights')
    pkg.text(manifest['rights']['license'], 'REL source license', 128)
    pkg.text(manifest['rights']['authorization'], 'REL source authorization', 1024)
    return metadata, current, source, extracted, baseline


def import_source(source_path, output, license_id, authorization):
    source = pkg.bounded_file(source_path, SOURCE_LIMIT, 'REL source')
    semantic, baseline = extract(source)
    pkg.text(license_id, 'REL source license', 128)
    pkg.text(authorization, 'REL source authorization', 1024)
    source_hash = pkg.sha256(source)
    obj = semantic_record(semantic, source_hash)
    project = record('Project', {'source_sha256': source_hash, 'source_file': 'source.py',
        'rights': {'license': license_id, 'authorization': authorization}, 'initial_object': obj['sha256'],
        'limitations': ['Restricted original local byte-transform fixture; not a general foreign-language frontend.',
                        'Host import/edit/build tooling; generated Lean component executes in the guest.',
                        'No Luanti/Lugaru or full REL release-gate completion is claimed.']})
    output = Path(output).absolute()
    pkg.require(output.parent.is_dir() and not output.exists(), 'REL import requires a new directory with an existing parent')
    with tempfile.TemporaryDirectory(prefix='.lt-rel-import-', dir=output.parent) as directory:
        temporary = Path(directory) / 'project'
        (temporary / 'objects').mkdir(parents=True)
        (temporary / 'source.py').write_bytes(source)
        (temporary / 'project.json').write_bytes(pkg.canonical(project))
        (temporary / 'objects' / (obj['sha256'] + '.json')).write_bytes(pkg.canonical(obj))
        (temporary / 'head.json').write_bytes(pkg.canonical({'object_sha256': obj['sha256']}))
        os.rename(temporary, output)
    return {'project': str(output), 'source_sha256': source_hash, 'object_sha256': obj['sha256'],
            'source_differential_cases': len(baseline), 'semantic': semantic}


def edit(project, shift):
    metadata, old, _, _, _ = load_project(project)
    pkg.integer(shift, 'edited shift', 0, old['content']['value']['width'] - 1)
    semantic = dict(old['content']['value'], shift=shift)
    obj = semantic_record(semantic, metadata['content']['source_sha256'], old['sha256'])
    destination = Path(project) / 'objects' / (obj['sha256'] + '.json')
    if destination.exists():
        pkg.require(destination.read_bytes() == pkg.canonical(obj), 'existing semantic hash collision/content mismatch')
    else:
        pkg.write_new(destination, pkg.canonical(obj))
    head = Path(project) / 'head.json'
    with tempfile.NamedTemporaryFile(prefix='.head-', dir=head.parent, delete=False) as temporary:
        temporary.write(pkg.canonical({'object_sha256': obj['sha256']}))
        temp_path = Path(temporary.name)
    os.replace(temp_path, head)
    return {'object_sha256': obj['sha256'], 'parent_object': old['sha256'], 'semantic': semantic}


def lean_source(semantic):
    validate_semantic(semantic)
    return f'''import Guest.SDK
namespace Guest
-- Generated from an authorized REL semantic object, not a fixed native payload.
def relTransformByte (value : UInt64) : UInt64 :=
  if value >= {semantic['lower']} && value <= {semantic['upper']} then
    (value-{semantic['lower']}+{semantic['shift']})%{semantic['width']}+{semantic['lower']}
  else value
partial def relTransform (p n token : UInt64) : UInt64 :=
  if n == 0 then token else
    let value := relTransformByte (load8 p token)
    relTransform (p+1) (n-1) (store8 p value token)
partial def relCopy (src dst n token : UInt64) : UInt64 :=
  if n == 0 then token else
    relCopy (src+1) (dst+1) (n-1) (store8 dst (load8 src token) token)
def relPrefix (initial : UInt64) : UInt64 :=
{literal_stores(PREFIX.encode())}
partial def relHex (p n token : UInt64) : UInt64 :=
  if n == 0 then consoleWrite 1 (store8 buffer 10 token) else
    let value := load8 p token
    let high := value >>> 4
    let low := value &&& 15
    let token := store8 buffer (if high < 10 then high+48 else high+87) token
    let token := store8 (buffer+1) (if low < 10 then low+48 else low+87) token
    relHex (p+1) (n-1) (consoleWrite 2 token)
def appMain (initial : UInt64) : UInt64 :=
  let len := objectRead 256 256 initial
  if len > 256 then len else
    let token := relTransform buffer len len
    let revision := objectRevise 256 len token
    if revision == 0xffffffffffffffff then revision else
      let token := relCopy buffer (buffer+512) len revision
      let token := relPrefix token
      relHex (buffer+512) len token
end Guest
'''


def literal_stores(value):
    lines = []
    for index, byte in enumerate(value):
        lines.append(f'  let token := store8 (buffer+{index}) {byte} ' + ('initial' if index == 0 else 'token'))
    lines.append(f'  consoleWrite {len(value)} token')
    return '\n'.join(lines)


def generate(project, output):
    metadata, semantic, _, _, _ = load_project(project)
    code = lean_source(semantic['content']['value']).encode()
    pkg.write_new(output, code)
    return {'lean': str(output), 'lean_sha256': pkg.sha256(code), 'object_sha256': semantic['sha256'],
            'source_sha256': metadata['content']['source_sha256']}


def build(project, *, sign_key, public_key, name='rel-component', version='1.0.0', text='Authorized REL source fixture.\n', backends=()):
    """Compile actual generated Lean, sign/export it, and optionally run a guest."""
    import driver
    metadata, semantic, source, original, baseline = load_project(project)
    data = text.encode('utf-8')
    pkg.require(len(data) <= 256, 'REL input text exceeds the SDK 256-byte bound')
    pkg.require(re.fullmatch('[a-z0-9][a-z0-9-]{0,31}', name) is not None, 'invalid REL build name')
    project = Path(project).absolute()
    pkg.require(project.is_relative_to(pkg.ROOT), 'REL native builds require a project inside this checkout')
    driver.BUILD.mkdir(exist_ok=True)
    # Existing SDK/backend APIs handle every generated function and primitive.
    for part in ('Primitives', 'SDK'):
        driver.lean(['-o', f'Guest/{part}.olean', f'Guest/{part}.lean'])
    generated = driver.BUILD / 'RelGenerated.lean'
    generated.write_text(lean_source(semantic['content']['value']), encoding='utf-8')
    driver.lean(['-o', generated.with_suffix('.olean'), generated])
    driver.compile_guest('build.RelGenerated', ['Guest.appMain'], name, 'runtime/app.S', 'runtime/app.ld')
    package = project / (name + '-' + version + '.ltpkg')
    source_paths = [generated, project / 'source.py', project / 'project.json',
                    project / 'head.json',
                    pkg.ROOT / 'tools/rel.py',
                    pkg.ROOT / 'Guest/SDK.lean', pkg.ROOT / 'Guest/Primitives.lean',
                    pkg.ROOT / 'Compiler/Main.lean', pkg.ROOT / 'runtime/app.S',
                    pkg.ROOT / 'runtime/app.ld', pkg.ROOT / 'runtime/primitives.S',
                    pkg.ROOT / 'toolchain.lock.json', pkg.ROOT / 'lean-toolchain']
    source_paths += sorted((project / 'objects').glob('*.json'))
    arguments = ['create', '--name', name, '--version', version,
                 '--elf', str(driver.BUILD / (name + '.elf')),
                 '--binary', str(driver.BUILD / (name + '.bin')),
                 '--sign-key', str(sign_key), '--output', str(package),
                 '--license', metadata['content']['rights']['license'],
                 '--distribution-authority', metadata['content']['rights']['authorization'],
                 '--parent', semantic['sha256'], '--evidence', 'REL restricted original-source differential: all 256 byte inputs matched extraction',
                 '--limitation', 'Semantic edits intentionally change source behavior; source equivalence is claimed only for the extracted original.']
    for path in source_paths:
        arguments += ['--source', str(path)]
    for capability in CAPS:
        arguments += ['--capability', capability]
    release = pkg.create(pkg.parser().parse_args(arguments))
    policy = dict(allow_development=True, trust_keys=[public_key], approved_caps=CAPS, require_signature=True)
    pkg.check(package, **policy)
    expected = transform(semantic['content']['value'], data)
    original_result = transform(original, data)
    report = {'schema': 1, 'record_type': 'Evidence', 'source_sha256': pkg.sha256(source),
              'semantic_object': semantic['sha256'], 'source_extraction_cases': len(baseline),
              'release': release, 'input_hex': data.hex(), 'source_baseline_hex': original_result.hex(),
              'component_expected_hex': expected.hex(), 'source_equivalent_on_all_bytes':
                  all(transform_byte(semantic['content']['value'], index) == baseline[index] for index in range(256)),
              'guest': []}
    if backends:
        driver.build(text, package=package, policy=policy)
        driver.emulators()
        image_hash = pkg.sha256((driver.BUILD / 'guest.bin').read_bytes())
        for backend in backends:
            output = driver.backend(backend)
            results = re.findall(r'^' + PREFIX + r'([0-9a-f]*)$', output, re.MULTILINE)
            pkg.require(len(results) == 1 and bytes.fromhex(results[0]) == expected,
                        'REL native output differs from the extracted/edited semantic computation on ' + backend)
            pkg.require('SESSION PASS' in output, 'REL guest session failed on ' + backend)
            report['guest'].append({'backend': backend, 'image_sha256': image_hash,
                                    'actual_hex': results[0], 'differential': 'pass'})
    evidence = project / (name + '-' + version + '-evidence.json')
    pkg.write_new(evidence, pkg.canonical(report))
    return report



def check():
    """Check importer confinement, semantic edits, and provenance failures."""
    cases = []
    def rejected(label, operation):
        try:
            operation()
        except (pkg.PackageError, OSError):
            cases.append(label)
            return
        raise pkg.PackageError(label + ': invalid REL input was accepted')
    source = pkg.bounded_file(pkg.ROOT / 'examples/rel/rotation.py', SOURCE_LIMIT, 'fixture')
    semantic, baseline = extract(source)
    pkg.require(len(baseline) == 256 and baseline[ord('a')] == ord('f')
                and baseline[ord('Z')] == ord('Z'), 'fixture extraction/baseline failed')
    cases.append('actual restricted source differential covers all 256 byte inputs')
    rejected('executable top-level source rejected', lambda: extract(source + b'\nprint("side effect")\n'))
    rejected('arbitrary source call rejected', lambda: extract(source.replace(b'return value', b'return abs(value)')))
    rejected('annotation execution rejected', lambda: extract(source.replace(b'value: int', b'value: print("unsafe")')))
    rejected('unsupported arithmetic rejected', lambda: extract(source.replace(b'% 26', b'// 26')))
    with tempfile.TemporaryDirectory(prefix='lt-rel-check-') as directory:
        directory = Path(directory)
        project = directory / 'project'
        import_source(pkg.ROOT / 'examples/rel/rotation.py', project, 'CC0-1.0', 'local original test fixture')
        first = load_project(project)[1]
        changed = edit(project, 7)
        _, current, snapshot, _, _ = load_project(project)
        pkg.require(current['content']['parent_object'] == first['sha256'] and source == snapshot,
                    'semantic edit did not preserve source/lineage')
        pkg.require(transform(current['content']['value'], b'abcZ') == b'hijZ', 'edited semantic computation failed')
        cases.append('semantic edit creates successor and preserves exact original source')
        generated = directory / 'Generated.lean'
        generate(project, generated)
        pkg.require(b'value-97+7' in generated.read_bytes(), 'edited semantic value did not reach real Lean source')
        cases.append('generated Lean contains edited computation and actual SDK calls')
        rejected('out-of-range semantic edit denied', lambda: edit(project, 26))
        obj_path = project / 'objects' / (current['sha256'] + '.json')
        obj = read_json(obj_path)
        obj['content']['value']['shift'] = 8
        obj_path.write_bytes(pkg.canonical(obj))
        rejected('tampered semantic hash denied before generation', lambda: generate(project, directory / 'Tampered.lean'))
        pkg.require(not (directory / 'Tampered.lean').exists(), 'denied generation wrote a component')
        obj_path.write_bytes(pkg.canonical(current))
        (project / 'source.py').write_bytes(source + b'\n')
        rejected('changed source snapshot denied before generation', lambda: load_project(project))
    return {'result': 'REL CHECK PASS', 'checks': cases, 'count': len(cases),
            'scope': 'host importer/extractor/lineage checks; actual guest differential evidence is produced by rel build --backend'}


def parser():
    parser = argparse.ArgumentParser(description='Authorized source-first REL byte-transform fixture')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('check')
    importer = commands.add_parser('import')
    importer.add_argument('--source', required=True, type=Path)
    importer.add_argument('--output', required=True, type=Path)
    importer.add_argument('--license', required=True)
    importer.add_argument('--authorization', required=True)
    editor = commands.add_parser('edit')
    editor.add_argument('project', type=Path)
    editor.add_argument('--shift', required=True, type=int)
    generator = commands.add_parser('generate')
    generator.add_argument('project', type=Path)
    generator.add_argument('--output', required=True, type=Path)
    builder = commands.add_parser('build')
    builder.add_argument('project', type=Path)
    builder.add_argument('--sign-key', required=True, type=Path)
    builder.add_argument('--public-key', required=True, type=Path)
    builder.add_argument('--name', default='rel-component')
    builder.add_argument('--version', default='1.0.0')
    builder.add_argument('--text', default='Authorized REL source fixture.\n')
    builder.add_argument('--backend', choices=('qemu', 'x86_64', 'aarch64'), action='append', default=[])
    return parser


def main(argv=None):
    args = parser().parse_args(argv)
    os.chdir(pkg.ROOT)
    try:
        if args.command == 'check':
            result = check()
        elif args.command == 'import':
            result = import_source(args.source, args.output, args.license, args.authorization)
        elif args.command == 'edit':
            result = edit(args.project, args.shift)
        elif args.command == 'generate':
            result = generate(args.project, args.output)
        else:
            result = build(args.project, sign_key=args.sign_key, public_key=args.public_key,
                           name=args.name, version=args.version, text=args.text, backends=args.backend)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (pkg.PackageError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print('lt rel:', exc, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
