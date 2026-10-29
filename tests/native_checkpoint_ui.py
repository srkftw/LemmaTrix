"""Graphical source-only checkpoint using actual input and presented glyphs."""
import json,struct,sys,types,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import projects,releases
from creator_journey import Journey,rendered_text,require
out=ROOT/'build/native-checkpoint-ui';out.mkdir(exist_ok=False)
key=ROOT/'build/campaign003-publisher.pem';public=ROOT/'build/campaign003-publisher.pub'
binary=ROOT/'build/live/desktop-checkpoint.bin'
release,manifest=releases.make(binary,'native-editor','4.0.0',895,key,profile=2)
package=out/'editor.ltrel';package.write_bytes(release);Path(str(package)+'.manifest.json').write_text(json.dumps(manifest,separators=(',',':'),sort_keys=True))
a=types.SimpleNamespace(output=out,public=public)
j=Journey(a)
try:
 j.boot(False);j.trust_stage(package,'native-editor');j.ui.press(1);time.sleep(.2)
 with j.client() as c:
  source=b'def value : UInt64 := 7\n';sourceid=projects.canonical_node(10,source)
  body=projects.manifest([('Main.lean',10,sourceid)]);head=projects.canonical_node(11,body)
  imported=projects.import_records(c,[dict(name='ui-checkpoint',head=head)],[dict(kind=11,id=head,payload=body),dict(kind=10,id=sourceid,payload=source)])[0]
  procs=c.request(2);shell=struct.unpack_from('<Q',procs,4*32)[0];c.objects(27,imported['cap'],shell,127)
  logical=projects.project_identity(c,imported['cap'])
 j.open_named_project('ui-checkpoint')
 j.ui.chord(29,37);j.wait_text(8,233,'Checkpoint current source only?');time.sleep(.2)
 frame=j.ui.frame();(out/'scope.ppm').write_bytes(frame.ppm())
 j.ui.press(28);j.wait_text(8,233,'Checkpoint complete.');time.sleep(.2)
 frame=j.ui.frame();(out/'complete.ppm').write_bytes(frame.ppm())
 j.ui.press(1);j.ui.chord(29,30);j.ui.textASCII('def value : UInt64 := 19\n',delay=.03);j.ui.press(62);time.sleep(.5)
 with j.client() as c:
  root=next(r for r in projects.roots(c) if r['name']=='ui-checkpoint')
  actual,files=projects.snapshot(c,root['cap']);assert files['Main.lean']==b'def value : UInt64 := 19\n'
  assert projects.project_identity(c,root['cap'])==logical
 j.passed('native Ctrl-K scope prompt, physical Enter checkpoint, actual completion glyphs, edited source after cap reload',project_id=logical,current_head=actual,source=files['Main.lean'].decode())
finally:
 if j.proc and j.proc.poll() is None:j.stop(hard=True)
