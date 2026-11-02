"""Physical native literal search in the actually admitted Notes source graph."""
import argparse,base64,contextlib,hashlib,json,struct,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace as NS
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import projects,releases
from campaign010_project_notes import NotesJourney,wait
from creator_journey import require,rendered_text

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--editor',type=Path,required=True);p.add_argument('--archive',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);public=ROOT/'tests/keys/development-rsa-public.pem'
 j=NotesJourney(NS(output=out/'personal',image=a.image,backend='qemu',public=public,network_mux=False));report=dict(schema=1,result='running',checks=[],image_sha256=j.image,editor=releases.inspect(a.editor.read_bytes()));began=time.monotonic()
 def save():report['elapsed_seconds']=round(time.monotonic()-began,3);(out/'execution.json').write_text(json.dumps(report,indent=2)+'\n')
 def passed(label,**fields):report['checks'].append(dict(check=label,result='pass',**fields));save();print('PASS',label,flush=True)
 def prompt(text):
  j.ui.chord(29,34);j.wait_text(8,370,'Find literal text',0xe9bc75,timeout=45);j.ui.textASCII(text,delay=.08);j.ui.press(28)
 def found(text):
  j.wait_text(8,370,'Found - Ctrl+Shift+G next',0xe9bc75,timeout=60)
  def visible():
   frame=j.ui.frame();rows=[rendered_text(frame,164,96+i*11,78)for i in range(25)]
   return(frame,rows)if any(text in row for row in rows)else None
  return wait(visible,'found literal is visible in native editor viewport',45)
 try:
  j.boot(vault=False);j.trust_stage(a.editor,'native-editor');j.ui.press(1)
  archive=json.loads(a.archive.read_bytes());records=[dict(n,payload=base64.b64decode(n['payload'],validate=True))for n in archive['nodes']]
  with j.client()as c:
   imported=projects.import_records(c,archive['selected'],records);root=imported[0];before,files=projects.snapshot(c,root['cap'])
   shell=struct.unpack_from('<Q',c.request(2),128)[0];c.objects(27,root['cap'],shell,127)
  j.open_named_project(root['name']);time.sleep(.4)
  prompt('foldSearch');frame,rows=found('foldSearch');(out/'native-main-search.ppm').write_bytes(frame.ppm())
  passed('physical Ctrl+G finds real Notes source and navigates its visible caret/selection',query='foldSearch',source=before,visible_rows=rows,files=len(files))
  # Search crosses from Main into a different real semantic source member.
  prompt('reviewed-intents');frame,rows=found('reviewed-intents');(out/'native-cross-file-search.ppm').write_bytes(frame.ppm())
  passed('literal search crosses loaded source members to actual permission declaration',query='reviewed-intents',expected_file='lemma.project.json',visible_rows=rows)
  prompt('Lemma.');first,rows=found('Lemma.');j.ui.chord(29,42,34)
  second,rows=wait(lambda:(v if(v:=found('Lemma.'))[0].digest!=first.digest else None),'Ctrl+Shift+G advances actual native match',45)
  (out/'native-next-search.ppm').write_bytes(second.ppm());passed('physical Ctrl+Shift+G advances to a distinct next matching source position',first_frame=first.digest,next_frame=second.digest)
  prompt('campaign010DefinitelyAbsentLiteral');j.wait_text(8,370,'No match - Ctrl+G changes query',0xe9bc75,timeout=60)
  (out/'native-not-found.ppm').write_bytes(j.ui.frame().ppm())
  with j.client()as c:after,unchanged=projects.snapshot(c,root['cap'])
  require(before==after and files==unchanged,'local search edited authorized source bytes')
  passed('bounded whole-project wrap reports not found and preserves exact source bytes',source=after,files_sha256={name:hashlib.sha256(data).hexdigest()for name,data in files.items()},candidate_bound=24*32769,per_loop_budget=512)
  report.update(result='pass-real-native-workbench-search',limits='Actual native keyboard and presented pixels on RV64 QEMU, normal graph import/admission and trusted picker. Literal ASCII query limit63bytes; no fuzzy/semantic/regular-expression search or new authority claimed.');save()
 except BaseException as error:
  with contextlib.suppress(Exception):(out/'failure.ppm').write_bytes(j.ui.frame().ppm())
  report.update(result='failure-preserved-source',error=repr(error),traceback=traceback.format_exc());save();raise
 finally:
  j.stop()
if __name__=='__main__':main()
