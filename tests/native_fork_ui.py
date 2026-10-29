"""Physical native editor fork, public publisher choice and independent edits."""
import argparse,hashlib,json,struct,sys,time,types
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import projects,releases
from creator_journey import Journey,rendered_text,require
from native_recovery_fork_ui import import_files

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'build/native-fork-ui');a=p.parse_args();a.output=a.output.resolve();require(not a.output.exists(),'new explicit output required');a.output.mkdir(parents=True)
 public=ROOT/'build/campaign003-publisher.pub';key=ROOT/'build/campaign003-publisher.pem';binary=ROOT/'build/live/apps/native-editor.bin'
 envelope,manifest=releases.make(binary,'native-editor','4.1.0',895,key,profile=2)
 package=a.output/'editor.ltrel';package.write_bytes(envelope);Path(str(package)+'.manifest.json').write_text(json.dumps(manifest,separators=(',',':'),sort_keys=True))
 j=Journey(types.SimpleNamespace(output=a.output,public=public));files={'Main.lean':b'def weight : UInt64 := 7\n','accent.txt':b'5\n'}
 def wait_text(x,y,text):
  try:return j.wait_text(x,y,text,foreground=0xe9bc75,timeout=60)
  except TimeoutError:
   frame=j.ui.frame();(a.output/'unexpected-frame.ppm').write_bytes(frame.ppm());print('presented status:',repr(rendered_text(frame,8,370,90,0xe9bc75)),flush=True);raise
 try:
  j.boot(False);j.trust_stage(package,'native-editor');j.ui.press(1);time.sleep(.3)
  with j.client() as c:
   upstream=import_files(c,'upstream-ui',files);logical=projects.project_identity(c,upstream['cap']);binding=c.objects(29,upstream['cap'])[0][7]
   shell=struct.unpack_from('<Q',c.request(2),4*32)[0];c.objects(27,upstream['cap'],shell,127)
  j.open_named_project('upstream-ui');(a.output/'upstream-open.ppm').write_bytes(j.ui.frame().ppm())
  j.ui.chord(29,33);wait_text(8,370,'Fork name (new identity;')
  name='own-ui-fork';j.ui.textASCII(name,delay=.06);j.ui.press(28);wait_text(8,370,'New publisher public key ID')
  publisher=hashlib.sha256(releases.public_modulus(public)).hexdigest();j.ui.textASCII(publisher,delay=.06);j.ui.press(28);wait_text(8,370,'Fork created; own identity.')
  (a.output/'fork-created.ppm').write_bytes(j.ui.frame().ppm())
  with j.client() as c:
   fork=next(r for r in projects.roots(c) if r['name']==name);identity=projects.project_identity(c,fork['cap']);require(identity!=logical and c.objects(29,fork['cap'])[0][7]!=binding,'fork reused project or live authority')
   require(projects.snapshot(c,fork['cap'])[1]==files,'fork copied wrong revision')
   h=c.objects(24,fork['cap'])[0][1];entries=projects.decode_manifest(c.read_object(h));lineage=next(i for _,kind,i in entries if kind==15);data=c.read_object(projects.resolve(c,fork['cap'],lineage));require(data[48:80].hex()==logical and data[144:176].hex()==publisher,'fork lineage/public publisher differs')
  j.ui.chord(29,30);j.ui.textASCII('def weight : UInt64 := 19\n',delay=.06);j.ui.press(62);time.sleep(.5)
  j.ui.press(61);j.ui.chord(29,18);time.sleep(.5);require(rendered_text(j.ui.frame(),110,142,2,0xaad6a4)=='05','semantic resource started with wrong value')
  for _ in range(6):j.ui.press(103)
  j.ui.press(28);j.ui.press(62);time.sleep(.5)
  with j.client() as c:
   fork=next(r for r in projects.roots(c) if r['name']==name);head,changed=projects.snapshot(c,fork['cap']);require(projects.project_identity(c,fork['cap'])==identity,'fork identity changed during edit');require(changed=={'Main.lean':b'def weight : UInt64 := 19\n','accent.txt':b'11\n'},'real source/resource edit differs');require(projects.snapshot(c,upstream['cap'])[1]==files,'upstream changed')
  (a.output/'fork-edited.ppm').write_bytes(j.ui.frame().ppm());j.passed('physical Ctrl-F and explicit public publisher create independent editable lineage',upstream=logical,fork=identity,head=head,lineage=lineage,publisher=publisher,source=changed['Main.lean'].decode(),resource=changed['accent.txt'].decode(),signature='no signature before a real scheme3 release covers this exact source root')
 finally:
  if j.proc and j.proc.poll() is None:j.stop(hard=True)
if __name__=='__main__':main()
