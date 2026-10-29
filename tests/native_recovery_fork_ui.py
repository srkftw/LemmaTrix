"""Actual trusted masked vault unlock/selected recovery and editor fork input.

Reuses the current platform image and compiled native editor. Administrative
setup retains two explicit test projects; the second boot uses physical input
for secret unlock, root selection, recovery, fork, and source/resource edits.
"""
import argparse,hashlib,json,struct,subprocess,sys,time,types
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import projects,project_vault,releases
from creator_journey import Journey,rendered_text,require
from forge_journey import wait

def import_files(c,name,files):
 entries=[];records=[]
 for path,payload in sorted(files.items()):
  identity=projects.canonical_node(10,payload);entries.append((path,10,identity));records.append(dict(kind=10,id=identity,payload=payload))
 payload=projects.manifest(entries);head=projects.canonical_node(11,payload)
 records.insert(0,dict(kind=11,id=head,payload=payload))
 return projects.import_records(c,[dict(name=name,head=head)],records)[0]

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'build/native-recovery-fork-ui');p.add_argument('--reuse-setup',type=Path);p.add_argument('--key',type=Path,default=ROOT/'build/campaign003-publisher.pem');p.add_argument('--public',type=Path,default=ROOT/'build/campaign003-publisher.pub');a=p.parse_args();a.output=a.output.resolve();require(not a.output.exists(),'output must be a new explicit test directory');a.output.mkdir(parents=True)
 image=hashlib.sha256((ROOT/'build/live/guest.bin').read_bytes()).hexdigest();binary=ROOT/'build/live/apps/native-editor.bin'
 envelope,manifest=releases.make(binary,'native-editor','4.1.0',895,a.key,profile=2)
 package=a.output/'editor.ltrel';package.write_bytes(envelope);Path(str(package)+'.manifest.json').write_text(json.dumps(manifest,sort_keys=True,separators=(',',':')))
 backing=(a.reuse_setup or a.output)/'objects.img';key_file=(a.reuse_setup or a.output)/'objects.key'
 if not a.reuse_setup:subprocess.run([str(ROOT/'lt'),'vault-init',str(backing),'--sectors','24576','--key-out',str(key_file)],cwd=ROOT,check=True)
 j=Journey(types.SimpleNamespace(output=a.output,public=a.public,vault=backing))
 selected_name='recover-selected';other_name='recover-not-selected'
 files={'Main.lean':b'def weight : UInt64 := 7\n','accent.txt':b'5\n','padding-a.txt':b'a'*24000,'padding-b.txt':b'b'*24000,'padding-c.txt':b'c'*24000}
 try:
  if not a.reuse_setup:
   j.boot(True)
   with j.client() as c:
    project_vault.unlock(c,key_file.read_bytes())
    other=import_files(c,other_name,{'Notes.txt':b'explicitly retained but not selected on recovery\n'})
    selected=import_files(c,selected_name,files)
    private=c.import_object(b'private unretained session data',10)
    private_id=c.objects(21,private)[1][:32].hex()
    saved=project_vault.retain(c,[other['cap'],selected['cap']])
    logical=projects.project_identity(c,selected['cap']);old_binding=c.objects(29,selected['cap'])[0][7]
   require(saved['projects']==2 and saved['bytes']>65536,'explicit retention setup missing')
   j.stop()
  else:
   entries=[(name,10,projects.canonical_node(10,payload)) for name,payload in sorted(files.items())]
   logical=projects.canonical_node(11,projects.manifest(entries));old_binding=None
   private_id=projects.canonical_node(10,b'private unretained session data')
   saved=dict(projects=2,bytes=sum(map(len,files.values()))+48,generation=1)
  j.boot(True);j.trust_stage(package,'native-editor');j.ui.press(1);time.sleep(.3)
  with j.client() as c:require(projects.roots(c)==[],'fresh guest acquired roots before explicit recovery')
  j.ui.press(87);j.wait_text(12,12,'TRUSTED OBJECTS VAULT STATUS');j.ui.press(22);j.wait_text(16,16,'TRUSTED OBJECTS VAULT UNLOCK')
  j.ui.textASCII(key_file.read_bytes().hex(),delay=.08)
  def fully_masked():
   frame=j.ui.frame();return frame if all(rendered_text(frame,16+i*8,114,1)=='*' for i in range(64)) else None
  try:masked=wait(fully_masked,'64 presented masked key digits',90)
  except TimeoutError:
   frame=j.ui.frame();(a.output/'masked-unlock-incomplete.ppm').write_bytes(frame.ppm());print('masked glyph count',sum(rendered_text(frame,16+i*8,114,1)=='*' for i in range(64)),flush=True);raise
  (a.output/'masked-unlock.ppm').write_bytes(masked.ppm())
  j.ui.press(28);j.wait_text(16,16,'SELECT RECOVERY ROOTS');time.sleep(.3)
  frame=j.ui.frame();names=[rendered_text(frame,32,100+i*28,len(name)) for i,name in enumerate((other_name,selected_name))]
  require(names==[other_name,selected_name],('authenticated inventory names differ',names))
  require(rendered_text(frame,16,100,1)=='*' and rendered_text(frame,16,128,1)=='-','initial selection is unclear')
  with j.client() as c:require(projects.roots(c)==[],'inventory browsing imported content')
  j.ui.press(2);j.ui.press(3);time.sleep(.2)
  frame=j.ui.frame();require(rendered_text(frame,16,100,1)=='-' and rendered_text(frame,16,128,1)=='*','physical selection did not change exact root mask')
  (a.output/'selected-recovery.ppm').write_bytes(frame.ppm());j.ui.press(28)
  def recovered():
   with j.client() as c:return next((r for r in projects.roots(c) if r['name']==selected_name),None)
  recovered_root=wait(recovered,'native selected recovery',180);time.sleep(.4)
  with j.client() as c:
   roots=projects.roots(c);require([r['name'] for r in roots]==[selected_name],'unselected root was also recovered')
   actual,restored=projects.snapshot(c,recovered_root['cap']);require(restored==files,'native recovery material differs')
   require(projects.project_identity(c,recovered_root['cap'])==logical,'canonical identity changed on native recovery')
   recovered_binding=c.objects(29,recovered_root['cap'])[0][7];require(old_binding is None or recovered_binding!=old_binding,'recovered authority reused prior session binding')
   ids=[];cursor=0
   while cursor<64:
    f,data=c.objects(26,recovered_root['cap'],cursor)
    if not f[1]:break
    ids.append(data[:32].hex());cursor=f[3]
   require(private_id not in ids,'unretained private object entered recovered closure')
  (a.output/'recovered.ppm').write_bytes(j.ui.frame().ppm())
  j.passed('trusted masked unlock and physical selected-root recovery',generation=saved['generation'],selected=selected_name,unselected=other_name,source_bytes=sum(map(len,files.values())),project_id=logical,no_import_before_approval=True)
  j.ui.press(1);j.open_named_project(selected_name)
  publisher=hashlib.sha256(releases.public_modulus(a.public)).hexdigest()
  j.ui.chord(29,33);j.wait_text(8,370,'Fork name (new identity;',foreground=0xe9bc75)
  fork_name='ui-own-fork';j.ui.textASCII(fork_name,delay=.04);j.ui.press(28);j.wait_text(8,370,'New publisher public key ID',foreground=0xe9bc75)
  j.ui.textASCII(publisher,delay=.03);j.ui.press(28);j.wait_text(8,370,'Fork created; own identity.',foreground=0xe9bc75)
  (a.output/'fork-created.ppm').write_bytes(j.ui.frame().ppm())
  with j.client() as c:
   fork=next(r for r in projects.roots(c) if r['name']==fork_name);fork_id=projects.project_identity(c,fork['cap'])
   require(fork_id!=logical,'native fork inherited upstream logical identity')
   require(c.objects(29,fork['cap'])[0][7]!=recovered_binding,'native fork inherited upstream live authority')
   _,initial=projects.snapshot(c,fork['cap']);require(initial==files,'fork source/resource bytes differ before edits')
   manifest_handle=c.objects(24,fork['cap'])[0][1];entries=projects.decode_manifest(c.read_object(manifest_handle))
   lineage=next(identity for _,kind,identity in entries if kind==15);provenance=c.read_object(projects.resolve(c,fork['cap'],lineage))
   require(provenance[48:80].hex()==logical and provenance[144:176].hex()==publisher,'typed fork lineage/publisher differs from actual choices')
  j.ui.chord(29,30);j.ui.textASCII('def weight : UInt64 := 19\n',delay=.04);j.ui.press(62);time.sleep(.4)
  j.ui.press(61);j.ui.chord(29,18);time.sleep(.4)
  require(rendered_text(j.ui.frame(),110,142,2,0xaad6a4)=='05','native semantic resource opened wrong input')
  for _ in range(6):j.ui.press(103)
  j.ui.press(28);j.ui.press(62);time.sleep(.6)
  with j.client() as c:
   fork=next(r for r in projects.roots(c) if r['name']==fork_name);final_head,changed=projects.snapshot(c,fork['cap'])
   require(projects.project_identity(c,fork['cap'])==fork_id,'native edits changed fork identity')
   require(changed['Main.lean']==b'def weight : UInt64 := 19\n' and changed['accent.txt']==b'11\n','actual source/resource edits differ')
   _,upstream=projects.snapshot(c,recovered_root['cap']);require(upstream==files,'editing fork modified upstream')
  (a.output/'fork-resource-edited.ppm').write_bytes(j.ui.frame().ppm())
  j.passed('native Ctrl-F fork with explicit publisher and independent source/resource edits',upstream_project=logical,fork_project=fork_id,fork_head=final_head,lineage=lineage,publisher=publisher,source=changed['Main.lean'].decode(),resource=changed['accent.txt'].decode(),signature='lineage remains unsigned until a real scheme3 publisher release covers the exact fork source root')
  require(hashlib.sha256((ROOT/'build/live/guest.bin').read_bytes()).hexdigest()==image,'test changed platform image')
  report={'image':image,'editor_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'editor_release':envelope[160:192].hex(),'backend':'QEMU system RV64 on shared x86-64 development host','checks':j.report}
  (a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:
  if j.proc and j.proc.poll() is None:j.stop(hard=True)
if __name__=='__main__':main()
