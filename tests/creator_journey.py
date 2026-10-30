"""Integrated graphical creator journey, using device input and real guest state.

Takes already built/signed editor/TextTools packages. It never writes guest memory,
uses UI setters, or recompiles an OS in response to a project edit.
"""
import argparse,contextlib,hashlib,json,os,re,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live,projects,project_vault,releases
from graphical_devices import DeviceInput

def require(value,message):
 if not value:raise AssertionError(message)

def rendered_score(frame):
 # Decode the native application's eight 5x7 score glyphs from actual display
 # pixels. App-local (50,56) is below the shell's 48-pixel trusted chrome.
 glyphs={15629733422:'0',15170933124:'1',33558693422:'2',32247317566:'3',
  2247698626:'4',32247857695:'5',15621636622:'6',8866891839:'7',
  15621113390:'8',15067498030:'9',16692328448:'a',32801348112:'b',
  15620126720:'c',16695014433:'d',15602333696:'e',8867684646:'f'}
 digits=[]
 for digit in range(8):
  bits=0
  for row in range(7):
   for column in range(5):
    offset=((104+row)*frame.width+50+digit*6+column)*4
    pixel=frame.bgrx[offset:offset+3]
    require(pixel in (bytes.fromhex('a2e5b8'),bytes.fromhex('352b14')),'unexpected score pixel color')
    if pixel==bytes.fromhex('a2e5b8'):bits|=1<<(row*5+4-column)
  require(bits in glyphs,'native score contains an unrecognized glyph')
  digits.append(glyphs[bits])
 return ''.join(digits)

def rendered_text(frame,x,y,count,foreground=0xd8e6ed):
 # This reads presented glyph pixels, not application buffers or private state.
 glyphs={int(bits):chr(int(code)) for code,bits in re.findall(r'if c == (\d+) then (\d+)',(ROOT/'Guest/Raster.lean').read_text())}
 fg=bytes((foreground&255,(foreground>>8)&255,(foreground>>16)&255));answer=[]
 for digit in range(count):
  bits=0
  for row in range(7):
   for column in range(5):
    offset=((y+row)*frame.width+x+digit*6+column)*4
    if frame.bgrx[offset:offset+3]==fg:bits|=1<<(row*5+4-column)
  answer.append(glyphs.get(bits,'?'))
 return ''.join(answer)

class Journey:
 def __init__(self,args):
  self.args=args;self.out=args.output;self.out.mkdir(parents=True,exist_ok=True);self.report=[];self.proc=None;self.ui=None
  self.socket=self.out/'portal.sock';self.graphics=self.out/'display.qmp';self.log=None
  self.image_path=Path(getattr(args,'image',None) or ROOT/'build/live/guest.bin').resolve()
  self.image=hashlib.sha256(self.image_path.read_bytes()).hexdigest()
 def passed(self,label,**data):
  self.report.append(dict(check=label,result='pass',**data));print('PASS',label,flush=True)
  (self.out/'journey.json').write_text(json.dumps(dict(image=self.image,backend=getattr(self.args,'backend','qemu'),checks=self.report),indent=2)+'\n')
 @contextlib.contextmanager
 def client(self):
  c=live.Client(self.socket,timeout=240)
  try:yield c
  finally:c.close()
 def boot(self,vault=True):
  self.socket.unlink(missing_ok=True);self.graphics.unlink(missing_ok=True)
  self.log=(self.out/('transport-'+str(len(self.report))+'.log')).open('wb')
  cmd=[sys.executable,ROOT/'lt','run','--image',self.image_path,'--socket',self.socket,'--graphics',self.graphics]
  if vault:cmd+=['--vault',self.args.vault]
  self.proc=subprocess.Popen(list(map(str,cmd)),cwd=ROOT,stdout=self.log,stderr=self.log,start_new_session=True)
  end=time.monotonic()+90
  while not self.socket.exists():
   require(self.proc.poll() is None,'guest exited at boot')
   if time.monotonic()>end:raise TimeoutError('graphical boot readiness')
   time.sleep(.05)
  self.ui=DeviceInput('qemu',self.graphics);time.sleep(.3)
 def stop(self,hard=False):
  if self.ui:self.ui.close();self.ui=None
  if self.proc and self.proc.poll() is None:
   if hard:os.killpg(self.proc.pid,signal.SIGKILL)
   else:
    with self.client() as c:
     try:c.request(70)
     except EOFError:pass
   self.proc.wait(timeout=20)
  if self.log:self.log.close();self.log=None
 def trust_stage(self,path,name,pub=None):
  with self.client() as c:
   c.request(10,releases.project(name)+releases.public_modulus(pub or self.args.public));info=c.stage(path)
  old=self.ui.frame().digest;self.ui.press(88);self.ui.wait_frame(old);time.sleep(.5);self.ui.press(28);time.sleep(2)
  with self.client() as c:
   active=c.request(29,releases.project(name));require(active[160:192].hex()==info['release_id'],'GUI exact release activation')
   procs=c.request(2);running=[struct.unpack_from('<4Q',procs,i) for i in range(6*32,len(procs),32) if 0<struct.unpack_from('<Q',procs,i+8)[0]<5]
   require(running,'native process did not start')
  return info,running[-1][0]
 def roots(self):
  with self.client() as c:return projects.roots(c)
 def snapshot(self,root):
  with self.client() as c:return projects.snapshot(c,root)
 def creator(self):return next(r for r in self.roots() if r['name']=='creator')
 def wait_text(self,x,y,text,foreground=0xd8e6ed,timeout=30):
  deadline=time.monotonic()+timeout
  while True:
   frame=self.ui.frame()
   if rendered_text(frame,x,y,len(text),foreground)==text:return frame
   if time.monotonic()>deadline:raise TimeoutError('expected native text pixels did not arrive: '+repr(text))
   time.sleep(.1)
 def open_named_project(self,name):
  old=self.ui.frame().digest;self.ui.chord(42,60);self.ui.wait_frame(old);time.sleep(.5)
  frame=self.ui.frame();rows=[rendered_text(frame,32,107+i*12,len(name)+1).rstrip() for i in range(16)]
  require(name in rows,'trusted project picker did not list '+name+': '+repr(rows))
  for _ in range(rows.index(name)):
   old=self.ui.frame().digest;self.ui.press(108);self.ui.wait_frame(old);time.sleep(.3)
  old=self.ui.frame().digest;self.ui.press(28);self.ui.wait_frame(old);time.sleep(.6)
 def open_creator(self):self.open_named_project('creator')
 def retain_graphically(self,name):
  self.open_named_project(name)
  with self.client() as c:before=project_vault.inventory(c)
  old=self.ui.frame().digest;self.ui.press(68);self.ui.wait_frame(old);time.sleep(.5)
  frame=self.ui.frame();require(rendered_text(frame,16,40,len(name))==name,'retention chrome identifies a different project')
  self.ui.press(28);deadline=time.monotonic()+90
  while True:
   with self.client() as c:saved=project_vault.inventory(c)
   if saved['generation']>before['generation'] and any(r['name']==name for r in saved['projects']):break
   if time.monotonic()>deadline:raise TimeoutError('GUI did not durably retain '+name)
   time.sleep(.2)
  time.sleep(.3);return saved
 def weight(self,text):
  self.ui.press(61);time.sleep(.1)
  self.ui.click(164+23*6,96+5*11+2);self.ui.press(111);self.ui.textASCII(text,delay=.035);self.ui.press(62);time.sleep(.4)
 def run(self):
  self.boot();self.passed('graphical boot',frame=self.ui.frame().digest)
  editor,editor_instance=self.trust_stage(self.args.editor,'native-editor');self.passed('device approved and started separately signed editor',release=editor['release_id'],instance=editor_instance)
  self.ui.textASCII('notes',delay=.035);self.ui.press(28);self.ui.textASCII('def note : UInt64 := 1\n',delay=.035);self.ui.press(62);time.sleep(.4)
  notes=next(r for r in self.roots() if r['name']=='notes');self.passed('keyboard created committed multi-file notes project',root=notes['head'])
  tools_info,tools_instance=self.trust_stage(self.args.text_tools,'text-tools');self.ui.textASCII('independent input 42',delay=.07);time.sleep(.4)
  tools_frame=self.wait_text(8,116,'independent input 42')
  require(rendered_text(tools_frame,56,94,8)=='00000003' and rendered_text(tools_frame,218,94,8)=='00000014' and rendered_text(tools_frame,356,94,8)=='00000000','independent app did not render actual3words/20bytes/0LF')
  require(rendered_text(tools_frame,8,116,20)=='independent input 42','independent app private input pixels differ')
  (self.out/'text-tools-input.ppm').write_bytes(tools_frame.ppm())
  self.passed('independent graphical application retains arbitrary private input',instance=tools_instance,frame=tools_frame.digest,rendered_words=3,rendered_bytes=20,rendered_lf=0)
  self.ui.chord(56,15);time.sleep(.3)
  with self.client() as c:
   # Explicit source portal transports bytes; canonical schemas/identities are
   # validated by Objects, and the user opens the root through the trusted picker.
   entries=[]
   for path in sorted((ROOT/'examples/creator').rglob('*')):
    if path.is_file():
     _,identity=projects.node(c,path.read_bytes(),10);entries.append((path.relative_to(ROOT/'examples/creator').as_posix(),10,identity))
   h,identity=projects.node(c,projects.manifest(entries),11)
   f,_=c.objects(22,h,0,7,data=bytes(32)+b'creator'.ljust(64,b'\0'));root=f[1]
   p=c.request(2);shell=struct.unpack_from('<Q',p,128)[0];c.objects(27,root,shell,127)
  self.open_creator();time.sleep(.3)
  original_resource=self.creator()['head']
  self.ui.press(61);time.sleep(.2);self.ui.press(61);time.sleep(.3)
  self.ui.chord(29,18);time.sleep(.3);self.ui.press(103);time.sleep(.2);self.ui.press(28);time.sleep(.3);self.ui.press(62);time.sleep(.5)
  six=self.creator()['head'];_,six_files=self.snapshot(self.creator()['cap'])
  resource_cap=self.creator()['cap']
  with self.client() as c:
   manifest_handle=c.objects(24,resource_cap)[0][1];_,six_ids=c.objects(21,manifest_handle)
  require(six_ids[32:64].hex()==original_resource,'structured resource commit lost its actual parent edge')
  require(six_files['accent.txt']==b'6\n' and six!=original_resource,'structured semantic resource change was not committed')
  self.ui.chord(29,18);time.sleep(.3);self.ui.press(108);time.sleep(.2);self.ui.press(28);time.sleep(.3);self.ui.press(62);time.sleep(.5)
  five=self.creator()['head'];_,five_files=self.snapshot(self.creator()['cap'])
  resource_cap=self.creator()['cap']
  with self.client() as c:
   manifest_handle=c.objects(24,resource_cap)[0][1];_,five_ids=c.objects(21,manifest_handle)
  require(five_ids[32:64].hex()==six,'resource return lost its intentional revision parent')
  require(five_files['accent.txt']==b'5\n' and five not in (six,original_resource),'intentional return to resource5 lost distinct revision lineage')
  self.passed('native structured resource editing preserves semantic lineage',original=original_resource,changed=six,reconstructed=five)
  for _ in range(4):self.ui.press(61);time.sleep(.2)
  old=self.ui.frame().digest;self.ui.press(64);self.ui.wait_frame(old);time.sleep(.3)
  selected_frame=self.ui.frame();require(rendered_text(selected_frame,8,100,2)=='0a','native Inspector did not read selected Source schema')
  (self.out/'inspector-source.ppm').write_bytes(selected_frame.ppm())
  old=selected_frame.digest;self.ui.press(15);self.ui.wait_frame(old);time.sleep(.3)
  manifest_frame=self.ui.frame();require(rendered_text(manifest_frame,8,100,2)=='0b','native Inspector did not read Project manifest schema')
  require(rendered_text(manifest_frame,8,244,64)==five,'Inspector named-head commitment pixels differ')
  resource_cap=self.creator()['cap']
  with self.client() as c:logical_project=projects.project_identity(c,resource_cap)
  require(rendered_text(manifest_frame,8,216,64)==logical_project,'Inspector logical project identity pixels differ')
  (self.out/'inspector-manifest.ppm').write_bytes(manifest_frame.ppm())
  self.passed('native Inspector reads Source and manifest identities',head=five,source_frame=selected_frame.digest,manifest_frame=manifest_frame.digest)
  old=manifest_frame.digest;self.ui.press(64);self.ui.wait_frame(old);time.sleep(.3)
  self.ui.press(63);time.sleep(.4)
  with self.client() as c:first=projects.build_bridge(c,self.out/'build-weight3')
  require(first['status']=='ok','first exact multi-module/resource build failed: '+first['diagnostic_text'])
  with self.client() as c:pub1=projects.publish_result(self.out/'build-weight3/job.result.json',self.args.key,'creator','1.0.0',self.out/'creator-1.ltrel',client=c,rights=768)
  self.passed('exact resource-backed build and checked Release graph',source=first['source_root'],binary=first['artifact']['sha256'],content=pub1['content'])
  release1,app1=self.trust_stage(self.out/'creator-1.ltrel','creator');self.ui.textASCII('cat123',delay=.07);time.sleep(.4);frame1=self.wait_text(50,104,'00000014',0xb8e5a2);(self.out/'native-weight3.ppm').write_bytes(frame1.ppm())
  require(rendered_score(frame1)=='00000014','Weight3 native rendered score differs from expected cat123 result')
  self.passed('first compiled app accepts real keyboard input',release=release1['release_id'],instance=app1,frame=frame1.digest,rendered_score=rendered_score(frame1))
  # Return focus to the editor by cycling actual trusted focus control.
  self.ui.chord(56,15);time.sleep(.3)
  self.weight('missing');self.ui.press(63);time.sleep(.3)
  with self.client() as c:bad=projects.build_bridge(c,self.out/'build-diagnostic',defer_result=True)
  require(bad['status']=='error' and any(d['path']=='Util.lean' for d in bad['diagnostics']),'real located compiler diagnostic absent')
  # Edit B while result A is undelivered. No privileged edit command is used.
  for _ in range(7):self.ui.press(14,.03)
  self.ui.textASCII('7',delay=.04);self.ui.press(62);time.sleep(.3)
  newer=self.creator()['head']
  with self.client() as c:
   wrong=dict(bad,source_root='00'*32)
   try:projects.complete_build(c,wrong)
   except ValueError:pass
   else:raise AssertionError('substituted source build result accepted')
   projects.complete_build(c,bad)
  require(self.creator()['head']==newer,'result A overwrote newer project B')
  self.passed('located compiler error and delayed exact-source result preserve newer edits',built=bad['source_root'],newer=newer,diagnostics=bad['diagnostics'])
  self.ui.press(63);time.sleep(.3)
  with self.client() as c:second=projects.build_bridge(c,self.out/'build-weight7')
  require(second['status']=='ok','corrected source rebuild failed: '+second['diagnostic_text'])
  latest_root=self.creator()['cap']
  with self.client() as c:pub2=projects.publish_result(self.out/'build-weight7/job.result.json',self.args.key,'creator','1.1.0',self.out/'creator-2.ltrel',release1['release_id'],client=c,rights=768,attach_root=latest_root)
  release2,app2=self.trust_stage(self.out/'creator-2.ltrel','creator');self.ui.textASCII('cat123',delay=.07);time.sleep(.4);frame2=self.wait_text(50,104,'00000018',0xb8e5a2);(self.out/'native-weight7.ppm').write_bytes(frame2.ppm())
  require(first['artifact']['sha256']!=second['artifact']['sha256'],'edited source produced identical native code')
  require(rendered_score(frame2)=='00000018','Weight7 native rendered score differs from expected cat123 result')
  self.passed('edited multi-module code updates native application without OS rebuild',binary=second['artifact']['sha256'],release=release2['release_id'],instance=app2,frame=frame2.digest,rendered_score=rendered_score(frame2))
  # Every selection redraw resets the trusted modal's physical-gesture gate.
  # Wait for real presented pixels, then leave its raw input queue idle before B.
  # Catalog rows are editor, TextTools, creator1, creator2.
  old=self.ui.frame().digest;self.ui.chord(56,67);self.ui.wait_frame(old);time.sleep(.4)
  for _ in range(2):
   old=self.ui.frame().digest;self.ui.press(108);self.ui.wait_frame(old);time.sleep(.4)
  old=self.ui.frame().digest;self.ui.press(48);self.ui.wait_frame(old);time.sleep(.4);self.ui.press(1)
  with self.client() as c:active=c.request(29,releases.project('creator'))
  require(active[160:192].hex()==release1['release_id'],'explicit GUI rollback did not select previous generation')
  self.passed('explicit graphical rollback preserves existing app instances')
  # Both snapshots are approved through native trusted F10 controls. Host
  # management supplies only the explicit unlock key and inspects real results.
  with self.client() as c:project_vault.unlock(c,self.args.vault_key.read_bytes())
  self.ui.chord(56,15);time.sleep(.4)
  creator_saved=self.retain_graphically('creator')
  require(creator_saved['bytes']>65536,'selected creator closure did not exceed64KiB')
  inventory=self.retain_graphically('notes')
  with self.client() as c:
   private=c.import_object(b'private ephemeral object not retained',2)
   named=projects.roots(c);selected=[next(r for r in named if r['name']=='notes'),next(r for r in named if r['name']=='creator')]
   logical_ids={r['name']:projects.project_identity(c,r['cap']) for r in selected}
  require(inventory['generation']>creator_saved['generation'] and inventory['bytes']>65536 and len(inventory['projects'])==2,'second GUI snapshot did not preserve both named projects')
  require({r['name']:r['head'] for r in inventory['projects']}=={r['name']:r['head'] for r in selected},'GUI retained different named heads')
  saved=dict(generation=inventory['generation'],nodes=len(inventory['nodes']),projects=len(inventory['projects']),bytes=inventory['bytes'])
  self.passed('two F10 approved complete named graphs durably retained',saved=saved,heads={r['name']:r['head'] for r in selected})
  old_caps=[r['cap'] for r in selected];self.stop();self.boot()
  with self.client() as c:
   project_vault.unlock(c,self.args.vault_key.read_bytes());restored=project_vault.recover(c)
   require({r['name']:projects.project_identity(c,r['cap']) for r in restored['roots']}==logical_ids,'logical project identities changed during recovery')
   for old in old_caps:
    try:c.objects(24,old)
    except ValueError:pass
    else:raise AssertionError('stale root authority revived')
   try:c.objects(5,private)
   except ValueError:pass
   else:raise AssertionError('private unsaved object survived')
   try:c.request(25,struct.pack('<Q',1))
   except ValueError:pass
   else:raise AssertionError('install approval survived restart')
  require({r['name']:r['head'] for r in restored['roots']}=={r['name']:r['head'] for r in selected},'recovered stable names/heads differ')
  self.passed('restart recovery preserves names/complete graph/lineage with fresh authority',restored=restored)
  # Re-provision current-session publisher trust, then approve this exact editor
  # release again. Recovered executable bytes never revive install authority.
  _,fresh_editor=self.trust_stage(self.args.editor,'native-editor')
  self.ui.press(1);time.sleep(.3)
  self.open_named_project('creator')
  restored_frame=self.wait_text(164,96,'import Lean')
  require(rendered_text(restored_frame,164,96,11)=='import Lean','recovered editor did not render actual Main.lean content')
  (self.out/'recovered-editor-source.ppm').write_bytes(restored_frame.ppm())
  with self.client() as c:
   recovered_creator=next(r for r in projects.roots(c) if r['name']=='creator');_,recovered_files=projects.snapshot(c,recovered_creator['cap'])
  require(recovered_files['accent.txt']==b'5\n' and b'def Weight : UInt64 := 7' in recovered_files['Util.lean'],'recovered source/resource content differs from selected graph')
  self.passed('freshly approved editor opens recovered project through native trusted picker',instance=fresh_editor,head=recovered_creator['head'],frame=restored_frame.digest)
  self.stop();return self.report

def main():
 p=argparse.ArgumentParser();p.add_argument('--editor',type=Path,required=True);p.add_argument('--text-tools',type=Path,required=True);p.add_argument('--public',type=Path,required=True);p.add_argument('--key',type=Path,required=True);p.add_argument('--vault',type=Path,required=True);p.add_argument('--vault-key',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output=a.output.resolve();a.vault=a.vault.resolve();j=Journey(a)
 try:j.run()
 finally:
  if j.proc and j.proc.poll() is None:j.stop(hard=True)
if __name__=='__main__':main()
