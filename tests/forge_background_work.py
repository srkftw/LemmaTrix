"""Physical editing and an unrelated native app while an exact graph transfer stalls.

All packages are reused already signed artifacts. The opaque transport pause
holds stream bytes without decoding messages or touching guest application state.
"""
import argparse,hashlib,json,os,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import forge,projects,releases
from creator_journey import rendered_text
from forge_journey import wait,import_project
from forge_resume import OpaqueSwitch,relationship,browse
from signed_forge_journey import ClientNode

def presented(node,x,y,text,color=0xd8e6ed):
 return wait(lambda:(f if rendered_text((f:=node.ui.frame()),x,y,len(text),color)==text else None),'physical native rendered text '+text,120)
def root_named(node,name):return next(r for r in node.roots() if r['name']==name)

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path);p.add_argument('--image',required=True,type=Path);p.add_argument('--forge',required=True,type=Path);p.add_argument('--forge-public',required=True,type=Path);p.add_argument('--editor',type=Path,default=ROOT/'build/signed-forge-journey-2/editor.ltrel');p.add_argument('--editor-public',type=Path,default=ROOT/'build/signed-forge-journey-2/publisher.pub');p.add_argument('--text-tools',type=Path,default=ROOT/'build/text-tools-check/text-tools-responsive.ltrel');p.add_argument('--text-public',type=Path,default=ROOT/'build/text-tools-check/publisher.pub');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);os.environ['LT_GUEST_IMAGE']=str(a.image.resolve());switch=OpaqueSwitch();nodes=[]
 try:
  sender=ClientNode(a.output/'publisher',switch.endpoints[0]);nodes.append(sender);receiver=ClientNode(a.output/'recipient',switch.endpoints[1]);nodes.append(receiver)
  for node in nodes:node.install(a.forge,a.forge_public)
  editor,editor_info=receiver.install_app(a.editor,a.editor_public,'native-editor')
  receiver.ui.textASCII('network-notes',delay=.03);receiver.ui.press(28);receiver.ui.textASCII('def localWork : UInt64 := 41\n',delay=.03);receiver.ui.press(62)
  first=wait(lambda:next((r for r in receiver.roots() if r['name']=='network-notes'),None),'native initial unrelated editor commit',120)
  text, text_info=receiver.install_app(a.text_tools,a.text_public,'text-tools');initial='queue remains bounded 42';receiver.ui.textASCII(initial,delay=.04);presented(receiver,8,116,initial)
  relationship(switch,nodes,a.output/'explicit-relationship',0,1,[os.getrandom(32),os.getrandom(32)])
  _,head,files,private=import_project(sender);sender.select('creator');sender.ui.press(62);wait(lambda:sender.inspect()['status']==4,'native exact source offer',120)
  receiver.focus(receiver.instance);browse(receiver);receiver.ui.press(63)
  def unfinished():
   state=receiver.inspect()
   return state if state['import_transaction'] and state['received_nodes']>=1 and state['received_nodes']<state['metadata_nodes'] else None
  before=wait(unfinished,'unfinished native graph before opaque pause',180);switch.pause(True);time.sleep(.25)
  held=receiver.inspect();assert held['import_transaction']==before['import_transaction'] and not any(r['head']==head for r in receiver.roots()),held
  c=receiver.client()
  try:
   raw=c.request(100,struct.pack('<8Q',43,held['import_transaction'],0,0,1,0,0,1));denied=struct.unpack_from('<Q',raw)[0]
   assert denied==3 and len(raw)==64 and forge.inspect(c,receiver.instance)['import_transaction']==held['import_transaction'],'stage bytes disclosed to a different caller'
  finally:c.close()
  receiver.focus(editor);replacement='def localWork : UInt64 := 73\n-- slow peer kept working\n';receiver.ui.chord(29,30);receiver.ui.textASCII(replacement,delay=.04);receiver.ui.press(62)
  changed=wait(lambda:(r if (r:=root_named(receiver,'network-notes'))['head']!=first['head'] else None),'native editor commits during stalled peer',120)
  c=receiver.client()
  try:
   _,actual=projects.snapshot(c,changed['cap']);assert actual['Main.lean'].decode()==replacement,actual
  finally:c.close()
  editor_frame=presented(receiver,164,96,'def localWork : UInt64 := 73');(receiver.path/'editor-during-stall.ppm').write_bytes(editor_frame.ppm())
  receiver.focus(text);suffix=' and local input 2026';receiver.ui.textASCII(suffix,delay=.05);text_frame=presented(receiver,8,116,initial+suffix);(receiver.path/'text-tools-during-stall.ppm').write_bytes(text_frame.ppm())
  receiver.focus(receiver.instance);after=receiver.inspect();assert after['import_transaction']==before['import_transaction'] and not any(r['head']==head for r in receiver.roots()),after
  (receiver.path/'forge-during-stall.ppm').write_bytes(receiver.ui.frame().ppm());switch.pause(False)
  complete=wait(lambda:(s if (s:=receiver.inspect())['status']==11 and not s['import_transaction'] else None),'native graph completes after paused endpoint resumes',300)
  c=receiver.client()
  try:
   received=next(r for r in projects.roots(c) if r['head']==head);actual_head,actual=projects.snapshot(c,received['cap']);assert actual_head==head and actual==files
   ids=[];cursor=0
   while True:
    f,payload=c.objects(26,received['cap'],cursor)
    if not f[1]:break
    ids.append(payload[:32].hex());cursor=f[3]
   assert private not in ids
  finally:c.close()
  wait(lambda:sender.inspect()['status']==10,'actual validated receipt after resumed transport',120)
  receiver.focus(editor);presented(receiver,164,96,'def localWork : UInt64 := 73');receiver.focus(text);presented(receiver,8,116,initial+suffix)
  report=dict(image=hashlib.sha256(a.image.read_bytes()).hexdigest(),forge=releases.inspect(a.forge.read_bytes())['release_id'],editor=editor_info['release_id'],text_tools=text_info['release_id'],root=head,source_bytes=sum(map(len,files.values())),same_incomplete_stage_during_work=True,before=before,after=after,complete=complete,editor_root_before=first['head'],editor_root_after=changed['head'],actual_saved_source=replacement,actual_text_input=initial+suffix,physical_actions=['Alt-Tab to editor','Ctrl-A replace source','F4 commit','Alt-Tab to TextTools','type new uncanned input','Alt-Tab to Forge'],graph_preloaded_into_recipient=False,private_object_absent=True,environment='two isolated QEMU guests; three separately signed native apps in recipient; opaque stream pause on one development host')
  (a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:
  switch.pause(False)
  for node in reversed(nodes):
   try:node.stop()
   except BaseException:pass
  switch.close()
if __name__=='__main__':main()
