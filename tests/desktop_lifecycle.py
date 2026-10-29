"""Focused real-keyboard lifecycle UI and rooted-project lifetime check."""
import argparse,json,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from creator_journey import Journey,require
import projects

def main():
 p=argparse.ArgumentParser();p.add_argument('--editor',type=Path,required=True);p.add_argument('--text-tools',type=Path,required=True);p.add_argument('--public',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output=a.output.resolve();j=Journey(a)
 def edit_instance():
  with j.client() as c:return struct.unpack_from('<4Q',c.request(2),6*32)
 def menu():
  old=j.ui.frame().digest;j.ui.chord(56,67);j.ui.wait_frame(old);time.sleep(.5)
 def action(code):
  old=j.ui.frame().digest;j.ui.press(code);j.ui.wait_frame(old);time.sleep(.5)
 try:
  j.boot(False);_,old_editor=j.trust_stage(a.editor,'native-editor');j.ui.textASCII('survive',delay=.05);j.ui.press(28);j.ui.textASCII('def durableInSession : UInt64 := 17\n',delay=.05);j.ui.press(62);time.sleep(.4)
  with j.client() as c:original=next(r for r in projects.roots(c) if r['name']=='survive')
  j.trust_stage(a.text_tools,'text-tools');j.ui.textASCII('independent input 42',delay=.09);j.wait_text(8,116,'independent input 42')
  j.ui.chord(56,15);time.sleep(.4);menu();action(19);restarted=edit_instance()[0];require(restarted!=old_editor,'native GUI R did not restart exact incarnation');j.ui.press(1);time.sleep(.4);j.ui.press(1);j.open_named_project('survive');j.wait_text(164,96,'def durableInSession')
  j.ui.chord(56,15);j.wait_text(8,116,'independent input 42');j.ui.chord(56,15);time.sleep(.4);menu();action(31);require(edit_instance()[1]==5,'native GUI S did not stop editor');j.ui.press(1);j.wait_text(8,116,'independent input 42')
  menu();action(28);fresh=edit_instance()[0];require(fresh!=restarted and edit_instance()[1]<5,'native GUI Enter did not start installed editor');j.ui.press(1);time.sleep(.4);j.ui.press(1);j.open_named_project('survive');j.wait_text(164,96,'def durableInSession')
  with j.client() as c:now=next(r for r in projects.roots(c) if r['name']=='survive');require(now['head']==original['head'],'app death changed rooted project')
  j.passed('trusted GUI restart/stop/start preserve named project and independent app state',instances=[old_editor,restarted,fresh],root=now['head'],text_tools='independent input 42',frame=j.ui.frame().digest);j.stop()
 finally:
  if j.proc and j.proc.poll() is None:j.stop(hard=True)
if __name__=='__main__':main()
