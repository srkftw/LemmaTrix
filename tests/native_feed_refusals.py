"""Focused actual Feed signatures, duplicate acceptance, and signed audiences."""
import argparse,json,struct,hashlib,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from messenger_journey import Guest,wait
from native_feed_community import ui
import feed,identity,network

def route(client,op,**kwargs):return network.call(client,op,slot=0,**kwargs)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--attach',type=Path,required=True);a=p.parse_args();out=a.attach.resolve();actors=[];checks=[]
 def attach(i,graphical=False):
  g=Guest('node'+str(i),'qemu',out,out/'guest.bin',graphical=graphical).attach(None);actors.append(g);return g
 alpha=attach(4);beta=attach(5);g=attach(7,True)
 try:
  original=feed.invoke(beta.client,491,action=5)[1][32:]
  corrupt=bytearray(original);corrupt[-1]^=1
  f,_=feed.invoke(beta.client,491,action=1,data=bytes(corrupt),allowed=(10,));assert f[0]==10;checks.append('Altered original author signature refused10 by native destination')
  before=feed.invoke(beta.client,491,action=8)[0]
  duplicate,_=feed.invoke(beta.client,491,action=1,data=original);after=feed.invoke(beta.client,491,action=8)[0]
  assert duplicate[2]==2 and before==after;checks.append('Exact original signed duplicate returns original durable acceptance without new row or storage budget')
  live=identity.instances(g.client);g.ui=next(r[0]for r in live if r[2]==799 and r[1]in(1,2,3,4));owner=next(r[0]for r in live if r[2]==1024 and r[1]in(1,2,3,4))
  phase=route(g.client,32)[0]
  if phase[2]!=3:
   route(g.client,31);wait(lambda:route(g.client,32)[0][2]==3,240,'fourth independent personal circuit')
  route(g.client,38,h=3,a=28,b=owner,c=1048576,d=4096);wait(lambda:route(g.client,41)[0][2]==3,240,'home-only native terminal')
  g.device.chord(56,15);time.sleep(.2)
  if ui(g)[0][1]==0:g.device.press(60);wait(lambda:ui(g)[0][1]!=0,180,'new home scoped native author')
  author=ui(g)[1][:32]
  text='A home-only project note: this discussion remains inside our selected federation.'
  g.device.press(61);wait(lambda:ui(g)[0][2]==1,60,'home-only native compose');g.device.textASCII(text,delay=.035);wait(lambda:ui(g)[0][3]==len(text),120,'home-only exact draft');g.device.press(62);time.sleep(.2);g.device.press(63)
  def find(client):
   for cursor in range(64):
    f,row=feed.invoke(client,491,action=5,handle=cursor,allowed=(0,6))
    if f[0]==6:return None
    if row[144:176]==author:return f,row
  _,record=wait(lambda:find(alpha.client),240,'native home-only post durable')
  event_id,envelope=record[:32],record[32:]
  assert not any(envelope[304:336])
  denied,_=feed.invoke(beta.client,491,action=1,data=envelope,allowed=(11,));assert denied[0]==11
  assert find(beta.client)is None;checks.append('Actual native UI home-only signed post stays home; other configured federation refuses valid signed event11')
  states={}
  for i in(0,6,7):
   if i==7:client=g.client
   else:
    peer=attach(i);client=peer.client
   states[str(i)]=list(route(client,41)[0]);assert states[str(i)][2]==3
  checks.append('Three independent personal clients remain admitted through shared running relays, including two same destinationAlpha')
  report=dict(schema=1,result='pass',checks=checks,original_duplicate=list(duplicate),signed_home_only_event=event_id.hex(),home_author=author.hex(),concurrent_terminal_states=states,scope='Actual local native service boundary refusals; no new host signing or event fixtures.')
  (out/'refusals.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
 finally:
  for actor in actors:
   if actor.client:actor.client.close()
   if actor.device:actor.device.close()
if __name__=='__main__':main()
