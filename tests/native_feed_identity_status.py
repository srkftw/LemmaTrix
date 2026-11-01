"""Actual native Account-v1 status length and graphical public identity check."""
import argparse,hashlib,json,struct,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace as NS
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import feed,identity,messenger,releases
from messenger_journey import Guest,PUB,SIGN,wait,screenshot
from native_feed_project_account import focus_feed,export_public
from native_community_campaign import feed_ui

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--packages',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);image=out/'guest.bin';image.write_bytes(a.image.read_bytes())
 paths={name:out/(name+'.ltrel')for name in('identity','feed-account','feed','status-client')}
 for name in('identity','feed'):paths[name].write_bytes((a.packages/(name+'.ltrel')).read_bytes())
 for name,binary,project,rights,version in(('feed-account','feed-account','feed-account',1024,'0.9.1'),('status-client','feed-account-status-client','feed-account-status-client',799,'0.9.0')):
  raw,_=releases.make(ROOT/'build/live/apps'/(binary+'.bin'),project,version,rights,SIGN,profile=2,license='NOASSERTION');paths[name].write_bytes(raw)
 report=dict(schema=1,image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),packages={n:dict(release_id=releases.inspect(f.read_bytes())['release_id'],sha256=hashlib.sha256(f.read_bytes()).hexdigest())for n,f in paths.items()},checks=[])
 g=Guest('status','qemu',out,image,graphical=True).start();started=time.monotonic();complete=False
 def passed(label,**values):report['checks'].append(dict(check=label,result='pass',**values));print('PASS',label,values,flush=True)
 try:
  signer=identity.start(g.client,paths['identity'],PUB);owner,oid=feed.install_or_launch(g.client,paths['feed-account'],PUB,1024);probe,pid=feed.install_or_launch(g.client,paths['status-client'],PUB,799)
  sid=bytes.fromhex(releases.inspect(paths['identity'].read_bytes())['release_id'])
  for operation in(402,410):identity.bind(g.client,signer['service'],owner,sid,oid,operation)
  messenger.bind(g.client,5,owner,probe,480,oid,pid)
  home=hashlib.sha256(b'Native Feed status home').digest();peer=hashlib.sha256(b'Native Feed status selected peer').digest()
  def probe_call(action,payload=b''):
   raw=g.client.request(150,struct.pack('<Q8Q',probe,800,action,0,0,0,0,0,1)+payload);f=struct.unpack_from('<8Q',raw);assert f[0]==0
   job=f[1]
   def completed():
    raw=g.client.request(150,struct.pack('<Q8Q',probe,800,1,job,0,0,0,0,1));f=struct.unpack_from('<8Q',raw)
    if f[0]==6:return None
    assert f[0]==0,f
    return raw
   return wait(completed,300,'native typed Account status probe')
  created=probe_call(0,home+peer);assert len(created)==64 and struct.unpack_from('<Q',created,8)[0]!=0
  status=probe_call(2);assert len(status)==160 and any(status[64:96])and status[96:160]==home+peer
  (out/'native-account-status.bin').write_bytes(status)
  passed('actual bound native AccountSDK consumer receives exactly160 bytes including public key and both public scopes',bytes=len(status),public=status[64:96].hex(),response_sha256=hashlib.sha256(status).hexdigest())
  for instance in(probe,owner):g.client.request(26,struct.pack('<Q',instance))
  selected=feed.start(g.client,NS(identity=paths['identity'],owner=paths['feed-account'],ui=paths['feed'],public=PUB,federation=home.hex(),peer=peer.hex()));g.feed_ui=selected['ui'];g.feed_owner=selected['owner']
  focus_feed(g);g.device.press(60)
  def public_identity():
   f,data=feed_ui(g)
   return data[:96]if f[1]==1 and any(data[:32])and data[32:96]==home+peer else None
  public=wait(public_identity,300,'graphical Feed consumes complete scoped public identity')
  profile=export_public(g);assert profile[32:64]==public[:32]and profile[64:128]==home+peer
  passed('ordinary native F2 identity gesture displays the exact public key and scopes exported by its separately owned account',public=public[:32].hex(),profile_sha256=hashlib.sha256(profile).hexdigest(),profile_bytes=len(profile))
  report['frame']=screenshot(g,'native-public-identity');report['result']='pass';complete=True
 except BaseException as error:
  report.update(result='failure-preserved-native-actor',error=repr(error),traceback=traceback.format_exc(),native_events=g.client.events.decode('ascii','replace'));raise
 finally:
  report['seconds']=time.monotonic()-started;(out/('evidence.json'if complete else'failure.json')).write_text(json.dumps(report,indent=2)+'\n')
  if complete:g.stop()
  else:
   if g.client:g.client.close()
   if g.device:g.device.close()
   if g.log:g.log.close()

if __name__=='__main__':main()
