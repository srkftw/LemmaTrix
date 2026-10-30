"""Fresh graphical Library O/I acquires, approves and plays a remote Game.

Reuses an explicitly owned live publisher fixture. Only public signed metadata
and enrollment keys are provisioned into the recipient; no Game Project nodes
or executable bytes are imported through its management portal.
"""
import argparse
import contextlib
import hashlib
import json
import socket
import struct
import sys
import time
import traceback
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'),str(ROOT/'tests')]
import federation
import library_peer
import live
import network
import nodes
import projects
import releases
from creator_journey import Journey,require,rendered_text
from crate_game import state as game_state
from library_journey import Node,appcall,wait


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider-base',required=True,type=Path)
    parser.add_argument('--image',required=True,type=Path)
    parser.add_argument('--packages',required=True,type=Path)
    parser.add_argument('--fetch',type=Path,default=ROOT/'build/live/apps/library-fetch.bin')
    parser.add_argument('--game',type=Path,default=ROOT/'build/campaign005/game-secure-editions/game1/crate-workshop.ltrel')
    parser.add_argument('--key',type=Path,default=ROOT/'build/campaign005/publisher.pem')
    parser.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub')
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--keep-on-failure',action='store_true')
    args = parser.parse_args()
    out=args.output.resolve();out.mkdir(exist_ok=False);base=args.provider_base.resolve()
    personal=None;success=False;checks=[];provider_instances={}
    @contextlib.contextmanager
    def source():
        c=live.Client(base/'provider/portal.sock',timeout=240)
        try:yield c
        finally:c.close()
    def passed(label,**facts):
        checks.append(dict(check=label,result='passed',**facts));print('PASS',label,flush=True)
        (out/'journey.json').write_text(json.dumps(dict(checks=checks,recipient_image=hashlib.sha256(args.image.read_bytes()).hexdigest(),provider_image=hashlib.sha256((base/'platform.bin').read_bytes()).hexdigest(),recipient_host_game_import=False),indent=2)+'\n')
    try:
        # Close only this test's previous headless recipient. The separately
        # running publisher retains its actual admitted/validated source graph.
        try:
            old=live.Client(base/'receiver/portal.sock',timeout=5)
            try:
                try:old.request(70)
                except EOFError:pass
            finally:old.close()
        except (FileNotFoundError,ConnectionRefusedError):pass
        with source() as c:
            rows=c.request(2)
            for rights,name in ((2175,'registry'),(1025,'peer')):
                found=[struct.unpack_from('<Q',rows,i)[0]for i in range(7*32,len(rows),32)if struct.unpack_from('<Q',rows,i+16)[0]==rights and 0<struct.unpack_from('<Q',rows,i+8)[0]<5]
                require(len(found)==1,'owned provider role unavailable');provider_instances[name]=found[0]
            reg,peer=provider_instances['registry'],provider_instances['peer']
            page,admission=federation.call(c,reg,6)
            require(struct.unpack_from('<Q',admission,16)[0]==5,'source Game not consumer+executable admitted')
            fid=admission[288:320];head=admission[320:352]
            roots=[r for r in projects.roots(c)if r['head']==head.hex()]
            require(len(roots)==1,'provider exact public Game root missing')
            game_scope=c.objects(27,roots[0]['cap'],peer,1)[0][1]
            # Reset this explicit selected relationship policy, preserving the
            # original source bytes. No Graph/payload bytes enter the recipient.
            library_peer.call(c,peer,402,1)
            _,material=network.load_credentials(base/'provider.credential')
            library_peer.call(c,peer,400,1,3,int.from_bytes(head[:8],'little')|1,game_scope,16777216,100000,material[:32]+material[64:96]+head)
        # A separate signed metadata-only service relationship uses native
        # context0; context1 keeps the selected Game seed relationship.
        _,game_desc,_=network.load_description(base/'game.service')
        client_id=game_desc[64:96]
        probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
        registry_desc=out/'registry.service'
        detail=network.create_description(base/'network.pem',client_id,'127.0.0.1:'+str(port),'library-registry',registry_desc)
        client_credential,server_credential=out/'registry.client',out/'registry.server'
        network.provision(client_credential,server_credential,client_id,bytes.fromhex(detail['server_id']),bytes.fromhex(detail['service_id']))
        with source() as c:
            library_peer.call(c,peer,402,0)
            network.configure(c,server_credential,registry_desc,slot=0);network.call(c,13,slot=0)
            library_peer.call(c,peer,400,0,1,1,0,16777216,100000,client_id+bytes.fromhex(detail['service_id'])+fid)
        personal=Node('personal',out,args.image.resolve(),graphics=True)
        regpkg=args.packages/'library-registry.ltrel';raw=regpkg.read_bytes();info=releases.inspect(raw)
        with personal.client() as c:
            verifier=nodes.start_package(c,nodes.approved_package(regpkg,args.public,info['release_id'],2175),raw)
            federation.configure(c,verifier,base/'federation.pub','consumer',allowed_rights=8191)
            network.configure(c,client_credential,registry_desc,slot=0)
            network.configure(c,base/'reader.credential',base/'game.service',slot=1)
            game_info=releases.inspect(args.game.read_bytes())
            c.request(10,bytes.fromhex(game_info['project_id'])+releases.public_modulus(args.public))
            require(projects.roots(c)==[],'fresh personal guest contains preloaded Game root')
        fetch_raw,_=releases.make(args.fetch,'graph-native-fetch','1.0.0',1151,args.key,profile=2,license='NOASSERTION')
        fetch_package=out/'graph-native-fetch.ltrel';fetch_package.write_bytes(fetch_raw)
        j=Journey(argparse.Namespace(output=personal.base/'native-actions',public=args.public,image=args.image));j.socket=personal.socket;j.graphics=personal.graphics;j.ui=personal.ui;j.image=hashlib.sha256(args.image.read_bytes()).hexdigest()
        fetch_info,fetch=j.trust_stage(fetch_package,'graph-native-fetch')
        lib_info,lib=j.trust_stage(args.packages/'library-native.ltrel','library-native')
        with personal.client()as c:c.request(184,struct.pack('<Q',lib));appcall(c,lib,700,data=fid)
        def word(offset):
            with personal.client()as c:return struct.unpack_from('<Q',appcall(c,lib,701)[1],offset)[0]
        def frame_text(x,y,text):return rendered_text(personal.ui.frame(),x,y,len(text))==text
        def focus_library():
            for _ in range(5):
                if frame_text(12,58,'LEMMA LIBRARY'):return
                personal.ui.chord(56,15);time.sleep(.4)
            raise AssertionError('actual native Library focus absent')
        focus_library()
        for slot in (0,1):
            personal.ui.press(60);personal.ui.press(slot+2);personal.ui.press(28)
            def authenticated():
                with personal.client()as c:return network.status(c,slot)['endpoint_authenticated']
            wait(authenticated,300,'native provider authentication'+str(slot))
        personal.ui.press(59);personal.ui.press(16)
        wait(lambda:word(16)==1,300,'actual signed remote Game catalog')
        personal.ui.press(62);personal.ui.press(2);personal.ui.press(24)
        wait(lambda:word(528)==fetch,60,'native O exact Fetcher binding')
        with personal.client()as c:require(projects.roots(c)==[],'Game root appeared before native I acquisition')
        passed('fresh native Library selects enrolled registry/seed and binds independent fetcher through O',library_release=lib_info['release_id'],fetch_release=fetch_info['release_id'],provider_head=head.hex(),recipient_game_roots_before_I=0)
        (out/'catalog-before-I.ppm').write_bytes(personal.ui.frame().ppm())
        personal.ui.press(23)
        wait(lambda:word(536)!=0,60,'I starts immutable Game acquisition operation')
        (out/'native-acquisition.ppm').write_bytes(personal.ui.frame().ppm())
        wait(lambda:frame_text(16,12,'SIGNED P'),900,'remote Game closure and trusted local execution approval')
        (out/'trusted-game-approval.ppm').write_bytes(personal.ui.frame().ppm())
        with personal.client()as c:
            rows=c.request(2)
            require(not any(struct.unpack_from('<Q',rows,i+16)[0]==795 and 0<struct.unpack_from('<Q',rows,i+8)[0]<5 for i in range(7*32,len(rows),32)),'Game executed before trusted physical approval')
        passed('native I downloads actual Game Project and reaches trusted capability approval without recipient payload preload',head=head.hex(),game_not_running_before_approval=True)
        personal.ui.press(28)
        def game_running():
            with personal.client()as c:
                table=c.request(2)
                return next((struct.unpack_from('<Q',table,i)[0]for i in range(7*32,len(table),32)if struct.unpack_from('<Q',table,i+16)[0]==795 and 0<struct.unpack_from('<Q',table,i+8)[0]<5),None)
        game=wait(game_running,180,'approved actual native Game process')
        for _ in range(5):
            if frame_text(8,56,'CRATE WORKSHOP'):break
            personal.ui.chord(56,15);time.sleep(.4)
        require(frame_text(8,56,'CRATE WORKSHOP'),'actual downloaded Game frame absent')
        personal.ui.press(32);personal.ui.press(32)
        def won():
            with personal.client()as c:
                state=game_state(c,game)
                return state if state['won']==1 else None
        actual=wait(won,60,'two actual keyboard pushes solve remote Game')
        require(actual['moves']==2 and actual['boxes']==536870912,'actual puzzle target differs')
        (out/'remote-game-solved.ppm').write_bytes(personal.ui.frame().ppm())
        with personal.client()as c:
            active=c.request(29,bytes.fromhex(game_info['project_id']))
            require(active[160:192].hex()==game_info['release_id'],'installed a different executable generation')
        passed('physical Enter installs exact downloaded release and DD solves original native puzzle',game_release=game_info['release_id'],game_state=actual,game_rights=795,recipient_host_game_import=False)
        result=dict(result='passed',checks=checks,recipient_image=hashlib.sha256(args.image.read_bytes()).hexdigest(),provider_image=hashlib.sha256((base/'platform.bin').read_bytes()).hexdigest(),library_release=lib_info['release_id'],fetch_release=fetch_info['release_id'],fetch_binary_sha256=hashlib.sha256(args.fetch.read_bytes()).hexdigest(),game_release=game_info['release_id'],project_head=head.hex(),recipient_host_game_import=False,limitations=['provider reused its explicitly owned prior D3 image; recipient uses corrected247 image','focused O/I/Enter/DD test; save migration and media are separate executed journeys'])
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));success=True
    except BaseException:
        (out/'error.txt').write_text(traceback.format_exc());raise
    finally:
        if personal and(success or not args.keep_on_failure):personal.stop()


if __name__=='__main__':main()
