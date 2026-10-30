"""Pinned-image no-vault restart boundary with actual native Game input.

Only two sequential guests are used. Package staging/approval is repeated;
private metadata, graph source, checked chunks, jobs and saves use public SDKs.
This deliberately does not claim a native Library Add or monitoring journey.
"""
import argparse,hashlib,json,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import content,live,projects,releases
from creator_journey import Journey,require
from crate_game import app,state
from library_journey import appcall,wait


def rejected(action,label):
    try:action()
    except ValueError as error:return str(error)
    raise AssertionError(label+' accepted stale authority')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',type=Path,default=ROOT/'build/campaign005/final-4/guest.bin')
    p.add_argument('--expected-image',default='643b801e42091c99f5d20e3ff40f5ab293840c6c5377a260491201b2b71c4fe1')
    p.add_argument('--game',type=Path,default=ROOT/'build/campaign005/game-secure-editions/game1/crate-workshop.ltrel')
    p.add_argument('--library',type=Path,default=ROOT/'build/campaign005/final-2/packages/library-native.ltrel')
    p.add_argument('--expected-library',default='3a440ae9d37a4f4a99cb0f6fe5634d55bcda12edfc6568c0941aa446afff2dbb',help='exact selected signed Library release; historical default is unchanged')
    p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub')
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output=a.output.resolve();a.output.mkdir(exist_ok=False)
    checks=[];active=None
    image=hashlib.sha256(a.image.read_bytes()).hexdigest()
    game_info=releases.inspect(a.game.read_bytes());library_info=releases.inspect(a.library.read_bytes())
    require(image==a.expected_image,'unexpected common image')
    require(game_info['release_id']=='3a56b13d0e211adf25e66d05c09dedc48506c84cb4fe328af8295b3460be7779','unexpected secure Game release')
    require(library_info['release_id']==a.expected_library,'unexpected Library release')
    def passed(label,**details):
        checks.append(dict(check=label,result='passed',**details));print('PASS',label,flush=True)
        (a.output/'progress.json').write_text(json.dumps(dict(image=image,checks=checks),indent=2)+'\n')
    def boot(name):
        j=Journey(argparse.Namespace(output=a.output/name,public=a.public,image=a.image));j.boot(False)
        # The normal runner command is part of the evidence: no storage backend.
        command=Path('/proc/'+str(j.proc.pid)+'/cmdline').read_bytes().split(b'\0')
        require(b'--vault' not in command and b'--server-store' not in command,'unexpected personal backing argument')
        return j,[x.decode()for x in command if x]
    def trust(j,path,rights):
        info=releases.inspect(path.read_bytes())
        with j.client()as c:
            old=c.request(2);before={struct.unpack_from('<Q',old,i)[0]for i in range(0,len(old),32)}
            c.request(10,bytes.fromhex(info['project_id'])+releases.public_modulus(a.public));c.stage(path)
        old=j.ui.frame().digest;j.ui.press(88);j.ui.wait_frame(old);time.sleep(.5);j.ui.press(28)
        def running():
            with j.client()as c:
                rows=c.request(2)
                found=[struct.unpack_from('<Q',rows,i)[0]for i in range(7*32,len(rows),32)if struct.unpack_from('<Q',rows,i+16)[0]==rights and 0<struct.unpack_from('<Q',rows,i+8)[0]<5 and struct.unpack_from('<Q',rows,i)[0]not in before]
                if not found:return None
                require(len(found)==1,'ambiguous newly approved role')
                current=c.request(29,bytes.fromhex(info['project_id']));require(current[160:192].hex()==info['release_id'],'activated a different release')
                return found[0]
        return wait(running,180,'fresh trusted native package approval')
    def vault_status(c):
        raw=c.request(202,struct.pack('<8Q',202,0,3,0,0,0,0,1));require(len(raw)>=64,'short Vault status')
        fields=struct.unpack_from('<8Q',raw);require(fields[0]==0 and fields[5]==0 and fields[2]==0,'Objects vault unexpectedly unlocked or populated')
        return fields
    def library_empty(c,lib):
        fields,data=appcall(c,lib,701)
        return len(data)==640 and all(struct.unpack_from('<Q',data,i)[0]==0 for i in (16,88,96,536))
    try:
        j,first_command=boot('first');active=j
        with j.client()as c:
            require(projects.roots(c)==[] and c.objects(10)[0][1:4]==(0,0,0),'first guest was not empty')
            first_vault=vault_status(c)
        game=trust(j,a.game,795);j.wait_text(8,56,'CRATE WORKSHOP')
        j.ui.press(32);j.ui.press(32)
        def solved():
            with j.client()as c:
                current=state(c,game);return current if current['won']==1 else None
        solved_state=wait(solved,60,'real keyboard puzzle win')
        require(solved_state['moves']==2 and solved_state['boxes']==536870912,'unexpected actual puzzle result')
        (a.output/'first'/'solved.ppm').write_bytes(j.ui.frame().ppm())
        with j.client()as c:
            fields,_=app(c,game,502);require(fields[0]==0,'ephemeral save export failed');saved=fields[1];save_bytes=c.read_object(saved)
            require(len(save_bytes)==192,'unexpected save length')
            old_game_read=c.objects(6,saved,game,1)[0][1]
            require(app(c,game,503,old_game_read)[0][0]==0,'original selected save grant did not load before restart')
        lib=trust(j,a.library,1919)
        with j.client()as c:
            c.request(184,struct.pack('<Q',lib))
            require(wait(lambda:library_empty(c,lib),60),'Library did not start empty')
            metadata=b'{"scope":"private-session-boundary","selected_collection":"open-courtyard","monitor_only":true}'
            private=c.import_object(metadata,2);private_grant=c.objects(6,private,lib,1)[0][1]
            source=b'namespace PrivateSession\ndef note : UInt64 := 7\nend PrivateSession\n'
            blob,blob_id=projects.node(c,source,10);manifest,head=projects.node(c,projects.manifest([('session.lean',10,blob_id)]),11)
            name=b'private-session-source';root=c.objects(22,manifest,0,len(name),data=bytes(32)+name.ljust(64,b'\0'))[0][1]
            require(projects.snapshot(c,root)[1]['session.lean']==source,'private source graph did not contain actual bytes')
            raw=content.original_wave(.05,2);operation=7712301
            selected,manifest_bytes,chunks,proofs=content.reserve(c,raw,operation,hashlib.sha256(b'explicit-ephemeral-provider').digest(),hashlib.sha256(b'explicit-ephemeral-federation').digest())
            content.ingest_chunk(c,selected,0,chunks[0],proofs[0]);sdk=content.api(c)
            require(sdk.objects(307,selected,0,64)[1]==raw[:64],'checked private range did not match')
            pending=sdk.objects(301,selected,1,data=proofs[1])[0][1]
            for offset in range(0,len(chunks[1]),512):sdk.objects(302,pending,offset,data=chunks[1][offset:offset+512])
            sdk.objects(303,pending);progress=sdk.objects(304,pending)[0];require(progress[2]==2 and progress[3]>0,'actual hash job not in progress')
            sdk.objects(305,pending,1);paused=sdk.objects(304,pending)[0];require(paused[2]==3,'pending job was not paused')
            read_grant=sdk.objects(308,selected,game)[0][1]
            require(vault_status(c)[5]==0,'private work unlocked Vault')
            denied=c.request(203,struct.pack('<Q',saved));require(struct.unpack_from('<Q',denied)[0]==3,'no-vault save retention was not unavailable')
            old=dict(game=game,library=lib,save=saved,save_read=old_game_read,private=private,private_grant=private_grant,source_blob=blob,source_root=root,content=selected,content_read=read_grant,job=pending)
            first_stats=c.objects(10)[0];first_roots=projects.roots(c)
        passed('native DD and GameSDK502 create actual ephemeral progress/save; private metadata, source and checked content remain unretained',game_state=solved_state,save_sha256=hashlib.sha256(save_bytes).hexdigest(),save_bytes=len(save_bytes),private_metadata_sha256=hashlib.sha256(metadata).hexdigest(),source_head=head,content_total=len(raw),verified_content_bytes=4096,paused_job_state=paused[2],hash_cursor=paused[3],no_vault_save_retain_status=3,library_add_exercised=False)
        j.stop();active=None
        j,second_command=boot('second');active=j
        with j.client()as c:
            require(projects.roots(c)==[],'private source/collection root survived no-vault restart')
            require(c.objects(10)[0][1:4]==(0,0,0),'Objects records or grants survived no-vault restart')
            second_vault=vault_status(c)
            stale={}
            for key in ('save','private','source_blob'):stale[key]=rejected(lambda key=key:c.objects(5,old[key]),key)
            stale['source_root']=rejected(lambda:c.objects(29,old['source_root']),'source root')
            sdk=content.api(c)
            stale['content']=rejected(lambda:sdk.objects(306,old['content']),'content root')
            stale['job']=rejected(lambda:sdk.objects(304,old['job']),'content job')
            stale['job_control']=rejected(lambda:sdk.objects(305,old['job'],2),'job resume')
            fresh,_,_,_=content.reserve(c,raw,operation,hashlib.sha256(b'explicit-ephemeral-provider').digest(),hashlib.sha256(b'explicit-ephemeral-federation').digest())
            require(fresh!=old['content'],'content handle incarnation was reused')
            fresh_description=sdk.objects(306,fresh)[0];require(fresh_description[2]==1 and fresh_description[3]==0,'old checked ranges reappeared under a repeated operation ID')
            stale['missing_old_range']=rejected(lambda:sdk.objects(307,fresh,0,64),'old checked range')
            candidate=sdk.objects(301,fresh,0,data=proofs[0])[0][1]
            sdk.objects(305,candidate,3);sdk.objects(305,candidate,4)
            candidate=sdk.objects(301,fresh,0,data=proofs[0])[0][1]
            require(candidate!=old['job'],'fresh job allocation reused an old token')
            stale['content_after_allocation']=rejected(lambda:sdk.objects(306,old['content']),'old content after new allocation')
            stale['job_after_allocation']=rejected(lambda:sdk.objects(304,old['job']),'old job after new allocation')
            # An explicit negative unlock cannot discover or create backing.
            key=hashlib.sha256(b'only-an-explicit-no-vault-negative-test-key').digest()
            unlock=c.request(200,struct.pack('<8Q',200,0,3,0,0,0,0,1)+key)
            require(struct.unpack_from('<Q',unlock)[0]==5,'unlock unexpectedly found backing')
            vault_status(c)
        passed('fresh identical no-vault image contains no private Objects/root/save or resumed job authority',old_authority_rejections=stale,fresh_content_verified_bytes=0,vault_unlock_without_backing_status=5)
        fresh_game=trust(j,a.game,795);j.wait_text(8,56,'CRATE WORKSHOP')
        with j.client()as c:
            empty=state(c,fresh_game);require(empty['moves']==0 and empty['completed']==0 and empty['won']==0 and empty['save']==0,'fresh game recovered unapproved progress')
            refused=app(c,fresh_game,503,old['save_read'])[0];require(refused[0]!=0,'old save read authority survived restart')
            after=state(c,fresh_game);require(after['moves']==0 and after['completed']==0 and after['won']==0,'refused old save changed fresh progress')
        fresh_lib=trust(j,a.library,1919)
        with j.client()as c:
            c.request(184,struct.pack('<Q',fresh_lib));require(wait(lambda:library_empty(c,fresh_lib),60),'fresh Library has nonempty personal state')
            vault_status(c)
        (a.output/'second'/'empty-library.ppm').write_bytes(j.ui.frame().ppm())
        passed('fresh execution approvals start secure Game at zero progress and refuse old save; Library starts empty',fresh_game_state=empty,old_save_load_status=refused[0],native_library_add_exercised=False)
        j.stop();active=None
        personal_files=[str(x.relative_to(a.output))for x in a.output.rglob('*')if x.is_file()]
        require(not any(x.endswith(('.vault','.img','.store'))for x in personal_files),'a personal backing file was created')
        result=dict(schema=1,result='passed',image_sha256=image,game_release=game_info['release_id'],library_release=library_info['release_id'],checks=checks,first_guest_command=first_command,second_guest_command=second_command,old_handles=old,first_objects_stats=list(first_stats),first_private_roots=first_roots,no_storage_backend_selected=True,personal_object_payload_written_to_host=False,host_artifacts='explicit framebuffer captures, UART transport logs and hash/state evidence; no personal backing',native_library_add_exercised=False,limitations=['private collection metadata is an explicitly labeled Objects boundary fixture, not a claimed native Library Add/monitoring operation','graph source and selected content use public SDK setup; Game input and package approvals use actual device input','process restart/volatile-memory behavior, not a physical data-remanence claim'])
        (a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
    finally:
        if active:active.stop(hard=True)

if __name__=='__main__':main()
