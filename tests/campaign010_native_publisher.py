"""Native public-project build, trusted publisher review and real installation.

The driver uses the documented byte import/compiler portals and physical input.
It never writes guest memory or creates a publisher signature on the host.
"""
import argparse, hashlib, json, signal, struct, subprocess, sys, time, traceback
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import identity, live_build, native_publisher, projects, releases
from creator_journey import Journey, require, rendered_text

def wait(predicate,label,timeout=180):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        value=predicate()
        if value:return value
        time.sleep(.15)
    raise TimeoutError(label)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',type=Path,default=ROOT/'build/live/guest.bin')
    p.add_argument('--project',type=Path,default=ROOT/'build/external-sdk-checkpoint')
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--editor',type=Path);p.add_argument('--identity',type=Path)
    p.add_argument('--helper',type=Path,default=ROOT/'examples/notes-schema')
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    key=ROOT/'tests/keys/development-rsa.pem';pub=ROOT/'tests/keys/development-rsa-public.pem'
    def package(module,name):
        binary=live_build.app('Guest.'+module,'Guest.'+module+'.main',name,2)
        raw,manifest=releases.make(binary,name,'1.0.0',799 if module=='Desktop'else 0,key,profile=2)
        target=out/(name+'.ltrel');target.write_bytes(raw)
        Path(str(target)+'.manifest.json').write_bytes(releases.pkg.canonical(manifest));return target
    editor=a.editor or package('Desktop','native-editor')
    signer=a.identity or package('Identity','identity')
    j=Journey(SimpleNamespace(output=out/'personal',image=a.image,public=pub,key=key,backend='qemu'))
    worker=None;worker_log=None;began=time.monotonic();record=dict(schema=1,result='running',image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),checks=[])
    def save():
        record['elapsed_seconds']=time.monotonic()-began;(out/'execution.json').write_text(json.dumps(record,indent=2)+'\n')
    def passed(label,**fields):
        record['checks'].append(dict(check=label,result='pass',**fields));save();print('PASS',label,flush=True)
    try:
        j.boot(vault=False)
        _,editor_instance=j.trust_stage(editor,'native-editor')
        j.ui.press(1);time.sleep(.2)
        with j.client()as c:service=identity.start(c,signer,pub)
        passed('legacy packages install and start without changing their original signatures',editor_instance=editor_instance,identity_service=service)
        helper_import=subprocess.run([sys.executable,ROOT/'lt','project','--socket',j.socket,'import',a.helper,'--name','notes-schema'],capture_output=True,text=True,check=True)
        helper_root=json.loads(helper_import.stdout)['root']
        with j.client()as c:
            helper_logical=projects.project_identity(c,helper_root)
            fields,helper_public=identity.invoke(c,400,a=1,data=hashlib.sha256(b'LT-PROJECT-PUBLISHER\0').digest()+bytes.fromhex(helper_logical))
            helper_key=fields[1];helper_decoded=identity.decode_public(helper_public)
            helper_proposal=native_publisher.prepare(c,root=helper_root,publisher=helper_key,name='notes-schema',version='1.0.0',license='MIT',exports=['Notes.Schema'],output=out/'helper-review')
            try:c.request(227,bytes.fromhex(helper_proposal['release_id']))
            except ValueError:pass
            else:raise AssertionError('management portal bypassed trusted physical signing review')
        j.ui.chord(56,88);time.sleep(.5);j.ui.press(28)
        def helper_signed():
            with j.client()as c:state=native_publisher.inspect(c)
            if state['phase']==4:raise AssertionError('helper native signature failed '+repr(state))
            return state if state['phase']==3 else None
        wait(helper_signed,'source-only native helper signature',300)
        with j.client()as c:helper_info=native_publisher.export(c,out/'helper-review',out/'notes-schema.ltrel')
        (out/'notes-schema.pub').write_bytes(bytes.fromhex(helper_decoded['public_key']))
        passed('real source-only helper is natively signed as an inert DevelopmentArtifact',release=helper_info,source=str(a.helper.resolve()),envelope=str(out/'notes-schema.ltrel'),public_key=str(out/'notes-schema.pub'))
        j.ui.press(1);time.sleep(.3)
        imported=subprocess.run([sys.executable,ROOT/'lt','project','--socket',j.socket,'import',a.project,'--name','sdk-checkpoint'],capture_output=True,text=True,check=True)
        imported=json.loads(imported.stdout);root=imported['root']
        j.open_named_project('sdk-checkpoint')
        # Introduce an actual elaboration error through the native editor.
        j.ui.press(102);j.ui.textASCII('unknownCheckpointCommand\n',delay=.03);j.ui.press(62)
        worker_log=(out/'compiler-worker.log').open('wb')
        worker=subprocess.Popen(list(map(str,[sys.executable,ROOT/'lt','project','--socket',j.socket,'serve','--project','external-sdk-checkpoint','--root',root,'--requester',editor_instance,'--output',out/'worker'])),cwd=ROOT,stdout=worker_log,stderr=worker_log,start_new_session=True)
        j.ui.press(63)
        def result_paths():return sorted((out/'worker').glob('session-*/job-*/job.result.json'))
        def failed():
            paths=result_paths()
            if not paths:return None
            value=json.loads(paths[-1].read_bytes());return (paths[-1],value)if value.get('delivered')and value.get('status')=='error'else None
        bad_path,bad=wait(failed,'real native build diagnostic',300)
        require(any(d.get('path')=='Main.lean'and d.get('line')==1 for d in bad.get('diagnostics',[])),'missing located Main.lean diagnostic')
        passed('ordinary public SDK source reaches isolated compiler and reports a real located error',result=str(bad_path),diagnostics=bad['diagnostics'])
        j.ui.press(64);time.sleep(.4);(out/'located-diagnostic.ppm').write_bytes(j.ui.frame().ppm())
        j.ui.press(102)
        for _ in 'unknownCheckpointCommand\n':j.ui.press(111,.02)
        j.ui.press(62);j.ui.press(63)
        def built():
            for path in result_paths():
                value=json.loads(path.read_bytes())
                if value.get('status')=='ok'and value.get('delivered'):return path,value
        result_path,result=wait(built,'corrected native public SDK build',300)
        passed('native correction builds exact frozen public SDK source through key-free serve',source=result['source_root'],artifact=result['artifact'],result=str(result_path),sdk=result.get('sdk'),recipe=result['recipe'])
        with j.client()as c:
            logical=projects.project_identity(c,root)
            fields,public=identity.invoke(c,400,a=1,data=hashlib.sha256(b'LT-PROJECT-PUBLISHER\0').digest()+bytes.fromhex(logical))
            publisher=fields[1];decoded=identity.decode_public(public)
            proposal=native_publisher.prepare(c,root=root,publisher=publisher,name='external-sdk-checkpoint',version='1.0.0',license='NOASSERTION',result_path=result_path,output=out/'review')
        passed('fresh guest-owned publisher prepares actual graph and Build/Evidence for review',publisher=decoded,proposal=proposal)
        j.ui.chord(56,88);time.sleep(.6);(out/'trusted-publisher-review.ppm').write_bytes(j.ui.frame().ppm());j.ui.press(28)
        def signed():
            with j.client()as c:value=native_publisher.inspect(c)
            if value['phase']==4:raise AssertionError('native signing failed '+repr(value))
            return value if value['phase']==3 else None
        state=wait(signed,'actual native signing completion',300)
        with j.client()as c:info=native_publisher.export(c,out/'review',out/'external-sdk-checkpoint.ltrel')
        raw=(out/'external-sdk-checkpoint.ltrel').read_bytes();public_key=bytes.fromhex(decoded['public_key'])
        require(info['signature_verified']and releases.release_prefix(raw)==608,'native release was not independently verified')
        passed('trusted physical review signs actual Ed25519 release without host publisher key',release=info,signature_sha256=hashlib.sha256(raw[512:576]).hexdigest())
        with j.client()as c:
            c.request(10,bytes.fromhex(info['project_id'])+public_key);staged=c.stage(out/'external-sdk-checkpoint.ltrel')
        j.ui.press(88);time.sleep(.4);j.ui.press(28);time.sleep(1)
        with j.client()as c:
            active=c.request(29,bytes.fromhex(info['project_id']));require(active[160:192].hex()==info['release_id'],'trusted Launcher installed a different release')
            actors=identity.instances(c);running=[row for row in actors if row[2]==768 and 0<row[1]<5]
            require(running,'native SDK application did not run')
            tampered=bytearray(raw);tampered[-1]^=1
            bad=out/'tampered.ltrel';bad.write_bytes(tampered)
            try:c.stage(bad)
            except ValueError:pass
            else:raise AssertionError('tampered artifact was admitted')
            try:identity.invoke(c,405,h=publisher,a=next(row[0]for row in actors if row[0]&255==1),b=6,c=512,data=hashlib.sha256(raw[:512]).digest())
            except ValueError:pass
            else:raise AssertionError('generic portal bypassed native signing review')
        (out/'native-sdk-application.ppm').write_bytes(j.ui.frame().ppm())
        passed('native Launcher validates installs and runs the exact v4 public SDK artifact; tamper and approval bypass fail',release_id=info['release_id'],running=running,staged=staged)
        record['result']='pass';save()
    except BaseException as error:
        record.update(result='failure',error=repr(error),traceback=traceback.format_exc());save();raise
    finally:
        if worker and worker.poll()is None:
            oskill=signal.SIGINT
            try:__import__('os').killpg(worker.pid,oskill);worker.wait(timeout=10)
            except (ProcessLookupError,subprocess.TimeoutExpired):worker.kill();worker.wait(timeout=5)
        if worker_log:worker_log.close()
        j.stop(hard=True)
    return 0

if __name__=='__main__':raise SystemExit(main())
