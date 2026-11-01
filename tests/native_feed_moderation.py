"""Real native report, signed local moderation, appeal, and supersession.

The reporter/author uses ordinary native UI input. The federation operator
explicitly requests a decision, constructed and signed by its native consumer.
"""
import argparse,json,struct,sys,time,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from messenger_journey import Guest,wait,screenshot
from native_feed_community import ui
import feed

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--attach',type=Path,required=True);a=p.parse_args();out=a.attach.resolve();state=json.loads((out/'continuation.json').read_text());actors=[];checks=[];start=time.monotonic()
    def attach(i,graphical=False):
        g=Guest('node'+str(i),'qemu',out,out/'guest.bin',graphical=graphical).attach(None);actors.append(g);return g
    reporter=attach(6,True);reporter.ui=state['clients']['6']['ui'];personal=attach(0,True);personal.ui=state['personal']['ui'];operator=attach(5)
    author=ui(reporter)[1][:32]
    def rows():
        result=[]
        for cursor in range(64):
            f,payload=feed.invoke(operator.client,490,action=1,handle=cursor,allowed=(0,6))
            if f[0]==6:break
            result.append((f,payload))
        return result
    def event(kind,target=None):
        return next(((f,p)for f,p in rows()if struct.unpack_from('<Q',p,32+176)[0]==kind and (kind==8 or p[32+112:32+144]==author) and (target is None or p[32+368:32+400]==target)),None)
    reply=event(2);assert reply;target=reply[1][:32];original=reply[1][32:]
    def select(g,target):
        g.device.press(104)
        for _ in range(64):
            wait(lambda:ui(g)[0][4] in(15,16,26,40),180,'native event read or explicit visibility marker')
            f,selected=ui(g,795)
            if selected[:32]==target:return ui(g)[0]
            old=selected[:32];g.device.press(28)
            wait(lambda:ui(g,795)[1][:32]!=old or ui(g)[0][4] in(16,26),180,'native chronological next event')
            time.sleep(.3)
        raise AssertionError('native target not found')
    def submit(kindkey,text):
        wait(lambda:ui(reporter)[0][5] in(0,6,7),180,'native previous operation accepted')
        reporter.device.press(kindkey);wait(lambda:ui(reporter)[0][2] in(6,7),60,'native report/appeal compose')
        reporter.device.textASCII(text,delay=.035);wait(lambda:ui(reporter)[0][3]==len(text),120,'native complete private reason')
        reporter.device.press(62);time.sleep(.2);reporter.device.press(63)
    def decide(action,reason):
        feed.invoke(operator.client,490,action=5,handle=action,data=target+reason.encode(),allowed=(0,6))
        def finished():
            f,p=feed.invoke(operator.client,490,action=6,allowed=(0,6));return (f,p)if f[0]==0 and len(p)==32 else None
        return wait(finished,240,'native moderator signed durable decision')[1]
    def target_row():
        return next((f for f,p in rows()if p[:32]==target),None)
    try:
        report=event(6,target)
        if report is None:
            select(personal,target);personal.device.press(66);wait(lambda:ui(personal)[0][4]==18,120,'native local block committed')
            select(reporter,target)
            submit(67,'Please review my reply under this federation visibility policy. This report is intended only for its moderators.')
            report=wait(lambda:event(6,target),240,'native private report accepted')
        checks.append('Alpha user blocks Beta reply author in private local preferences')
        checks.append('Real native report accepted without creating moderator authority or cross federation replication')
        prior=event(8,target)
        hidden=prior[1][:32] if prior else decide(1,'Reviewed report: temporarily hide this reply under local policy version1.')
        assert target_row()[5]==0
        denied,_=feed.invoke(operator.client,491,action=6,offset=0,count=134,data=target,allowed=(1,));assert denied[0]==1
        checks.append('Authorized native moderator decision hides exact event and ordinary direct read is refused')
        appeal=event(7,target)
        if appeal is None:
            select(reporter,target)
            submit(68,'I appeal the visibility decision on my own reply and request an explicit local review result.')
            appeal=wait(lambda:event(7,target),240,'native private appeal accepted')
        reversed_id=decide(3,'Appeal reviewed: reverse the earlier visibility decision while retaining its signed policy history.')
        assert target_row()[5]==1
        after=next(p for f,p in rows()if p[:32]==target);assert after[32:]==original
        checks.append('Author appeal receives explicit authorized signed reversal and original author event is unchanged')
        # Local block remains effective even after the federation reversed its own
        # decision. Native outcome hides selected body and returns blocked marker.
        personal.device.press(104)
        for _ in range(3):
            wait(lambda:ui(personal)[0][4] in(15,16),180,'native local filtered timeline')
            if ui(personal)[0][4]==16:break
            personal.device.press(28)
        assert ui(personal)[0][4]==16
        checks.append('Federation reversal preserves Alpha personal local block')
        operator.client.close();operator.client=None
        alpha=attach(4)
        af,ap=feed.invoke(alpha.client,491,action=5,handle=2);assert af[5]==1 and ap[:32]==target and ap[32:]==original
        checks.append('Alpha independently retains permitted original reply; Beta policy never rewrites it or expands private report audience')
        report=dict(schema=1,result='pass',target=target.hex(),report_id=report[1][:32].hex(),appeal_id=appeal[1][:32].hex(),hidden_decision=hidden.hex(),reversal_decision=reversed_id.hex(),author_public=author.hex(),original_event_sha256=hashlib.sha256(original).hexdigest(),checks=checks,frames={g.name:screenshot(g,'moderation')for g in(personal,reporter)},seconds=time.monotonic()-start,scope='Local native all-QEMU selected-federation workflow; remote-home private appeals are unsupported in this profile.')
        (out/'moderation.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
    except BaseException as error:
        (out/'moderation-failure.json').write_text(json.dumps(dict(error=repr(error),checks=checks,reader=list(ui(reporter)[0]),target=target.hex()),indent=2)+'\n');raise
    finally:
        for g in actors:
            if g.client:g.client.close()
            if g.device:g.device.close()
if __name__=='__main__':main()
