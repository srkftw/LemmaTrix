"""Interrupt native F8 graph publication on a seed's actual backing device.

Consumes an existing operator-selected disk and two explicit namespaces; it
never copies a backing or imports a host graph fixture. Recovery uses native F9.
"""
import argparse, hashlib, json, os, signal, socket, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule, network, projects, server_store
from durable_signed_releases import Seed
from forge_journey import wait
from forge_replication import save

def main():
    p=argparse.ArgumentParser()
    for name in ('output','image','package','public','disk'):
        p.add_argument('--'+name,type=Path,required=True)
    for name in ('previous-namespace','next-namespace','previous-head','next-head'):
        p.add_argument('--'+name,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    os.environ['LT_GUEST_IMAGE']=str(a.image.resolve())
    old_ns,new_ns=bytes.fromhex(a.previous_namespace),bytes.fromhex(a.next_namespace)
    probe=socket.socket();probe.bind(('127.0.0.1',0));endpoint='127.0.0.1:'+str(probe.getsockname()[1]);probe.close()
    key,public=a.output/'network.pem',a.output/'network.pub';capsule.generate_key(key,public)
    description=a.output/'service.public';client_id=os.getrandom(32)
    network.create_description(key,client_id,endpoint,'forge',description,hashlib.sha256(a.image.read_bytes()).digest())
    _,descriptor,_=network.load_description(description)
    client_key,server_key=a.output/'unused-client.credential',a.output/'server.credential'
    network.provision(client_key,server_key,client_id,hashlib.sha256(capsule.modulus(key)).digest(),hashlib.sha256(descriptor).digest())
    node=None;checks=[]
    def boot(label):
        result=Seed(a.output/label,endpoint,True,a.disk)
        result.setup(a.package,a.public,server_key,description)
        c=result.client()
        try:server_store.call(c,230)
        finally:c.close()
        assert not result.roots(),'restart replayed host graph outside own store'
        return result
    def recover(namespace,head):
        node.namespace(namespace);node.ui.press(67)
        preview=wait(lambda:(s if (s:=node.archive())['phase']==4 else None),'native retained scope inspection',180)
        assert preview['head']==head,preview
        node.ui.press(67)
        def done():
            state=node.archive()
            if state['phase']==9:raise AssertionError(('own graph recovery rejected',state))
            return state if state['phase']==8 else None
        wait(done,'complete native own-device graph recovery',240)
        root=next(r for r in node.roots() if r['head']==head)
        c=node.client()
        try:assert projects.project_identity(c,root['cap'])=='08fb3bbeb18eb2bb5c573eb2a77cc05236e5705fb5e09bc6a974e13771dc885a'
        finally:c.close()
        return preview
    def passed(check,**fields):
        checks.append(dict(check=check,result='pass',**fields))
        report=dict(image=hashlib.sha256(a.image.read_bytes()).hexdigest(),
                    environment='QEMU guest; operator-selected own purpose2 disk; actual process termination during native publication',checks=checks)
        (a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',check,flush=True)
    try:
        node=boot('before-interruption')
        recover(old_ns,a.previous_head);recover(new_ns,a.next_head)
        node.namespace(old_ns)
        before=a.disk.read_bytes();node.ui.press(66)
        def partial():
            state=node.archive()
            if state['phase']==9:raise AssertionError(('native save failed before fault',state))
            return state if state['phase']==2 and 4096<=state['done']<state['total'] else None
        boundary=wait(partial,'actual native inactive-bank partial write',240)
        (node.path/'partial-publication.ppm').write_bytes(node.ui.frame().ppm())
        # The native SDK has accepted a real page, but no root may yet publish.
        during=a.disk.read_bytes()
        assert during[:8192]==before[:8192], 'commit roots changed before complete graph stage'
        assert during!=before, 'fault never reached actual backing writes'
        os.killpg(node.proc.pid,signal.SIGKILL);node.proc.wait(timeout=15);node.stop();node=None
        passed('interrupt native F8 after actual inactive-bank writes without publishing root',boundary=boundary,root_sectors_unchanged=True,backing_changed=True)
        node=boot('recovered-previous')
        previous=recover(old_ns,a.previous_head)
        next_scope=recover(new_ns,a.next_head)
        passed('own-device restart recovers complete prior generation and separately retained next generation',previous=previous,separate_next=next_scope,no_host_graph_replay=True)
        node.namespace(old_ns);committed=save(node);node.stop();node=None
        node=boot('recovered-new')
        recovered=recover(old_ns,a.next_head)
        passed('explicit retry commits complete next generation and native restart recovers exact root',committed=committed,recovered=recovered)
    finally:
        if node:node.stop()

if __name__=='__main__':main()
