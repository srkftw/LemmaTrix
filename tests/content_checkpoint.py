"""Encrypted private checkpoint/restart/adoption through native SDK boundaries.

This fixture supplies original bytes via normal SDK calls; actual authenticated
provider exchange is separate Library evidence. Restart between the two phases.
"""
import argparse, hashlib, json, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import content, project_vault
from live import Client

def reject(fn, code):
    try: fn()
    except ValueError as error: assert f'status{code}' in str(error), str(error)
    else: raise AssertionError('checkpoint authority boundary accepted')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--socket',required=True,type=Path);p.add_argument('--key',required=True,type=Path)
    p.add_argument('--phase',required=True,choices=('retain','recover-resume'))
    p.add_argument('--metadata',required=True,type=Path);p.add_argument('--old-job',type=int);p.add_argument('--output',type=Path)
    a=p.parse_args();c=content.ContentClient(Client(a.socket,timeout=180))
    try:
        project_vault.unlock(c,a.key.read_bytes())
        raw=content.original_wave(1,2);manifest,chunks,proofs=content.commitments(raw)
        provider1=hashlib.sha256(b'explicit checkpoint source one').digest()
        provider2=hashlib.sha256(b'explicit checkpoint source two').digest()
        federation=hashlib.sha256(b'explicit current federation').digest()
        operation=time.time_ns()&0x7fffffffffffffff;started=time.monotonic()
        if a.phase=='retain':
            h,_,_,_=content.reserve(c,raw,operation,provider1,federation)
            for index in (0,1):content.ingest_chunk(c,h,index,chunks[index],proofs[index])
            old_job=c.objects(301,h,2,data=proofs[2])[0][1]
            c.objects(302,old_job,0,data=chunks[2][:512])
            assert c.objects(306,h)[0][2:4]==(1,8192)
            metadata=c.import_object(a.metadata.read_bytes(),kind=2)
            result=content.retain(c,h,operation+1,metadata=metadata)
            inventory,stored=content.vault_call(c,246)
            assert stored==manifest and inventory[2:4]==(1,8192),inventory
            result.update(old_job_for_stale_check=old_job,verified_retained_bytes=8192,
                          checks=['two verified chunks retained','unverified512-byte staging excluded',
                                  'private encrypted bitmap and selected metadata committed together'])
        else:
            result=content.recover(c,operation);read_h=result['handle']
            state,recovered=c.objects(306,read_h)
            assert state[2:4]==(1,8192) and recovered==manifest,state
            assert c.read_object(result['metadata_handle'])==a.metadata.read_bytes()
            assert c.objects(307,read_h,0,512)[1]==raw[:512]
            reject(lambda:c.objects(307,read_h,8192,512),6)
            reject(lambda:c.objects(301,read_h,2,data=proofs[2]),1)
            if a.old_job:reject(lambda:c.objects(304,a.old_job),3)
            binding=provider2+federation+content.sha(manifest)
            reject(lambda:c.objects(315,read_h,operation+1,len(raw)-1,3,data=binding),2)
            bad=provider2+federation+hashlib.sha256(b'wrong immutable root').digest()
            reject(lambda:c.objects(315,read_h,operation+1,len(raw),3,data=bad),2)
            acquired=c.objects(315,read_h,operation+1,len(raw),3,data=binding)[0][1]
            assert acquired!=read_h
            reject(lambda:c.objects(301,read_h,2,data=proofs[2]),1)
            for index in range(2,len(chunks)):content.ingest_chunk(c,acquired,index,chunks[index],proofs[index])
            job=c.objects(310,acquired)[0][1];content.wait_job(c,job);c.objects(305,job,4)
            assert c.objects(306,acquired)[0][2:7]==(2,len(raw),len(raw),len(chunks),len(chunks))
            actual=hashlib.sha256()
            for offset in range(0,len(raw),512):actual.update(c.objects(307,acquired,offset,min(512,len(raw)-offset))[1])
            assert actual.digest()==content.sha(raw)
            result.update(complete_handle=acquired,actual_read_sha256=actual.hexdigest(),reused_verified_bytes=8192,
                          newly_ingested_bytes=len(raw)-8192,checks=['fresh readonly checkpoint','unverified chunk absent',
                          'old job denied','fresh mode/budget/provider/root-bound adoption','old handle stays readonly',
                          'complete resumed bytes match original'])
        result.update(schema=1,phase=a.phase,total_bytes=len(raw),chunks=len(chunks),
                      manifest_sha256=content.sha(manifest).hex(),elapsed_seconds=time.monotonic()-started,
                      network_scope='native SDK fixture; authenticated provider transfer is separate Library evidence')
    finally:c.close()
    text=json.dumps(result,indent=2)+'\n'
    if a.output:a.output.write_text(text)
    print(text,end='')
if __name__=='__main__':main()
