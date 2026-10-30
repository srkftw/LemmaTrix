"""Dedicated v1 vault corruption and Launcher recovery-reference regression.

Ciphertext corruption is rejected by Vault204 before Launcher creates a stage.
The optional ordinary Lean probe separately exercises the real restoreChunks
failure and discard helper after a real stage allocation; it never impersonates
Launcher or obtains Vault authority. Neither check is graphical save recovery.
"""
import argparse,contextlib,hashlib,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live,nodes,project_vault,releases
from library_journey import wait


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--probe',type=Path);p.add_argument('--attempts',type=int,default=65)
 p.add_argument('--key',type=Path,default=ROOT/'build/campaign005/publisher.pem');p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');a=p.parse_args()
 if a.attempts<=64:raise ValueError('regression requires more than64 recovery attempts')
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);sock=out/'portal.sock';vault=out/'objects.vault';key=out/'objects.key';log=(out/'guest.log').open('wb');proc=None;client=None;checks=[]
 def passed(label,**facts):
  checks.append(dict(check=label,result='passed',**facts));print('PASS',label,flush=True);(out/'progress.json').write_text(json.dumps(dict(image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),checks=checks),indent=2)+'\n')
 def stats():return list(client.objects(10)[0][1:4])
 def rejected(operation):
  try:operation()
  except ValueError as error:return str(error)
  raise AssertionError('expected rejection')
 def raw_vault(op):return client.request(op,struct.pack('<8Q',op,0,3,0,0,0,0,1))
 try:
  subprocess.run([str(ROOT/'lt'),'vault-init',str(vault),'--sectors','512','--key-out',str(key)],cwd=ROOT,check=True)
  command=list(map(str,[ROOT/'lt','run','--backend','qemu','--image',a.image,'--socket',sock,'--vault',vault]));proc=subprocess.Popen(command,cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
  wait(sock.exists,90,'guest boot');client=live.Client(sock,timeout=180);project_vault.unlock(client,key.read_bytes())
  # Structurally valid original schema1 save. This is selected diagnostic data,
  # not a claim of Game execution or its additional selected-level validation.
  payload=bytearray(192);struct.pack_into('<2Q',payload,0,0x3156415343544c,1);payload[16:48]=hashlib.sha256(b'Launcher recovery regression game').digest();payload[48:80]=hashlib.sha256(b'Launcher recovery regression pack').digest();struct.pack_into('<6Q',payload,80,1,0,1,1<<28,27,0);payload=bytes(payload)
  selected=client.import_object(payload,2);retained=client.request(203,struct.pack('<Q',selected));assert len(retained)==64 and struct.unpack_from('<Q',retained)[0]==0
  recovered=client.request(207);assert len(recovered)==96 and struct.unpack_from('<Q',recovered)[0]==0
  recovered_handle=struct.unpack_from('<Q',recovered,8)[0];assert client.read_object(recovered_handle)==payload
  client.objects(47,recovered_handle);client.objects(47,selected)
  unrelated_payload=b'private unrelated Object survives selected ciphertext corruption';unrelated=client.import_object(unrelated_payload,2)
  allocation=client.import_object(b'pre-fault generation witness',2);before_handle=allocation;client.objects(47,allocation);baseline=stats()
  original=vault.read_bytes();candidates=[]
  for sector in (0,1):
   root=original[sector*512:(sector+1)*512]
   if struct.unpack_from('<Q',root)[0]==0x31544c56544c:candidates.append((struct.unpack_from('<Q',root,24)[0],sector,root))
  generation,root_sector,root=max(candidates);length=struct.unpack_from('<Q',root,40)[0];bank_sector=8 if struct.unpack_from('<Q',root,32)[0]==0 else 152
  assert generation==1 and length==192 and root[:128]==original[bank_sector*512:bank_sector*512+128]
  changed=bytearray(original);cipher_offset=bank_sector*512+128;changed[cipher_offset+17]^=0x80
  # The public cipher checksum is not authority. Preserve the authenticated
  # header/tag, and update only this outer checksum to the altered ciphertext.
  changed[root_sector*512+144:root_sector*512+176]=hashlib.sha256(changed[cipher_offset:cipher_offset+length]).digest()
  assert changed[root_sector*512:root_sector*512+144]==original[root_sector*512:root_sector*512+144]
  assert changed[cipher_offset-128:cipher_offset]==original[cipher_offset-128:cipher_offset]
  assert changed[cipher_offset+length:cipher_offset+length+16]==original[cipher_offset+length:cipher_offset+length+16]
  with vault.open('r+b',buffering=0) as stream:stream.write(changed);os.fsync(stream.fileno())
  vault_failure=struct.unpack_from('<8Q',raw_vault(204));assert vault_failure[0]==5,vault_failure
  failures=[]
  for attempt in range(a.attempts):
   failure=rejected(lambda:client.request(207));assert failure=='guest rejected command207, status1',failure;failures.append(failure)
   assert stats()==baseline,('failed207 leaked owned records/bytes/grants',attempt+1,baseline,stats())
   assert client.read_object(unrelated)==unrelated_payload
  fresh=client.import_object(b'post-fault generation witness',2);after_handle=fresh
  assert before_handle&255==after_handle&255 and (after_handle>>8&0xffffff)==(before_handle>>8&0xffffff)+1,'pre-stage auth rejection unexpectedly allocated Object capabilities'
  assert client.read_object(fresh)==b'post-fault generation witness';client.objects(47,fresh);assert stats()==baseline
  passed('real v1 ciphertext corruption fails closed before stage allocation;65 or more Launcher207 failures preserve actual owned records, reserved bytes, grants and unrelated Objects',attempts=a.attempts,typed_save_bytes=192,generation=generation,root_sector=root_sector,bank_sector=bank_sector,ciphertext_byte_offset=cipher_offset+17,authenticated_header_and_tag_unchanged=True,public_cipher_checksum_recomputed=True,vault204_status=vault_failure[0],launcher207_error=failures[0],owned_records_reserved_bytes_grants_before=baseline,owned_records_reserved_bytes_grants_after=stats(),before_allocation_handle=before_handle,after_allocation_handle=after_handle,allocation_generation_delta=1,stage_created_during207=False,selected_payload_sha256=hashlib.sha256(payload).hexdigest(),unrelated_object_sha256=hashlib.sha256(unrelated_payload).hexdigest(),backing_sha256_before=hashlib.sha256(original).hexdigest(),backing_sha256_after=hashlib.sha256(changed).hexdigest())
  probe=None
  if a.probe:
   raw,_=releases.make(a.probe,'launcher-recovery-probe','1.0.0',127,a.key,profile=2,license='NOASSERTION');path=out/'launcher-recovery-probe.ltrel';path.write_bytes(raw);info=releases.inspect(raw,releases.public_modulus(a.public));instance=nodes.start_package(client,nodes.approved_package(path,a.public,info['release_id'],127),raw)
   rows=client.request(2);actual=[struct.unpack_from('<4Q',rows,i) for i in range(0,len(rows),32) if struct.unpack_from('<Q',rows,i)[0]==instance];assert len(actual)==1 and 0<actual[0][1]<5 and actual[0][2]==127
   observations=[]
   for attempt in range(a.attempts):
    data=client.request(150,struct.pack('<Q8Q',instance,930,0,0,0,0,0,0,1));assert len(data)==128;words=struct.unpack('<16Q',data);assert words[0]==0,words
    assert words[2]==0xffffffffffffffff and words[3]==0 and words[4:7]==(0,0,0) and words[8:11]==(1,192,1) and words[11]==3,words
    observations.append(dict(stage_handle=words[1],restore_result=words[2],pending_cleanup=words[3],after_owned_records_bytes_grants=list(words[4:7]),during_owned_records_bytes_grants=list(words[8:11]),stale_stage_status=words[11]))
    assert stats()==baseline and client.read_object(unrelated)==unrelated_payload
   assert len({o['stage_handle']for o in observations})==a.attempts
   passed('ordinary signed caller creates real192-byte stages; actual Launcher.restoreChunks receives Vault206 authority denial and exact discardRecoveredSave reclaims every failed stage',attempts=a.attempts,actual_caller_rights=127,caller_instance=instance,restored_vault_authority=False,baseline_probe_owned_records_bytes_grants=[0,0,0],observations=observations,stage_created=True,launcher_role_impersonated=False,scope='function-boundary negative; not end-to-end207 post-stage fault injection')
   probe=dict(source='tests/fixtures/LauncherRecoveryProbe.lean',source_sha256=hashlib.sha256((ROOT/'tests/fixtures/LauncherRecoveryProbe.lean').read_bytes()).hexdigest(),binary_sha256=hashlib.sha256(a.probe.read_bytes()).hexdigest(),release_id=info['release_id'],package_sha256=hashlib.sha256(raw).hexdigest(),actual_rights=127,instance=instance)
  report=dict(schema=1,result='passed',backend='qemu',image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),launcher_source_sha256=hashlib.sha256((ROOT/'Guest/Launcher.lean').read_bytes()).hexdigest(),command=command,checks=checks,probe=probe,limitations=['dedicated newly initialized explicit development Objects-v1 backing; intentional ciphertext fault only','Vault204 authenticates the complete v1 payload before Launcher207 allocates a stage, so this real207 fault is pre-stage rejection','optional ordinary fixture exercises actual imported restoreChunks/discard helper after its own stage allocation and an actual kernel-denied Vault206; it has no Launcher or Vault authority','no graphical N/save recovery, Game execution, media pipeline, speaker output, physical durability or corruption recovery success claimed'])
  (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:
  if client:
   with contextlib.suppress(EOFError,OSError,ValueError):client.request(70)
   client.close()
  if proc and proc.poll()is None:
   try:proc.wait(20)
   except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGTERM);proc.wait(10)
  log.close()


if __name__=='__main__':main()
