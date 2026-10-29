"""Focused receipt comparison boundaries using actual completed build records.

Mutated temporary records are parser fixtures, never new verifier evidence.
"""
import argparse,hashlib,json,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import remote_build

def main():
 p=argparse.ArgumentParser();p.add_argument('--journey',type=Path,required=True);a=p.parse_args()
 journey=json.loads(a.journey.read_text());builder,verifier=[Path(r['result']) for r in journey['executions']]
 assert remote_build.compare(builder,verifier)['result']=='match'
 original=json.loads(verifier.read_text());binary=Path(original['artifact']['path']).read_bytes()
 with tempfile.TemporaryDirectory(prefix='lt-remote-compare-') as directory:
  directory=Path(directory);mutated=directory/'different.bin';changed=bytes([binary[0]^1])+binary[1:];mutated.write_bytes(changed)
  receipt=json.loads(json.dumps(original));receipt['artifact'].update(path=str(mutated),sha256=hashlib.sha256(changed).hexdigest())
  record=directory/'receipt.json';record.write_text(json.dumps(receipt))
  negative=remote_build.compare(builder,record)
  assert negative['result']=='mismatch' and not negative['bytes_equal']
  receipt['toolchain_id']='00'*32;record.write_text(json.dumps(receipt))
  try:remote_build.compare(builder,record)
  except ValueError as e:assert 'toolchain_id' in str(e)
  else:raise AssertionError('different toolchain accepted')
  receipt=json.loads(json.dumps(original));receipt['remote_contract']['provider_id']=journey['verification']['builder'];record.write_text(json.dumps(receipt))
  try:remote_build.compare(builder,record)
  except ValueError as e:assert 'distinct' in str(e)
  else:raise AssertionError('builder accepted as separate verifier')
  receipt=json.loads(json.dumps(original));receipt['artifact']['path']=str(mutated);record.write_text(json.dumps(receipt))
  try:remote_build.compare(builder,record)
  except ValueError as e:assert 'changed' in str(e)
  else:raise AssertionError('uncommitted changed artifact accepted')
 report={'kind':'comparison-parser-boundaries','actual_completed_pair':str(a.journey),'actual_pair_bytes_equal':True,'different_actual_fixture_bytes':'mismatch','different_toolchain':'reject','same_provider':'reject','changed_uncommitted_artifact':'reject','negative_records':'temporary synthetic mutations; no claim of additional verifier computation'}
 (a.journey.parent/'comparison-boundaries.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':main()
