"""Offline controller provenance/observation guards; no native actors or builds."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace as NS
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live
from native_community_campaign import selected_delivery_package
from native_community_reconnect import write_no_vault_ledger
from native_community_policy_restart import blocked_selection_allowed
import native_delivery_idle_continuation as idle

INFO=dict(version='0.8.2',rights=1024,release_id='11'*32,project_id='22'*32)

def write(path,value):path.write_text(json.dumps(value,indent=2)+'\n')

def refuses(action):
 try:action()
 except (ValueError,AssertionError):return
 raise AssertionError('invalid public provenance was accepted')


def main():
 checks=[]
 previous=b'p'*512;author=b'a'*32;marker=bytes(144)+author+bytes(336)
 assert all(blocked_selection_allowed(value,previous,author)for value in(previous,bytes(512),marker))
 for offset in(0,32,143,176,511):
  bad=bytearray(marker);bad[offset]=1
  assert not blocked_selection_allowed(bytes(bad),previous,author)
 assert not blocked_selection_allowed(bytes(144)+b'b'*32+bytes(336),previous,author)
 assert not blocked_selection_allowed(marker[:-1],previous,author)
 checks.append('blocked row accepts exact legacy/current shapes and refuses altered event/body bytes or author')
 with tempfile.TemporaryDirectory(prefix='native-shipping-guards-')as temporary,patch.object(live,'Client',side_effect=AssertionError('no actor access')):
  out=Path(temporary);state=dict(configuration=dict(messenger=dict(delivery=INFO['release_id'])))
  write(out/'delivery.ltrel',INFO)
  # Synthetic public package metadata tests only the host provenance selector.
  with patch('native_community_campaign.releases.inspect',side_effect=lambda raw:json.loads(raw)):
   path,info,source=selected_delivery_package(out,state,'alice')
   assert path.name=='delivery.ltrel'and source=='initial_common_configuration'and info==INFO
   runtime=copy.deepcopy(state);runtime['current_runtime_packages']=dict(messenger_by_person=dict(alice=dict(delivery=INFO['release_id'])))
   write(out/'delivery-recovery-0.8.2.ltrel',INFO)
   assert selected_delivery_package(out,runtime,'alice')[2]=='explicit_runtime_successor'
   runtime['current_runtime_packages']['messenger_by_person']['alice']['delivery']='33'*32
   refuses(lambda:selected_delivery_package(out,runtime,'alice'))
   write(out/'delivery.ltrel',dict(INFO,version='0.8.1'))
   refuses(lambda:selected_delivery_package(out,state,'alice'))
   write(out/'delivery.ltrel',dict(INFO,rights=799))
   refuses(lambda:selected_delivery_package(out,state,'alice'))
   write(out/'delivery.ltrel',INFO)
   checks.append('fresh/successor package provenance accepted; wrong release, old version and rights refused before diagnostic')
   actors={name:NS(name=name,delivery=100+i,owner=200+i,ui=300+i)for i,name in enumerate(('alice','bob'))}
   order=[]
   class Client:
    def __init__(self,g):self.g=g
    def request(self,operation,data):
     assert operation==14 and data==bytes.fromhex(INFO['project_id']);order.append((self.g.name,'catalog'))
     return bytes(64)+bytes.fromhex(INFO['release_id'])
   for g in actors.values():g.client=Client(g)
   def endpoint(client,role,operation):
    assert(role,operation)==(4,464);order.append((client.g.name,'endpoint'));return client.g.delivery
   def diagnostic(g,role,operation,**kwargs):
    assert(role,operation,kwargs)==(4,464,dict(a=5));order.append((g.name,'diagnostic'))
    return(0,7,800,0,0,0,512 if g.name=='alice'else 511,1),b''
   def terminal(g,operation):
    assert operation==41;return(0,1,3,0,1000000,3000,0,1),b'p'*32
   campaign=NS(state=state,actors=actors)
   with patch.object(idle,'attach_campaign',return_value=contextlib.nullcontext(campaign)),patch.object(idle.messenger,'endpoint',side_effect=endpoint),patch.object(idle,'role',side_effect=diagnostic),patch.object(idle,'net',side_effect=terminal),patch.object(idle,'send_ui',side_effect=AssertionError('no input below threshold')),patch.object(idle.time,'sleep',side_effect=AssertionError('no idle padding')),patch.object(sys,'argv',['idle','--attach',str(out)]),contextlib.redirect_stdout(io.StringIO()):
    idle.main()
   skipped=json.loads((out/'delivery-idle-useful-work.json').read_text())
   assert skipped['result']=='skipped-not-qualified'and skipped['native_text_sent']is False
   assert order==[(name,step)for name in('alice','bob')for step in('catalog','endpoint','diagnostic')]
   checks.append('post512 exits with explicit not-qualified record below513, after exact catalog/endpoint checks and without input/sleep')
  config=dict(image_sha256='44'*32);author='55'*32
  check=dict(result='pass',old_owner=8,new_owner=264,historical_feed_public=author,current_feed_identity_present=False,current_feed_public=None)
  completed=dict(result='pass',done=dict(ephemeral=True),configuration=config,checks=[check])
  actors=dict(configuration=config,personal=dict(charlie=dict(feed=dict(owner=264,ui=265),feed_public=author,historical_feed_public=author,current_feed_identity_present=False,current_feed_public=None)),events=dict(long=dict(author=author)))
  for name,value in [('reconnect-progress.json',completed),('reconnect.json',completed),('native-actors.json',actors)]:write(out/name,value)
  ledger=write_no_vault_ledger(out,actors,completed,'66'*32)
  assert ledger['schema']==2 and ledger['completed_native_checks']==check
  assert ledger['reconnect_sha256']==ledger['final_reconnect_sha256']==hashlib.sha256((out/'reconnect.json').read_bytes()).hexdigest()
  assert ledger['current_feed_owner']==264 and ledger['current_feed_ui']==265 and ledger['current_feed_public']is None
  invalid=copy.deepcopy(actors);invalid['personal']['charlie']['feed']['owner']=8
  refuses(lambda:write_no_vault_ledger(out,invalid,completed,'66'*32))
  invalid=copy.deepcopy(completed);invalid['result']='running'
  refuses(lambda:write_no_vault_ledger(out,actors,invalid,'66'*32))
  checks.append('schema2 ledger binds final successful files and observed fresh owner; incomplete/stale observations refused')
 print(json.dumps(dict(schema=1,result='pass',checks=checks,scope='Mocked public package metadata and completed-observation guards only; no native state, application authority, keys, actors, builds or wire execution.'),indent=2))

if __name__=='__main__':main()
