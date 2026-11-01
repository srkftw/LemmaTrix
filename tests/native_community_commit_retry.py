"""Observe one exact committed Feed retry under positive durable budgets.

The original signed envelope comes from the completed native publication. The
operator submits that envelope once through its existing authorized native
service binding. It creates no post, signature, content upload or policy grant.
"""
import argparse,hashlib,json,time
from pathlib import Path
from native_community_campaign import attach_campaign
from native_community_reconnect import service


def matching(guest,event_id):
 rows=[];cursor=0
 for _ in range(65):
  fields,body=service(guest.client,491,action=5,handle=cursor,allowed=(0,6))
  if fields[0]==6:return rows
  assert len(body)==512 and hashlib.sha256(body[32:]).digest()==body[:32]
  assert cursor<fields[1]<=64,fields
  if body[:32]==event_id:rows.append((fields,body))
  cursor=fields[1]
 raise AssertionError('native bounded timeline did not terminate')


def event_budget(guest,index,event_id):
 fields,body=service(guest.client,490,action=14,handle=index,allowed=(0,2))
 if fields[0]==2:
  return dict(available=False,status=2,reason='This service does not expose administrative action14 per-event counters.')
 assert fields[1]==index+1 and body==event_id,(fields,body.hex())
 assert fields[2]&3==3,'event must already be replicated and have its durable reservation'
 assert 1<=fields[3]<=9 and fields[4]>0 and fields[5]>0,fields
 return dict(available=True,event=body.hex(),fields=list(fields),flags=fields[2],attempts=fields[3],reserved_bytes=fields[4],reserved_work=fields[5])


def compare_budget(before,after,policy,same_policy):
 assert same_policy==policy and len(policy)==32,'the exact retained replication policy must be unchanged'
 assert before[2]>0 and before[5]>0,'positive existing event byte/work reservations are required'
 # A consented native transport lease may roll while the duplicate's signature
 # is checked. Its finite allocation is independent of the event reservation.
 assert before[:3]==after[:3] and before[4:]==after[4:],(before,after)
 assert 0<before[3]<=after[3]<=before[1]<=16777216,(before,after)
 if before[3]==after[3]:
  assert after==before
  state='unchanged'
 else:state='finite_native_pool_roll'
 return dict(state=state,before_bytes=before[3],after_bytes=after[3],additional_bytes=after[3]-before[3],finite_ceiling=before[1],attribution='Transport allocations may roll independently under existing consent; this probe does not attribute a roll to the duplicate event.')


def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--attach',type=Path,required=True);args=parser.parse_args()
 out=args.attach.resolve();prior=json.loads((out/'reconnect.json').read_text());assert prior['result']=='pass' and prior['done']['retry'] and prior['done']['ephemeral']
 result_path=out/'commit-retry-budget.json';assert not result_path.exists(),'preserve the existing record; use a fresh campaign for this probe'
 row=bytes.fromhex(prior['accepted_row']);assert len(row)==512 and hashlib.sha256(row[32:]).digest()==row[:32]
 started=time.monotonic()
 with attach_campaign(out,graphical=())as campaign:
  alpha,beta=campaign.actors['alpha'],campaign.actors['beta']
  alpha_rows,beta_rows=matching(alpha,row[:32]),matching(beta,row[:32])
  assert len(alpha_rows)==len(beta_rows)==1 and alpha_rows[0][1]==beta_rows[0][1]==row
  assert alpha_rows[0][0][3]==3,'the source must have committed its replica acknowledgement before this probe'
  index=alpha_rows[0][0][1]-1
  event_before=event_budget(alpha,index,row[:32])
  before,policy=service(alpha.client,490,action=12)
  assert before[2]>0 and before[5]>0,'positive existing event byte/work reservations are required'
  response,_=service(alpha.client,491,action=1,data=row[32:]);assert response[0]==0 and response[2]==2,response
  after,same_policy=service(alpha.client,490,action=12)
  transport=compare_budget(before,after,policy,same_policy)
  event_after=event_budget(alpha,index,row[:32]);assert event_after==event_before,'the exact event flags, attempts and reserved byte/work must not renew'
  alpha_rows,beta_rows=matching(alpha,row[:32]),matching(beta,row[:32])
  assert len(alpha_rows)==len(beta_rows)==1 and alpha_rows[0][1]==beta_rows[0][1]==row
  assert alpha_rows[0][0][1]==index+1 and alpha_rows[0][0][3]==3
  result=dict(schema=2,result='pass',image_sha256=campaign.state['configuration']['image_sha256'],event=row[:32].hex(),signed_sha256=hashlib.sha256(row[32:]).hexdigest(),duplicate_reply=list(response),before_durable_budget=list(before),after_durable_budget=list(after),policy_hash=policy.hex(),transport_allocation=transport,per_event_before=event_before,per_event_after=event_after,copies_per_federation=1,elapsed_seconds=time.monotonic()-started,scope='One exact native already-committed envelope admission after its replica acknowledgement, with no append, commit, new author signature, route, policy or grant. The preceding GUI continuation separately exercises a fresh-context exact event retry.',limits='Aggregate event byte/work reservations remain unchanged. Where action14 is supported, the exact event flags, attempts and reserved byte/work also remain unchanged. Status2 explicitly records unavailable per-event counters on a legacy service. Existing finite native transport allocation may roll independently; no causal claim about that roll is made.')
  marker=out/'management-control-boundary.json'
  if marker.exists():campaign.state['actors']['beta']['synchronous_admin_until_restart']=json.loads(marker.read_text())['synchronous_admin_until_restart'];(out/'native-actors.json').write_text(json.dumps(campaign.state,indent=2)+'\n')
 result_path.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
