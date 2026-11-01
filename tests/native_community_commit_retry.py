"""Observe one exact committed Feed retry under positive durable budgets.

The original signed envelope comes from the completed native publication. The
operator submits that envelope once through its existing authorized native
service binding. It creates no post, signature, content upload or policy grant.
"""
import argparse,hashlib,json,struct,time
from pathlib import Path
from native_community_campaign import attach_campaign
from native_community_reconnect import service


def matching(guest,event_id):
 rows=[];cursor=0
 for _ in range(64):
  fields,body=service(guest.client,491,action=5,handle=cursor,allowed=(0,6))
  if fields[0]==6:return rows
  assert len(body)==512 and hashlib.sha256(body[32:]).digest()==body[:32]
  if body[:32]==event_id:rows.append(body)
  cursor=fields[1]
 raise AssertionError('native bounded timeline did not terminate')


def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--attach',type=Path,required=True);args=parser.parse_args()
 out=args.attach.resolve();prior=json.loads((out/'reconnect.json').read_text());assert prior['result']=='pass' and prior['done']['retry'] and prior['done']['ephemeral']
 row=bytes.fromhex(prior['accepted_row']);assert len(row)==512 and hashlib.sha256(row[32:]).digest()==row[:32]
 started=time.monotonic()
 with attach_campaign(out,graphical=())as campaign:
  alpha,beta=campaign.actors['alpha'],campaign.actors['beta']
  assert matching(alpha,row[:32])==[row]and matching(beta,row[:32])==[row]
  before,policy=service(alpha.client,490,action=12)
  assert before[2]>0 and before[5]>0,'positive existing event byte/work reservations are required'
  response,_=service(alpha.client,491,action=1,data=row[32:]);assert response[0]==0 and response[2]==2,response
  after,same_policy=service(alpha.client,490,action=12);assert after==before and same_policy==policy
  assert matching(alpha,row[:32])==[row]and matching(beta,row[:32])==[row]
  result=dict(schema=1,result='pass',image_sha256=campaign.state['configuration']['image_sha256'],event=row[:32].hex(),signed_sha256=hashlib.sha256(row[32:]).hexdigest(),duplicate_reply=list(response),before_durable_budget=list(before),after_durable_budget=list(after),policy_hash=policy.hex(),copies_per_federation=1,elapsed_seconds=time.monotonic()-started,scope='One exact native already-committed envelope admission, with no append, commit, new author signature, route, policy or grant. The preceding GUI continuation separately exercises a fresh-context exact event retry.',limits='This check proves unchanged exposed native aggregate event byte/work and allocation tuples. Per-row retry attempts are not exposed by the current operator API.')
  marker=out/'management-control-boundary.json'
  if marker.exists():campaign.state['actors']['beta']['synchronous_admin_until_restart']=json.loads(marker.read_text())['synchronous_admin_until_restart'];(out/'native-actors.json').write_text(json.dumps(campaign.state,indent=2)+'\n')
 (out/'commit-retry-budget.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
