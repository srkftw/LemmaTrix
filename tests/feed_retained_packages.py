"""Controller package guards using signed bytes and a read-only catalog model.

This is not native lifecycle or recovery evidence. Native25/26 and typed recovery
are exercised by the connected retained-account continuation.
"""
import argparse,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from native_feed_project_account import retained_pair_packages,check_admitted_pair
import releases

class Catalog:
 def __init__(self,bundle,*,wrong_current=False,changed_header=False,missing=False):
  self.raw=[(bundle/(name+'.ltrel')).read_bytes()for name in('identity','feed-account','feed')]
  self.wrong_current,self.changed_header,self.missing=wrong_current,changed_header,missing
 def request(self,operation,payload):
  if operation==14:
   raw=next(raw for raw in self.raw if raw[128:160]==payload)
   return bytes(64)+(bytes(32)if self.wrong_current else raw[160:192])+bytes(32)
  assert operation==13
  index=struct.unpack('<Q',payload)[0]
  if self.missing or index>=len(self.raw):raise ValueError('guest rejected command13, status1')
  header=bytearray(self.raw[index][:512])
  if self.changed_header:header[192]^=1
  return bytes(header)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--baseline',type=Path,required=True);p.add_argument('--current',type=Path,required=True);a=p.parse_args()
 ids=lambda bundle:{name:releases.inspect((bundle/(name+'.ltrel')).read_bytes())['release_id']for name in('identity','feed-account','feed','feed-federation')}
 old,new=ids(a.baseline),ids(a.current);checks=[]
 def check(name,run,refuse=False):
  try:run()
  except(AssertionError,ValueError):
   if not refuse:raise
  else:
   if refuse:raise AssertionError(name+' unexpectedly accepted')
  checks.append(dict(case=name,result='pass'))
 def admitted(bundle,active,relaunch,catalog):
  paths,packages=retained_pair_packages(bundle,active,relaunch=relaunch)
  check_admitted_pair(catalog,paths,packages,active,relaunch=relaunch)
 check('exact current signed bytes and native header hashes permit same-release relaunch',lambda:admitted(a.current,new,True,Catalog(a.current)))
 check('exact parents and strictly newer versions permit ordinary upgrade',lambda:admitted(a.current,old,False,Catalog(a.baseline)))
 check('successor cannot masquerade as exact current release',lambda:retained_pair_packages(a.current,old,relaunch=True),True)
 check('same current version cannot masquerade as successor',lambda:retained_pair_packages(a.current,new),True)
 check('wrong native current release refuses relaunch',lambda:admitted(a.current,new,True,Catalog(a.current,wrong_current=True)),True)
 check('changed native executable commitment refuses relaunch',lambda:admitted(a.current,new,True,Catalog(a.current,changed_header=True)),True)
 check('missing native catalog entry refuses relaunch',lambda:admitted(a.current,new,True,Catalog(a.current,missing=True)),True)
 print(json.dumps(dict(schema=1,result='pass',checks=checks,scope='Controller guards only: real signed packages, modeled read-only native catalog. No actor control, native relaunch, key recovery or storage claim.'),indent=2))

if __name__=='__main__':main()
