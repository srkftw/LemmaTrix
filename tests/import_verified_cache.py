"""Private checked staged bytes remain distinct from typed graph publication."""
import argparse,hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import live,projects

def denied(call,code):
 try:call()
 except ValueError as error:assert str(error)==f'Objects status{code}',str(error)
 else:raise AssertionError('unchecked or stale staged bytes became readable')

def main():
 p=argparse.ArgumentParser();p.add_argument('--socket',required=True,type=Path);p.add_argument('--output',type=Path);a=p.parse_args();c=live.Client(a.socket,timeout=180);checks=[]
 def begin(name,payload,kind=11,identity=None):
  identity=identity or projects.canonical_node(kind,payload);encoded=name.encode();root=struct.pack('<2Q',0,len(encoded))+bytes.fromhex(identity)+encoded.ljust(80,b'\0')
  txn=c.objects(35,a=1,b=1,c=len(payload),data=root)[0][1]
  c.objects(36,txn,0,kind,len(payload),data=bytes.fromhex(identity)+bytes(32)+hashlib.sha256(payload).digest());return txn
 def append(txn,payload,start=0):
  for offset in range(start,len(payload),512):c.objects(37,txn,0,offset,data=payload[offset:offset+512])
 def read(txn,offset=0,count=512):return c.objects(43,txn,0,offset,count)
 try:
  missing=projects.canonical_node(10,b'not in this chosen transaction')
  payload=projects.manifest([('Main.lean',10,missing)])
  txn=begin('private-cache',payload);c.objects(37,txn,0,0,data=payload[:32]);denied(lambda:read(txn),2);c.objects(37,txn,0,32,data=payload[32:])
  f,data=read(txn);assert data==payload and f[1:7]==(len(payload),len(payload),0,11,1,0)
  assert not any(r['name']=='private-cache' for r in projects.roots(c));denied(lambda:c.objects(38,txn),2);denied(lambda:read(txn),3)
  checks.append('complete Manifest bytes independently verify before missing dependency closure can publish; incomplete bytes remain unreadable')
  payload=b'checked cache byte contents '+bytes(range(256))*3;txn=begin('cache-a',payload,10);append(txn,payload);parts=[]
  for offset in range(0,len(payload),512):
   f,data=read(txn,offset);assert f[2]==len(payload) and f[3]==offset and f[4:7]==(10,1,0);parts.append(data)
  assert b''.join(parts)==payload;assert read(txn,len(payload))[1]==b'';denied(lambda:read(txn,0,513),2)
  c.objects(39,txn);denied(lambda:read(txn),3)
  checks.append('bounded cached reads return exact complete bytes and EOF without Object caps; cancellation revokes stage handle')
  # Same slot/generation progression must not inherit the prior checked flag.
  different=b'x'*len(payload);txn=begin('cache-b',payload,10);append(txn,different);denied(lambda:read(txn),5);c.objects(39,txn)
  original=bytes.fromhex(projects.canonical_node(10,payload));wrong=(bytes([original[0]^1])+original[1:]).hex();txn=begin('cache-c',payload,10,wrong);append(txn,payload);denied(lambda:read(txn),5);c.objects(39,txn)
  checks.append('fresh allocation rechecks actual payload hash and canonical offered node identity; wrong hash or ID never returns bytes')
  assert not any(r['name'].startswith('cache-') or r['name']=='private-cache' for r in projects.roots(c))
  report=dict(checks=checks,policy='integrity-checked private bytes only; complete typed dependency validation and atomic selected-root publication still require import commit')
  if a.output:a.output.write_text(json.dumps(report,indent=2)+'\n')
  print(json.dumps(report,indent=2))
 finally:c.close()
if __name__=='__main__':main()
