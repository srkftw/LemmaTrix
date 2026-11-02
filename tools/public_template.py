"""Generate native workbench starter bytes from the pinned public SDK recipe."""
from pathlib import Path
import json
import public_sdk,sdk
ROOT=Path(__file__).resolve().parents[1]
def members():
 project={'schema':1,'name':'native-tool','facet':'NativeApplication','module':'Main','entry':'Main.main','machine':'LT-Dev-v2','profile':2,'rights':768,'license':'NOASSERTION','distribution_authority':'local author declaration; review before distribution','persistence':'ephemeral','network':'unavailable','assurance':['host-bootstrap Lean/LLVM; source-to-binary unverified']}
 lock=public_sdk.make_lock(module='Main',entry='Main.main',profile=2,dependencies=[],facet='NativeApplication')
 return [('Main.lean',sdk.TEMPLATE),('lemma.project.json',public_sdk.canonical(project)+b'\n'),('lemma.lock.json',public_sdk.canonical(lock)+b'\n')]
def generated():
 files=members();out=['import Guest.Primitives','namespace Guest.PublicTemplate','-- Generated from the ordinary public SDK starter and exact lock; no owner API.']
 for function,items in [('writeName',[(n.encode(),len(n))for n,_ in files]),('write',[(b,len(b))for _,b in files])]:
  out+=['def '+function+' (index target t : UInt64) : UInt64 :=']
  for i,(data,n)in enumerate(items):
   out+=['  '+('if'if i==0 else'else if')+' index == '+str(i)+' then']
   for offset in range(0,n,8):out+=['    let t := Guest.store64 (target+'+str(offset)+') '+str(int.from_bytes(data[offset:offset+8].ljust(8,b'\0'),'little'))+' t']
   out+=['    t']
  out+=['  else t']
 out+=['def length (index : UInt64) : UInt64 := '+''.join('if index == '+str(i)+' then '+str(len(b))+' else 'for i,(_,b)in enumerate(files))+'0','def nameLength (index : UInt64) : UInt64 := '+''.join('if index == '+str(i)+' then '+str(len(n))+' else 'for i,(n,_)in enumerate(files))+'0','end Guest.PublicTemplate','']
 return '\n'.join(out)
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');a=p.parse_args();target=ROOT/'Guest/PublicTemplate.lean';text=generated()
 if a.check:
  if target.read_text()!=text:raise SystemExit('Native starter is stale; regenerate with python3 tools/public_template.py')
  print('Native public SDK starter and exact lock match')
 else:target.write_text(text)
