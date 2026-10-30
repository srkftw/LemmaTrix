"""Check generated native call frames against the existing guarded stack.

This is a conservative assembly resource check, not a compiler/binary proof.
External runtime primitives are leaf stubs with no generated frame; interrupts
use the separate kernel stack. A non-tail call cycle is rejected as unknown.
"""
import argparse, json, re
from pathlib import Path

def inspect(path,entry,budget):
 parts=re.split(r'(?m)^([A-Za-z][\w]*):\n',path.read_text());functions={}
 for i in range(1,len(parts),2):
  name,body=parts[i:i+2];frame=re.search(r'li t6, (\d+)\n  sub sp, sp, t6',body)
  if frame:functions[name]=(int(frame[1]),set(re.findall(r'^  call (\w+)',body,re.M)))
 if entry not in functions:raise ValueError('entry absent from generated assembly')
 def visit(name,seen):
  if name in seen:raise ValueError('unbounded non-tail call cycle: '+name)
  if name not in functions:return (0,[])
  frame,children=functions[name]
  extra,path=max((visit(child,seen|{name}) for child in children),default=(0,[]),key=lambda item:item[0])
  return frame+extra,[dict(function=name,frame=frame)]+path
 return visit(entry,set())

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--assembly',type=Path,required=True);p.add_argument('--entry',required=True);p.add_argument('--bytes',type=int,default=16384);a=p.parse_args()
 size,path=inspect(a.assembly,a.entry,a.bytes)
 print(json.dumps(dict(assembly=str(a.assembly),entry=a.entry,bytes=size,budget=a.bytes,path=path),indent=2))
 if size>a.bytes:raise SystemExit('generated call frames exceed the guarded stack')
if __name__=='__main__':main()
