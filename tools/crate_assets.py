"""Reproduce only the original, non-executable Crate Workshop resource bytes."""
import argparse,hashlib,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
GAME_ID=hashlib.sha256(b'crate-workshop').digest()
LEVELS=(
 ('########','#      #','#      #','# @$ . #','#      #','#      #','#      #','########'),
 ('########','#      #','#  .   #','#  $   #','#  @   #','#      #','#      #','########'),
 ('########','#      #','# . .  #','# $ $  #','#  @   #','#      #','#      #','########'),
 ('########','#      #','# .  . #','# $  $ #','#  @   #','#  ##  #','#      #','########'),
)
MOD_LEVEL=('########','#      #','#      #','# @$.  #','#      #','#      #','#      #','########')

def encode(levels):
 if not 1<=len(levels)<=8:raise ValueError('one through eight original levels required')
 out=struct.pack('<2Q',0x315445544152434c,1)+GAME_ID+struct.pack('<2Q',len(levels),0)
 for rows in levels:
  if len(rows)!=8 or any(len(row)!=8 for row in rows):raise ValueError('8x8 grid required')
  walls=goals=boxes=0;players=[]
  for y,row in enumerate(rows):
   for x,char in enumerate(row):
    if char not in '# .$@*+':raise ValueError('unknown cell')
    bit=1<<(y*8+x)
    if char=='#':walls|=bit
    if char in '.*+':goals|=bit
    if char in '$*':boxes|=bit
    if char in '@+':players.append(y*8+x)
  if len(players)!=1:raise ValueError('one player required')
  out+=struct.pack('<6Q',1,walls,goals,boxes,players[0],0)
 return out

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check',action='store_true');a=p.parse_args(argv)
 directory=ROOT/'resources/crate-workshop';directory.mkdir(parents=True,exist_ok=True)
 for name,levels in [('original',LEVELS),('near-goal',(MOD_LEVEL,*LEVELS[1:]))]:
  raw=encode(levels);path=directory/(name+'.ltlevels')
  if a.check:
   if path.read_bytes()!=raw:raise ValueError('resource differs from original recipe: '+str(path))
  else:path.write_bytes(raw)
  print(name,len(raw),hashlib.sha256(raw).hexdigest())
 return 0
if __name__=='__main__':raise SystemExit(main())
