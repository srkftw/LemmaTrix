"""Compiled native Tor circuit and stream SENDME flow, beyond500 DATA cells."""
import argparse,hashlib,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import onion_crypto as native
from network_crypto import store_bytes
import driver

def source(cells):
 s='''import Guest.TorCells
namespace build.OnionStreamFlow
def feedback (c r stream t : UInt64) : UInt64 :=
  let t := if stream == 0 then Guest.TorCells.sendme r 0 0x703000 t else Guest.TorCells.sendmeStream r 0 t
  if t == Guest.TorCells.err then 1 else
  let n := if stream == 0 then 23 else 0
  let t := Guest.TorCells.prepare 0x710000 5 stream 0x703000 n 0x701000 t
  let t := Guest.TorCells.originate r 0x6c0000 1 0x710000 t
  if t == Guest.TorCells.err then 2 else
  let t := Guest.TorCells.peel c 0x6c0000 1 0x710000 t
  if Guest.load64 0x6c03e8 t != 0 then 3 else
  if stream == 0 then Guest.TorCells.acceptSendme c 0 0x71000b 23 t else Guest.TorCells.acceptStreamSendme c 0 stream 0 t
partial def transfer (c r i limit t : UInt64) : UInt64 :=
  if i == limit then t else
    let t := Guest.TorCells.prepare 0x710000 2 17 0x700000 4 0x701000 t
    let t := Guest.TorCells.originate c 0x6c0000 0 0x710000 t
    if t == Guest.TorCells.err then 11 else
    let t := Guest.TorCells.peel r 0x6c0000 0 0x710000 t
    if Guest.load64 0x6c03e8 t != 0 then 12 else
    let t := if (i+1)%50 == 0 then feedback c r 17 t else t
    if t != 0 then 13 else
    let t := if (i+1)%100 == 0 then feedback c r 0 t else t
    if t != 0 then 14 else transfer c r (i+1) limit t
def check (t : UInt64) : UInt64 :=
'''
 s+=store_bytes(0x702000,hashlib.shake_256(b'public stream flow fixture').digest(92))+'\n'+store_bytes(0x701000,hashlib.shake_256(b'public padding fixture').digest(509))+'\n'+store_bytes(0x700000,b'DATA')+'\n'
 s+=f'''  let c : UInt64 := 0x6d0000
  let r : UInt64 := 0x6d1000
  let t := Guest.TorCells.init c 0x6c0000 0x702000 t
  let t := Guest.TorCells.init r 0x6c0000 0x702000 t
  let t := transfer c r 0 {cells} t
  if t != 0 then t else
  if Guest.load64 (Guest.TorCells.streamPackage c 0) t != 500 || Guest.load64 (Guest.TorCells.streamDeliver r 0) t != 500 then 21 else
  if Guest.load64 (Guest.TorCells.packageWindow c 0) t != 1000 || Guest.load64 (Guest.TorCells.deliverWindow r 0) t != 1000 then 22 else
  if Guest.load64 (Guest.TorCells.count c 0) t != {cells} || Guest.load64 (Guest.TorCells.count c 1) t != {cells//50+cells//100} then 23 else
  let e := Guest.TorCells.acceptStreamSendme c 0 17 0 t
  if e != Guest.TorCells.err then 24 else
  let e := Guest.TorCells.acceptStreamSendme c 0 18 0 e
  if e != Guest.TorCells.err then 25 else
  let t := Guest.store64 (Guest.TorCells.streamPackage c 0) 450 e
  let e := Guest.TorCells.acceptStreamSendme c 0 17 1 t
  if e != Guest.TorCells.err then 29 else
  let t := Guest.store64 (Guest.TorCells.streamPackage c 0) 0 e
  let t := Guest.TorCells.prepare 0x710000 2 17 0x700000 4 0x701000 t
  let t := Guest.TorCells.copy (Guest.TorCells.hashContext c 0) 0x705000 128 t
  let e := Guest.TorCells.originate c 0x6c0000 0 0x710000 t
  if e != Guest.TorCells.err then 26 else
  if Guest.TorCells.difference (Guest.TorCells.hashContext c 0) 0x705000 128 0 e != 0 then 27 else
  let t := Guest.TorCells.prepare 0x710000 5 0 0x703000 23 0x701000 e
  let t := Guest.TorCells.originate c 0x6c0000 0 0x710000 t
  if t == Guest.TorCells.err then 28 else
  0
end build.OnionStreamFlow
''';return s

def main():
 p=argparse.ArgumentParser();p.add_argument('--backend',action='append',choices=('qemu','x86_64','aarch64'));p.add_argument('--cells',type=int,default=600);a=p.parse_args();assert a.cells>0 and a.cells%100==0
 native.B=driver.ROOT/('build/onion-stream-flow-'+str(a.cells));driver.lean(['-o','Guest/TorCells.olean','Guest/TorCells.lean']);binary=native.build(source(a.cells),'OnionStreamFlow');report=dict(schema=1,profile='ordinary Tor circuit1000/100 and stream500/50 windows',image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),data_cells=a.cells,checks=[native.execute(binary,b) for b in a.backend or ['qemu']],checks_executed=['actual forward DATA and reverse authenticated circuit SENDME','actual reverse empty nonzero-stream SENDME','windows recover through more than500 DATA cells' if a.cells>500 else 'representative stream and circuit window increments','repeated/unsolicited and wrong-stream SENDME denied','nonempty stream SENDME body rejected','exhausted DATA preserves digest state while control remains possible']);(native.B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
