"""Public-profile CLI releases its borrowed read cap; no native actor is used."""
import contextlib
import io
import json
import struct
import sys
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import feed

class Client:
 def __init__(self,fail_read=False,fail_write=False):
  self.fail_read,self.fail_write=fail_read,fail_write
  self.calls=[]
 def request(self,operation,payload):
  assert operation==150 and struct.unpack_from('<2Q',payload)==(900,794)
  self.calls.append('export-cap')
  return struct.pack('<8Q',0,777,0,0,0,0,0,1)
 def read_object(self,handle):
  assert handle==777;self.calls.append('read')
  if self.fail_read:raise ValueError('read failed')
  return bytes(2048)
 def objects(self,operation,handle):
  assert(operation,handle)==(47,777);self.calls.append('drop-borrowed-cap')
 def close(self):self.calls.append('close')

def main():
 checks=[]
 for name,fail_read,fail_write in [('success',False,False),('read failure',True,False),('write failure',False,True)]:
  client=Client(fail_read,fail_write)
  def write(path,data):
   assert path==Path('unused-profile')and len(data)==2048
   client.calls.append('write')
   if fail_write:raise ValueError('write failed')
  error=None
  with patch.object(feed.live,'Client',return_value=client),patch.object(feed.releases.pkg,'write_new',side_effect=write),contextlib.redirect_stdout(io.StringIO()):
   try:feed.main(['--socket','unused','export-profile','--ui','900','--output','unused-profile'])
   except ValueError as caught:error=str(caught)
  assert error==('read failed'if fail_read else'write failed'if fail_write else None)
  expected=['export-cap','read','drop-borrowed-cap']+([]if fail_read else['write'])+['close']
  assert client.calls==expected,(name,client.calls)
  checks.append(dict(case=name,calls=client.calls,result='pass'))
 print(json.dumps(dict(schema=1,result='pass',checks=checks,scope='Host CLI mocked public-object capability lifecycle only; no native actor, private key, storage or wire claim.'),indent=2))

if __name__=='__main__':main()
