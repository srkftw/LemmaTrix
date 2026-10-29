"""Focused real-UART framing checks; transport does not implement guest policy."""
import struct,time
import live

def frame(client,rid):
 deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  where=client.buffer.find(live.REPLY)
  if where>=0:
   if where:del client.buffer[:where]
   if len(client.buffer)>=32:
    _,status,answer,length,reserved=struct.unpack_from('<4sIQQQ',client.buffer)
    assert length<=1024 and reserved==0,'invalid guest response framing'
    if len(client.buffer)>=32+length:
     raw=bytes(client.buffer[32:32+length]);del client.buffer[:32+length]
     if answer==rid:return status,raw
     continue
  data=client.stream.recv(65536)
  if not data:raise AssertionError('framing error killed management')
  client.buffer.extend(data)
 raise AssertionError('framing response deadline exceeded')

def check(client):
 checks=[]
 client.stream.sendall(b'untrusted-noise\x1b[2J\nLTTL2x')
 assert struct.unpack_from('<Q',client.request(1),8)[0]==2
 checks.append('noise/escape bytes resynchronize; no console execution')
 rid=max(client.counter+1,time.time_ns());client.counter=rid
 first=client.request(1,rid=rid)
 assert client.request(1,rid=rid)==first
 try:client.request(2,rid=rid)
 except ValueError as error:assert 'status4' in str(error)
 else:raise AssertionError('conflicting duplicate accepted')
 checks.append('exact last request replay; conflicting duplicate denied')
 for length,reserved in [(1025,0),(0,1)]:
  rid+=1
  client.stream.sendall(struct.pack('<4sIQQQ',live.MAGIC,length,rid,1,reserved))
  status,raw=frame(client,rid)
  assert status==2 and raw==b'','invalid header accepted'
 checks.append('oversize length and unknown critical flags rejected')
 rid+=1
 client.stream.sendall(struct.pack('<4sIQQQ',live.MAGIC,64,rid,100,0)+b'abc')
 status,raw=frame(client,rid)
 assert status==2 and raw==b'','partial payload did not time out safely'
 checks.append('truncated payload times out and parser recovers')
 client.counter=rid
 assert struct.unpack_from('<Q',client.request(1),8)[0]==2
 return checks
