"""LT-Transport-v2 opaque socket adapter. No content, credentials or policies.

The guest explicitly requests numeric TCP/UNIX connect or numeric TCP listen.
Each of four channels has its own socket, epoch, bounded buffers and failures.
All cryptography and relationship authorization remain inside the Lean broker.
"""
import errno,ipaddress,select,socket,struct,threading,time
MAGIC=b'LTM2';HEADER=struct.Struct('<4sBBHII');LIMIT=65536;CHANNELS=4

class MultiplexStream:
 def __init__(self):
  self.guest,self.local=socket.socketpair();self.local.setblocking(False)
  self.closed=threading.Event();self.error=None
  self.thread=threading.Thread(target=self.run,daemon=True)
 def start(self):self.thread.start()
 def close(self):
  self.closed.set();self.thread.join(timeout=2);self.local.close();self.guest.close()
 def run(self):
  channels=[dict(sock=None,listener=None,pending=bytearray(),epoch=0,connecting=False,endpoint=None,deadline=0,rxcredit=0,flow=False) for _ in range(CHANNELS)]
  incoming=bytearray();outgoing=bytearray()
  def event(op,slot,value=0,data=b''):
   ch=channels[slot];outgoing.extend(HEADER.pack(MAGIC,op,slot,len(data),ch['epoch'],value)+data)
  def disconnect(slot,reason=0,remove=False):
   ch=channels[slot]
   if ch['sock']:ch['sock'].close()
   ch['sock']=None;ch['pending'].clear();ch['connecting']=False
   # Epoch changes immediately on loss. Queued data from the previous epoch
   # can never be interpreted as the start of a replacement TCP connection.
   ch['epoch']+=1;event(5,slot,reason)
   if remove and ch['listener']:
    old=ch['listener'];ch['listener']=None
    if not any(other['listener'] is old for other in channels):old.close()
  def endpoint(raw,listen):
   text=raw.decode('ascii')
   if ':' in text:
    host,port=text.rsplit(':',1);address=ipaddress.ip_address(host);port=int(port)
    if address.version!=4 or not 1<=port<=65535:raise ValueError('numeric IPv4 endpoint and port required')
    return socket.AF_INET,(host,port)
   if listen or not text.startswith('/') or len(text)>96:raise ValueError('explicit numeric listener or absolute UNIX socket required')
   return socket.AF_UNIX,text
  try:
   while not self.closed.is_set():
    reads=([self.local] if len(incoming)<LIMIT and len(outgoing)<LIMIT else [])
    writes=[self.local] if outgoing else []
    for ch in channels:
     if ch['listener'] and ch['sock'] is None and len(outgoing)<LIMIT and ch['listener'] not in reads:reads.append(ch['listener'])
     if ch['sock']:
      if ch['connecting'] and time.monotonic()>=ch['deadline']:
       disconnect(channels.index(ch),errno.ETIMEDOUT);continue
      if not ch['connecting'] and len(outgoing)<LIMIT-1024 and (not ch['flow'] or ch['rxcredit']):reads.append(ch['sock'])
      if ch['pending'] or ch['connecting']:writes.append(ch['sock'])
    ready,writable,_=select.select(reads,writes,[],.05)
    if self.local in ready:
     data=self.local.recv(min(16384,LIMIT-len(incoming)))
     if not data:break
     incoming.extend(data)
    if self.local in writable:
     try:sent=self.local.send(outgoing);del outgoing[:sent]
     except BlockingIOError:pass
    # Consume at most sixteen device commands per readiness turn.
    for _ in range(16):
     if len(incoming)<HEADER.size:break
     magic,op,slot,n,epoch,value=HEADER.unpack_from(incoming)
     if magic!=MAGIC or slot>=CHANNELS or n>1008:raise ValueError('invalid LT-Transport-v2 command')
     if len(incoming)<HEADER.size+n:break
     ch=channels[slot]
     data=bytes(incoming[HEADER.size:HEADER.size+n]);del incoming[:HEADER.size+n]
     if op in (1,2):
      if ch['sock'] or ch['listener']:disconnect(slot,remove=True)
      try:
       family,address=endpoint(data,op==2);ch['endpoint']=address
       if value not in (0,1008):raise ValueError('unsupported receive window')
       ch['flow']=value==1008;ch['rxcredit']=value
       shared=next((other['listener'] for other in channels if other is not ch and other['listener'] and other['endpoint']==address),None) if op==2 else None
       remote=shared or socket.socket(family,socket.SOCK_STREAM);remote.setblocking(False)
       if op==2:
        if shared is None:remote.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);remote.bind(address);remote.listen(CHANNELS)
        ch['listener']=remote;event(9,slot)
       else:
        result=remote.connect_ex(address)
        if result not in (0,errno.EINPROGRESS,errno.EWOULDBLOCK):remote.close();raise OSError(result,'connect failed')
        ch['sock']=remote;ch['connecting']=bool(result);ch['deadline']=time.monotonic()+5
        if result==0:ch['epoch']+=1;event(4,slot,LIMIT)
      except (OSError,ValueError,UnicodeError) as error:
       if 'remote' in locals() and remote is not ch['sock'] and not any(other['listener'] is remote for other in channels):remote.close()
       event(6,slot,getattr(error,'errno',None) or errno.EINVAL)
     elif op==3:disconnect(slot,remove=True)
     elif op==7:
      if ch['sock'] and not ch['connecting'] and epoch==ch['epoch']:
       if len(ch['pending'])+n>LIMIT:disconnect(slot,errno.ENOBUFS)
       else:ch['pending'].extend(data)
      else:event(6,slot,errno.ENOTCONN)
     elif op==10:
      if ch['flow'] and epoch==ch['epoch'] and n==0 and value<=1008 and ch['rxcredit']<=1008-value:ch['rxcredit']+=value
      elif epoch==ch['epoch']:disconnect(slot,errno.EPROTO)
     else:event(6,slot,errno.ENOSYS)
    for slot,ch in enumerate(channels):
     listener=ch['listener'];remote=ch['sock']
     if listener in ready and ch['sock'] is None:
      try:
       remote,_=listener.accept();remote.setblocking(False);ch['sock']=remote;ch['rxcredit']=1008 if ch['flow'] else 0;ch['epoch']+=1;event(8,slot,LIMIT)
      except BlockingIOError:pass
     if remote is None:continue
     try:
      if remote in writable:
       if ch['connecting']:
        result=remote.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)
        if result:raise OSError(result,'connect failed')
        ch['connecting']=False;ch['epoch']+=1;event(4,slot,LIMIT)
       elif ch['pending']:
        sent=remote.send(ch['pending']);del ch['pending'][:sent]
        if ch['flow'] and sent:event(10,slot,sent)
      if remote in ready:
       data=remote.recv(min(1008,ch['rxcredit']) if ch['flow'] else 1008)
       if not data:disconnect(slot)
       else:
        if ch['flow']:ch['rxcredit']-=len(data)
        event(7,slot,data=data)
     except BlockingIOError:pass
     except OSError as error:disconnect(slot,error.errno or errno.EIO)
  except BaseException as error:
   if not self.closed.is_set():self.error=str(error)
  finally:
   try:self.local.shutdown(socket.SHUT_RDWR)
   except OSError:pass
   for ch in channels:
    if ch['sock']:ch['sock'].close()
    if ch['listener']:ch['listener'].close()
