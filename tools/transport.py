"""LT-Transport-v3 opaque socket adapter. No content, credentials or policies.

The guest explicitly requests numeric TCP/UNIX connect or numeric TCP listen.
Each of sixteen channels has its own socket, epoch, bounded buffers and failures.
All cryptography and relationship authorization remain inside the Lean broker.

The optional0600 UNIX fault-control socket accepts one JSON line (<=512 bytes)
per connection: {"op":"status"}, {"op":"status","slot":0}, or
{"op":"pause"|"resume","slot":0,"epoch":1}. Responses use version1.
Pause/resume require the exact connected epoch. Counters describe actual bytes
sent/received in that epoch; a new epoch clears counters, pause and queued bytes.
At most four control clients are resident, each with a two-second deadline.
"""
import errno,ipaddress,json,os,select,socket,struct,threading,time
from pathlib import Path
MAGIC=b'LTM3';HEADER=struct.Struct('<4sBBHII');LIMIT=65536;CHANNELS=16

class MultiplexStream:
 def __init__(self,fault_control=None):
  # This opt-in local fault adapter never interprets transported bytes. Its
  # acknowledgement is a barrier in the same loop that writes remote sockets.
  self.control=None;self.control_path=None;self.control_inode=None
  if fault_control is not None:
   path=Path(fault_control)
   if os.path.lexists(path):raise ValueError('network fault-control path exists; refusing to replace it')
   control=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);bound_inode=None
   try:
    control.bind(str(path));bound_inode=path.stat().st_ino
    os.chmod(path,0o600);control.listen(4);control.setblocking(False)
   except BaseException:
    control.close()
    if bound_inode is not None:
     try:
      if path.lstat().st_ino==bound_inode:path.unlink()
     except FileNotFoundError:pass
    raise
   self.control=control;self.control_path=path;self.control_inode=bound_inode
  self.guest,self.local=socket.socketpair();self.local.setblocking(False)
  self.closed=threading.Event();self.error=None
  self.thread=threading.Thread(target=self.run,daemon=True)
 def start(self):self.thread.start()
 def close(self):
  self.closed.set()
  if self.thread.ident is not None:self.thread.join(timeout=2)
  self.local.close();self.guest.close()
  if self.control:self.control.close()
  if self.control_path:
   try:
    if self.control_path.lstat().st_ino==self.control_inode:self.control_path.unlink()
   except FileNotFoundError:pass
 def run(self):
  channels=[dict(sock=None,listener=None,pending=bytearray(),epoch=0,connecting=False,endpoint=None,deadline=0,rxcredit=0,flow=False,txpaused=False,txbytes=0,rxbytes=0) for _ in range(CHANNELS)]
  incoming=bytearray();outgoing=bytearray()
  controls={}
  def new_epoch(ch):
   ch['epoch']+=1;ch['txpaused']=False;ch['txbytes']=0;ch['rxbytes']=0
  def public_channel(slot):
   ch=channels[slot]
   return dict(slot=slot,epoch=ch['epoch'],connected=ch['sock'] is not None and not ch['connecting'],connecting=ch['connecting'],tx_paused=ch['txpaused'],pending_bytes=len(ch['pending']),tx_bytes=ch['txbytes'],rx_bytes=ch['rxbytes'])
  def fault_command(raw):
   try:
    command=json.loads(raw)
    if not isinstance(command,dict) or set(command)-{'op','slot','epoch'}:raise ValueError('invalid control fields')
    op=command.get('op');slot=command.get('slot')
    if op=='status' and slot is None:
     if 'epoch' in command:raise ValueError('status does not select an epoch')
     return dict(version=1,ok=True,channels=[public_channel(i) for i in range(CHANNELS)])
    if type(slot) is not int or not 0<=slot<CHANNELS:raise ValueError('slot must be within0..15')
    ch=channels[slot]
    if op=='status':
     if 'epoch' in command:raise ValueError('status does not select an epoch')
    elif op in ('pause','resume'):
     if type(command.get('epoch')) is not int or command['epoch']!=ch['epoch']:raise ValueError('stale or missing channel epoch')
     if ch['sock'] is None or ch['connecting']:raise ValueError('channel is not connected')
     ch['txpaused']=op=='pause'
    else:raise ValueError('unsupported fault-control operation')
    return dict(version=1,ok=True,channel=public_channel(slot))
   except (ValueError,TypeError,UnicodeError) as error:return dict(version=1,ok=False,error=str(error))
  def event(op,slot,value=0,data=b''):
   ch=channels[slot];outgoing.extend(HEADER.pack(MAGIC,op,slot,len(data),ch['epoch'],value)+data)
  def disconnect(slot,reason=0,remove=False):
   ch=channels[slot]
   if ch['sock']:ch['sock'].close()
   ch['sock']=None;ch['pending'].clear();ch['connecting']=False
   # Epoch changes immediately on loss. Queued data from the previous epoch
   # can never be interpreted as the start of a replacement TCP connection.
   new_epoch(ch);event(5,slot,reason)
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
    if self.control and len(controls)<4:reads.append(self.control)
    for conn,state in controls.items():
     if state['output'] is None:reads.append(conn)
     else:writes.append(conn)
    for ch in channels:
     if ch['listener'] and ch['sock'] is None and len(outgoing)<LIMIT and ch['listener'] not in reads:reads.append(ch['listener'])
     if ch['sock']:
      if ch['connecting'] and time.monotonic()>=ch['deadline']:
       disconnect(channels.index(ch),errno.ETIMEDOUT);continue
      if not ch['connecting'] and len(outgoing)<LIMIT-1024 and (not ch['flow'] or ch['rxcredit']):reads.append(ch['sock'])
      if (ch['pending'] and not ch['txpaused']) or ch['connecting']:writes.append(ch['sock'])
    ready,writable,_=select.select(reads,writes,[],.05)
    # Process fault commands before any remote writes from this readiness turn.
    # A successful pause response therefore certifies that later sends on this
    # exact epoch wait for a matching resume, including sockets already writable.
    if self.control in ready:
     try:
      conn,_=self.control.accept();conn.setblocking(False)
      controls[conn]=dict(input=bytearray(),output=None,deadline=time.monotonic()+2)
     except BlockingIOError:pass
    for conn,state in list(controls.items()):
     try:
      if time.monotonic()>=state['deadline']:raise TimeoutError('fault-control command deadline')
      if conn in ready:
       data=conn.recv(513-len(state['input']))
       if not data:raise EOFError('fault-control client closed')
       state['input'].extend(data)
       if b'\n' in state['input']:
        line,extra=bytes(state['input']).split(b'\n',1)
        response=fault_command(line) if not extra and len(line)<=512 else dict(version=1,ok=False,error='one command of at most512 bytes required')
        state['output']=bytearray(json.dumps(response,separators=(',',':')).encode()+b'\n')
       elif len(state['input'])>512:state['output']=bytearray(b'{"version":1,"ok":false,"error":"control command too large"}\n')
      if conn in writable and state['output'] is not None:
       sent=conn.send(state['output']);del state['output'][:sent]
       if not state['output']:raise EOFError('fault-control reply complete')
     except BlockingIOError:pass
     except (OSError,EOFError,TimeoutError):conn.close();del controls[conn]
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
     if magic!=MAGIC or slot>=CHANNELS or n>1008:raise ValueError('invalid LT-Transport-v3 command')
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
        if result==0:new_epoch(ch);event(4,slot,LIMIT)
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
       remote,_=listener.accept();remote.setblocking(False);ch['sock']=remote;ch['rxcredit']=1008 if ch['flow'] else 0;new_epoch(ch);event(8,slot,LIMIT)
      except BlockingIOError:pass
     if remote is None:continue
     try:
      if remote in writable:
       if ch['connecting']:
        result=remote.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)
        if result:raise OSError(result,'connect failed')
        ch['connecting']=False;new_epoch(ch);event(4,slot,LIMIT)
       elif ch['pending'] and not ch['txpaused']:
        sent=remote.send(ch['pending']);del ch['pending'][:sent]
        ch['txbytes']+=sent
        if ch['flow'] and sent:event(10,slot,sent)
      if remote in ready:
       data=remote.recv(min(1008,ch['rxcredit']) if ch['flow'] else 1008)
       if not data:disconnect(slot)
       else:
        ch['rxbytes']+=len(data)
        if ch['flow']:ch['rxcredit']-=len(data)
        event(7,slot,data=data)
     except BlockingIOError:pass
     except OSError as error:disconnect(slot,error.errno or errno.EIO)
  except BaseException as error:
   if not self.closed.is_set():self.error=str(error)
  finally:
   for conn in controls:conn.close()
   try:self.local.shutdown(socket.SHUT_RDWR)
   except OSError:pass
   for ch in channels:
    if ch['sock']:ch['sock'].close()
    if ch['listener']:ch['listener'].close()
