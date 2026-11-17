"""Exercise actual local SDK ingestion with owned files, without building anything."""
import errno,hashlib,json,os,sys,tempfile,time
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import sdk

# Exact read_project body at 9329bcb; kept to expose the original late read
# safely. Its read_bytes call is observed and stopped before allocating bytes.
OLD_LOADER='''def read_project(directory):
 directory=Path(directory).resolve();files={}
 sdk.require(directory.is_dir(),'project directory does not exist')
 for path in sorted(directory.rglob('*')):
  if any(x.startswith('.') or x=='build' for x in path.relative_to(directory).parts):continue
  sdk.require(not path.is_symlink(),'project symlinks are not a source closure')
  if path.is_file():files[sdk.relative(path.relative_to(directory).as_posix())]=path.read_bytes()
 sdk.records(files)
 return files
'''
scope={'Path':Path,'sdk':sdk.sdk};exec(OLD_LOADER,scope);old_loader=scope['read_project']

def sparse(path,size):
 with path.open('wb')as stream:stream.truncate(size)

@contextmanager
def observed_reads(before=None):
 original=os.read;calls=[]
 def read(fd,size):
  info=os.fstat(fd)
  assert 0<size<=65536,'unbounded or oversized read request'
  calls.append({'inode':(info.st_dev,info.st_ino),'requested':size})
  if before:before(fd,size)
  data=original(fd,size);calls[-1]['returned']=len(data);return data
 with patch.object(sdk.os,'read',read):yield calls

@contextmanager
def observed_opens(before=None):
 original=os.open;opened=[]
 def open_file(path,flags,*args,**kwargs):
  if before:before(path,flags,kwargs)
  fd=original(path,flags,*args,**kwargs);opened.append(fd);return fd
 try:
  with patch.object(sdk.os,'open',open_file):yield opened
 finally:
  for fd in set(opened):
   try:os.fstat(fd)
   except OSError as error:assert error.errno==errno.EBADF
   else:raise AssertionError('loader descriptor leaked')

def main():
 started=time.monotonic();checks=[]
 def passed(label,**detail):checks.append(dict(check=label,result='pass',**detail))
 def refused(label,operation,*,reads=None,zero_reads=False):
  try:operation()
  except (ValueError,OSError)as error:
   if zero_reads:assert reads==[]
   passed(label,diagnostic=str(error));return
  raise AssertionError('accepted '+label)
 with tempfile.TemporaryDirectory(prefix='lt-sdk-ingestion-')as owned:
  home=Path(owned);outside=home/'outside';outside.mkdir();outside_file=outside/'owned-marker';outside_file.write_bytes(b'owned outside marker')
  outside_info=outside_file.stat();outside_inode=(outside_info.st_dev,outside_info.st_ino)
  def project(label):p=home/label;p.mkdir();return p
  def load(p,before=None):
   with observed_opens(),observed_reads(before)as reads:result=sdk.read_project(p)
   assert all(c['inode']!=outside_inode for c in reads)
   return result,reads
  p=project('lean-exact');(p/'Main.lean').write_bytes(b' '*sdk.sdk.MAX_SOURCE)
  files,reads=load(p);assert files=={'Main.lean':b' '*sdk.sdk.MAX_SOURCE};passed('exact 128KiB Lean member accepted',read_bytes=sum(c['returned']for c in reads))
  p=project('lean-over');sparse(p/'Main.lean',sdk.sdk.MAX_SOURCE+1)
  with observed_opens(),observed_reads()as reads:refused('128KiB+1 Lean refused before read',lambda:sdk.read_project(p),reads=reads,zero_reads=True)
  p=project('resource-exact');sparse(p/'asset.bin',sdk.sdk.MAX_BYTES)
  files,reads=load(p);assert len(files['asset.bin'])==sdk.sdk.MAX_BYTES and not any(files['asset.bin']);passed('exact 4MiB non-Lean member accepted',read_bytes=sum(c['returned']for c in reads))
  p=project('resource-over');sparse(p/'asset.bin',sdk.sdk.MAX_BYTES+1)
  with observed_opens(),observed_reads()as reads:refused('4MiB+1 non-Lean refused before read',lambda:sdk.read_project(p),reads=reads,zero_reads=True)
  for extra in (0,1):
   p=project('aggregate-'+str(extra));sparse(p/'one.bin',sdk.sdk.MAX_BYTES//2);sparse(p/'two.bin',sdk.sdk.MAX_BYTES//2+extra)
   with observed_opens(),observed_reads()as reads:
    if extra:
     refused('cumulative 4MiB+1 refused before second member read',lambda:sdk.read_project(p))
     assert len({c['inode']for c in reads})==1
    else:
     files=sdk.read_project(p);assert sum(map(len,files.values()))==sdk.sdk.MAX_BYTES;passed('cumulative exact 4MiB accepted')
  for count in (128,129):
   p=project('count-'+str(count))
   for i in range(count):(p/('member%03d.bin'%i)).touch()
   with observed_opens(),observed_reads()as reads:
    if count==129:
     refused('129 selected files refused before reading member129',lambda:sdk.read_project(p));assert len(reads)==128
    else:assert len(sdk.read_project(p))==128;passed('128 selected files accepted')
  p=project('preserved');(p/'App').mkdir();(p/'assets').mkdir()
  expected={'Main.lean':b'-- valid UTF-8: \xe2\x9c\x93\n','App/Other.lean':b'def other := 1\n','assets/categories.v1.json':b'{}\x00','lemma.project.json':b'{}','lemma.lock.json':b'{}'}
  for name,data in expected.items():(p/name).write_bytes(data)
  (p/'.hidden').mkdir();(p/'build').mkdir();(p/'App/build').mkdir()
  for name in ('.ignored','build/ignored','.hidden/ignored','App/build/ignored'):sparse(p/name,16*sdk.sdk.MAX_BYTES)
  (p/'.hidden/link').symlink_to(outside,target_is_directory=True)
  assert old_loader(p)==expected
  scanned=[];scan=os.scandir
  def observe_scan(fd):scanned.append((os.fstat(fd).st_dev,os.fstat(fd).st_ino));return scan(fd)
  with patch.object(sdk.os,'scandir',observe_scan):files,_=load(p)
  assert files==expected and list(files)==sorted(expected)
  assert all((d.stat().st_dev,d.stat().st_ino)not in scanned for d in (p/'.hidden',p/'build',p/'App/build'))
  passed('valid path bytes and sorted result unchanged; hidden/build directories pruned',members=len(files))
  for name,data,label in [('App.Other.lean',b'','noncanonical module'),('Lean.lean',b'','reserved namespace'),('Main.lean',b'\xff','invalid UTF-8')]:
   p=project(label.replace(' ','-'));(p/name).write_bytes(data)
   refused(label+' validation preserved',lambda p=p:sdk.read_project(p))
  for directory in (False,True):
   p=project('symlink-'+str(directory));(p/'selected').symlink_to(outside if directory else outside_file,target_is_directory=directory)
   with observed_opens(),observed_reads()as reads:refused('selected symlink '+('directory'if directory else'file')+' refused',lambda:sdk.read_project(p),reads=reads,zero_reads=True)
  for directory in (False,True):
   p=project('replace-before-open-'+str(directory));target=p/('Sub'if directory else'item.bin')
   if directory:target.mkdir();(target/'item.bin').write_bytes(b'original')
   else:target.write_bytes(b'original')
   replaced=[]
   def replace(path,flags,kwargs):
    if path==target.name and kwargs.get('dir_fd')is not None and not replaced:
     replaced.append(True);target.rename(p/'.held');target.symlink_to(outside if directory else outside_file,target_is_directory=directory)
   with observed_opens(replace),observed_reads()as reads:
    refused('replacement symlink '+('parent'if directory else'file')+' refused before outside read',lambda:sdk.read_project(p),reads=reads,zero_reads=True)
   assert replaced
  p=project('regular-identity-change');target=p/'item.bin';target.write_bytes(b'original');replacement=p/'.replacement';replacement.write_bytes(b'replaced');changed=[]
  def replace_regular(path,flags,kwargs):
   if path=='item.bin'and kwargs.get('dir_fd')is not None and not changed:changed.append(True);os.replace(replacement,target)
  with observed_opens(replace_regular),observed_reads()as reads:refused('regular-file identity replacement refused before read',lambda:sdk.read_project(p),reads=reads,zero_reads=True)
  p=project('root-replacement');(p/'item.bin').write_bytes(b'original');changed=[]
  def replace_root(path,flags,kwargs):
   if path==p.name and kwargs.get('dir_fd')is not None and not changed:changed.append(True);p.rename(home/'.held-root');p.symlink_to(outside,target_is_directory=True)
  with observed_opens(replace_root),observed_reads()as reads:refused('resolved project parent replacement symlink refused before read',lambda:sdk.read_project(p),reads=reads,zero_reads=True)
  assert changed
  for mutation,size in [('growth',8),('growth-lean-limit',sdk.sdk.MAX_SOURCE),('growth-total-limit',sdk.sdk.MAX_BYTES),('truncation',8),('same-size-write',8),('pathname-symlink',8)]:
   p=project(mutation);target=p/('Main.lean'if mutation=='growth-lean-limit'else'item.bin');sparse(target,size);initial=target.stat();inode=(initial.st_dev,initial.st_ino);changed=[]
   def mutate(fd,size):
    if (os.fstat(fd).st_dev,os.fstat(fd).st_ino)==inode and not changed:
     changed.append(True)
     if mutation.startswith('growth'):
      with target.open('ab')as stream:stream.write(b'!')
     elif mutation=='truncation':os.truncate(target,3)
     elif mutation=='same-size-write':target.write_bytes(b'modified');os.utime(target,ns=(initial.st_atime_ns,initial.st_mtime_ns+1))
     else:target.rename(p/'.held');target.symlink_to(outside_file)
   with observed_opens(),observed_reads(mutate)as reads:
    refused(mutation+' during actual descriptor read refused',lambda:sdk.read_project(p))
   assert changed and all(c['inode']==inode for c in reads)
   assert sum(c['returned']for c in reads)<=initial.st_size+1
   if mutation.startswith('growth'):assert sum(c['returned']for c in reads)==initial.st_size+1
  p=project('directory-after-open');target=p/'Sub';target.mkdir();(target/'item.bin').write_bytes(b'original');directory_inode=target.stat().st_ino;changed=[];scan=os.scandir
  def replace_opened(fd):
   if os.fstat(fd).st_ino==directory_inode and not changed:changed.append(True);target.rename(p/'.held');target.symlink_to(outside,target_is_directory=True)
   return scan(fd)
  with observed_opens(),observed_reads()as reads,patch.object(sdk.os,'scandir',replace_opened):refused('opened parent replacement detected without following outside link',lambda:sdk.read_project(p))
  assert changed and all(c['inode']!=outside_inode for c in reads)
  p=project('old-counterexample');target=p/'oversized.bin';sparse(target,16*sdk.sdk.MAX_BYTES);attempted=[]
  class StoppedBeforeAllocation(Exception):pass
  def stop_read(path):assert path==target;attempted.append(str(path.relative_to(home)));raise StoppedBeforeAllocation()
  with patch.object(Path,'read_bytes',stop_read):
   try:old_loader(p)
   except StoppedBeforeAllocation:pass
   else:raise AssertionError('old late-read counterexample did not reach read_bytes')
  assert attempted
  with observed_opens(),observed_reads()as reads:refused('same sparse64MiB counterexample rejected by actual new loader before read',lambda:sdk.read_project(p),reads=reads,zero_reads=True)
  passed('old loader requests unrestricted read_bytes before records validation; stopped before allocation',old_loader_sha256=hashlib.sha256(OLD_LOADER.encode()).hexdigest(),declared_bytes=target.stat().st_size,unbounded_read_bytes_executed=False)
 report=dict(schema=1,result='pass',scope=__doc__,checks=checks,seconds=time.monotonic()-started,temporary_directory_removed=not home.exists(),compiler_or_runtime_invoked=False,limitations=['Actual owned-file loader checks, with thin syscall observers/interleaving hooks; no coherent adversarial filesystem snapshot proof.','No unlimited tree CPU/depth bound or native IDE/release/MVP acceptance.'])
 print(json.dumps(report,indent=2))

if __name__=='__main__':main()
