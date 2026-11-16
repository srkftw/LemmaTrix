"""Exact SDK transfer regressions using owned files only; no compiler or signing."""
import errno,json,os,shutil,sys,tempfile,time
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import public_sdk as sdk

# The import body at de8da061, with only its CLI argument/print plumbing removed.
def old_import(directory):
 manifest=sdk.validate_manifest(json.loads((directory/'manifest.json').read_bytes()));sdk._read_sdk(directory,manifest);dest=sdk.CACHE/manifest['content_id']
 if dest.exists():sdk._read_sdk(dest,manifest)
 else:dest.parent.mkdir(parents=True,exist_ok=True);shutil.copytree(directory,dest)
 return manifest

def main():
 started=time.monotonic();checks=[];manifest,files=sdk.capture_sdk(ROOT,'sdk/manifest.json');cid=manifest['content_id']
 def passed(label,**detail):checks.append(dict(check=label,result='pass',**detail))
 def refused(label,operation):
  try:operation()
  except (ValueError,KeyError,OSError)as error:passed(label,diagnostic=str(error));return error
  raise AssertionError('accepted '+label)
 def put(directory):
  directory.mkdir()
  for name,data in {**files,'manifest.json':sdk.canonical(manifest)+b'\n'}.items():
   target=directory/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
  return directory
 def tree(directory):
  return {p.relative_to(directory).as_posix():('link',os.readlink(p))if p.is_symlink()else('file',p.read_bytes())for p in directory.rglob('*')if p.is_symlink()or p.is_file()}
 with tempfile.TemporaryDirectory(prefix='lt-sdk-transfer-')as temporary:
  owned=Path(temporary);outside=owned/'outside';outside.mkdir();marker=outside/'owned-marker';marker.write_bytes(b'owned marker only');marker_info=marker.stat();outside_inode=(marker_info.st_dev,marker_info.st_ino)
  source=put(owned/'old-input');(source/'extra.txt').write_bytes(b'undeclared');(source/'extra-dir').symlink_to(outside,target_is_directory=True)
  original_read=sdk._read_sdk
  def late_mutation(directory,selected):
   captured=original_read(directory,selected);(source/'Lemma/UI.lean').write_bytes(b'changed after validation');return captured
  with patch.object(sdk,'CACHE',owned/'old-cache'),patch.object(sdk,'_read_sdk',late_mutation):old_import(source)
  copied=owned/'old-cache'/cid
  assert (copied/'extra-dir/owned-marker').read_bytes()==marker.read_bytes()and(copied/'extra.txt').exists()
  assert(copied/'Lemma/UI.lean').read_bytes()!=files['Lemma/UI.lean']
  passed('old import counterexample copies undeclared file, traverses directory symlink and recopies changed bytes')
  source=put(owned/'input');(source/'extra.txt').write_bytes(b'undeclared');(source/'extra-dir').symlink_to(outside,target_is_directory=True)
  read=os.read;scan=os.scandir;reads=[];source_info=source.stat()
  def observe(fd,size):
   info=os.fstat(fd);assert 0<size<=65536;assert(info.st_dev,info.st_ino)!=outside_inode
   data=read(fd,size);reads.append((size,len(data)));return data
  def no_input_scan(path):
   info=os.fstat(path)if isinstance(path,int)else os.stat(path,follow_symlinks=False)
   assert(info.st_dev,info.st_ino)!=(source_info.st_dev,source_info.st_ino),'transfer enumerated input tree'
   return scan(path)
  cache=owned/'cache'
  with patch.object(sdk,'CACHE',cache),patch.object(sdk.os,'read',observe),patch.object(sdk.os,'scandir',no_input_scan):sdk.import_sdk(source)
  assert sdk.capture_sdk(cache/cid)==(manifest,files)
  assert set(tree(cache/cid))==set(files)|{'manifest.json'}
  passed('import publishes only manifest and 28 captured members without enumerating input or reading outside symlink',read_calls=len(reads),max_read_request=max(x[0]for x in reads))
  # A cache's unpinned extras are ignored by export as well.
  (cache/cid/'cache-extra').write_bytes(b'unpinned');(cache/cid/'cache-link').symlink_to(outside,target_is_directory=True)
  exported=owned/'exported'
  with patch.object(sdk,'CACHE',cache):sdk.export_sdk(exported)
  assert sdk.capture_sdk(exported)==(manifest,files)and set(tree(exported))==set(files)|{'manifest.json'}
  with patch.object(sdk,'CACHE',owned/'roundtrip'):sdk.import_sdk(exported);assert sdk.resolve_sdk({'version':sdk.VERSION,'content_id':cid})==(manifest,files)
  passed('export strips cache extras and valid exact export/import/resolve roundtrip succeeds')
  publish=sdk._publish_sdk
  for direction in ('import','export'):
   selected=put(owned/('mutate-'+direction));destination=owned/('frozen-'+direction);changed=[]
   if direction=='export':
    selected=owned/('export-cache')/cid;selected.parent.mkdir();put(selected)
   def mutate(destination_path,m,captured,allow_existing=False):
    if direction=='import'or Path(destination_path)==destination:
     assert captured==files;changed.append(True);(selected/'Lemma/UI.lean').write_bytes(b'changed after capture');(selected/'manifest.json').write_bytes(b'corrupt after capture')
    return publish(destination_path,m,captured,allow_existing)
   with patch.object(sdk,'CACHE',destination if direction=='import'else selected.parent),patch.object(sdk,'_publish_sdk',mutate):
    if direction=='import':sdk.import_sdk(selected);result=destination/cid
    else:sdk.export_sdk(destination);result=destination
   assert changed and sdk.capture_sdk(result)==(manifest,files)
   passed(direction+' publishes captured bytes despite input mutation after validation')
  for kind in ('missing','corrupt','manifest-json','manifest-hash','manifest-large','member-large','manifest-link','member-link','parent-link','recipe-link','member-fifo','manifest-fifo','root-link'):
   selected=put(owned/('bad-'+kind));member=selected/'Lemma/UI.lean'
   if kind=='missing':member.unlink()
   elif kind=='corrupt':member.write_bytes(b'x'*len(files['Lemma/UI.lean']))
   elif kind=='manifest-json':(selected/'manifest.json').write_bytes(b'{')
   elif kind=='manifest-hash':
    bad=dict(manifest,content_id='00'*32);(selected/'manifest.json').write_bytes(sdk.canonical(bad))
   elif kind in ('manifest-large','member-large'):
    target=selected/'manifest.json'if kind=='manifest-large'else member
    with target.open('wb')as stream:stream.truncate((sdk.SDK_MANIFEST_LIMIT if kind=='manifest-large'else sdk.MAX_SOURCE)+1)
    inode=(target.stat().st_dev,target.stat().st_ino)
   elif kind in ('manifest-link','member-link','recipe-link'):
    target=selected/('manifest.json'if kind=='manifest-link'else'Compiler/Main.lean'if kind=='recipe-link'else'Lemma/UI.lean');target.unlink();target.symlink_to(marker)
   elif kind=='parent-link':shutil.rmtree(selected/'Lemma');(selected/'Lemma').symlink_to(outside,target_is_directory=True)
   elif kind in ('member-fifo','manifest-fifo'):
    target=member if kind=='member-fifo'else selected/'manifest.json';target.unlink();os.mkfifo(target)
   else:
    link=owned/'selected-root-link';link.symlink_to(selected,target_is_directory=True);selected=link
   target_cache=owned/('bad-cache-'+kind)
   def bounded(fd,size):
    info=os.fstat(fd);assert 0<size<=65536;assert(info.st_dev,info.st_ino)!=outside_inode
    if kind.endswith('large'):assert(info.st_dev,info.st_ino)!=inode,'oversize input was read'
    return read(fd,size)
   with patch.object(sdk,'CACHE',target_cache),patch.object(sdk.os,'read',bounded):refused(kind+' input refused before publication',lambda:sdk.import_sdk(selected))
   assert not target_cache.exists()
  for kind in ('valid','manifest-corrupt','manifest-missing','member-corrupt','member-missing','different-valid-manifest','file','symlink'):
   target_cache=owned/('existing-'+kind);target_cache.mkdir();target=target_cache/cid
   if kind=='file':target.write_bytes(b'unknown target')
   elif kind=='symlink':target.symlink_to(outside,target_is_directory=True)
   else:
    put(target);(target/'keep-extra').write_bytes(b'preserve unknown extra')
    if kind=='manifest-corrupt':(target/'manifest.json').write_bytes(b'{}')
    elif kind=='manifest-missing':(target/'manifest.json').unlink()
    elif kind=='member-corrupt':(target/'Lemma/UI.lean').write_bytes(b'corrupt')
    elif kind=='member-missing':(target/'Lemma/UI.lean').unlink()
    elif kind=='different-valid-manifest':
     other=json.loads(sdk.canonical(manifest));other['operations']['Wallet']='changed';other['content_id']=sdk.sha(b'LT-PUBLIC-SDK-1\0'+sdk.canonical({k:v for k,v in other.items()if k!='content_id'}));(target/'manifest.json').write_bytes(sdk.canonical(other))
   before=tree(target_cache)
   with patch.object(sdk,'CACHE',target_cache):
    if kind=='valid':sdk.import_sdk(exported);passed('valid existing cache validates actual manifest and members')
    else:
     refused('existing '+kind+' cache refuses import',lambda:sdk.import_sdk(exported))
     refused('existing '+kind+' cache refuses checkout cache population',sdk.cache_sdk)
     refused('existing '+kind+' cache refuses resolve without repair',lambda:sdk.resolve_sdk({'version':sdk.VERSION,'content_id':cid}))
   assert tree(target_cache)==before
  for kind in ('directory','file','symlink','racing-directory'):
   destination=owned/('destination-'+kind)
   if kind=='directory':destination.mkdir();(destination/'keep').write_bytes(b'keep')
   elif kind=='file':destination.write_bytes(b'keep')
   elif kind=='symlink':destination.symlink_to(outside,target_is_directory=True)
   rename=sdk._rename_sdk
   def race(parent,stage,name):destination.mkdir();(destination/'keep').write_bytes(b'racing target');return rename(parent,stage,name)
   with patch.object(sdk,'_rename_sdk',race if kind=='racing-directory'else rename):refused('preexisting or racing '+kind+' export target preserved',lambda:publish(destination,manifest,files))
   assert destination.is_symlink()if kind=='symlink'else(destination.read_bytes()==b'keep'if kind=='file'else(destination/'keep').read_bytes()in(b'keep',b'racing target'))
  # Replace the owned stage name after its bytes have been validated. The held
  # FD keeps reads on the original stage, and cleanup must preserve replacement.
  original_files=sdk._sdk_files;swapped=[];replacement=[];destination=owned/'stage-replaced'
  def replace_stage(fd,m):
   result=original_files(fd,m)
   if not swapped:
    path=Path(os.readlink('/proc/self/fd/'+str(fd)))
    if path.name.startswith('.lt-sdk-'):
     held=path.with_name(path.name+'-held');path.rename(held);path.mkdir();(path/'keep').write_bytes(b'replacement');swapped.append(held);replacement.append(path)
   return result
  with patch.object(sdk,'_sdk_files',replace_stage):refused('replaced staging basename refuses publication',lambda:publish(destination,manifest,files))
  assert not destination.exists()and(replacement[0]/'keep').read_bytes()==b'replacement'
  passed('stage replacement preserved and never published or recursively removed')
  # A secondary cleanup error must not hide the publication error.
  def fail_rename(*args):raise OSError(errno.EIO,'primary publication failure')
  def fail_cleanup(*args,**kwargs):raise OSError(errno.EACCES,'secondary cleanup failure')
  with patch.object(sdk,'_rename_sdk',fail_rename),patch.object(sdk.shutil,'rmtree',fail_cleanup):
   error=refused('cleanup preserves primary publication exception',lambda:publish(owned/'failed',manifest,files));assert error.errno==errno.EIO
  # If an error occurs after rename, preserve the fully published destination.
  def publish_then_fail(*args):sdk_rename(*args);raise OSError(errno.EIO,'reporting after publication')
  sdk_rename=sdk._rename_sdk;destination=owned/'published-before-error'
  with patch.object(sdk,'_rename_sdk',publish_then_fail):refused('post-publication exception does not roll back target',lambda:publish(destination,manifest,files))
  assert sdk.capture_sdk(destination)==(manifest,files)
 report=dict(schema=1,status='pass',sdk_content_id=cid,members=len(files),member_bytes=sum(map(len,files.values())),checks=checks,seconds=round(time.monotonic()-started,3),real_builds=0)
 print(json.dumps(report,indent=2))
if __name__=='__main__':main()
