"""Temporary public HTTPS access through Cloudflare, with hidden child windows."""
from pathlib import Path
import hashlib,json,os,re,subprocess,sys,time,urllib.request,zipfile,shutil
import httpx

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
def hidden(command,log,environment=None):
    with log.open('ab') as output:return subprocess.Popen(command,cwd=ROOT,env=environment,stdin=subprocess.DEVNULL,stdout=output,stderr=output,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)

def package(origin):
    # The generic HTTPS package has no custom certificate requirement.
    output=ROOT/'ExtSecure Chrome Extension.zip'
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:
        for file in sorted((ROOT/'extension').rglob('*')):
            relative=file.relative_to(ROOT/'extension')
            if not file.is_file() or any(p in {'tests','node_modules','_metadata','__pycache__'} or p.startswith('.') for p in relative.parts):continue
            data=file.read_bytes()
            if relative.as_posix()=='core.js':data=re.sub(r"export const API_ORIGIN = '[^']+';",f"export const API_ORIGIN = '{origin}';",data.decode()).encode()
            elif relative.as_posix()=='manifest.json':
                value=json.loads(data);value['content_security_policy']['extension_pages']=re.sub(r'connect-src [^;]+;',f'connect-src {origin};',value['content_security_policy']['extension_pages']);data=json.dumps(value,indent=2).encode()
            elif relative.as_posix()=='rules/navigation.json':
                value=json.loads(data);value=[r for r in value if r['id']!=3];value.append({'id':3,'priority':200,'action':{'type':'allow'},'condition':{'regexFilter':'^'+re.escape(origin)+'/','resourceTypes':['main_frame'],'isUrlFilterCaseSensitive':True}});data=json.dumps(value).encode()
            elif relative.as_posix()=='workspace-kit.js':data=data.replace(b'http://127.0.0.1:8765',origin.encode())
            archive.writestr(relative.as_posix(),data)
        archive.writestr('INSTALL ON ANOTHER DEVICE.txt',f'''ExtSecure temporary public API
API: {origin}
Extract the ZIP. Open chrome://extensions, enable Developer mode, click Load unpacked and choose this extracted folder. Register/sign in using your own account, complete its approval and authenticator verification, then Add this device and complete device approval. Click Connect Chrome extensions to include installed extensions. No custom certificate installation is needed.
The host laptop must stay on with its API and tunnel running. This URL is temporary and changes when the tunnel is recreated; obtain a rebuilt ZIP after a change. This is a testing endpoint until Basel supplies the permanent API. Only approved accounts/devices can use protected features.
''')
    return output

def start():
    directory=ROOT/'.private/public-api';directory.mkdir(parents=True,exist_ok=True);state=directory/'state.json'
    if state.exists():
        value=json.loads(state.read_text())
        try:
            with httpx.Client(timeout=8,trust_env=False) as client:
                if client.get(value['origin']+'/health').json().get('service')=='TestAPI':package(value['origin']);return value['origin']
        except (httpx.HTTPError,ValueError):pass
        raise RuntimeError('The previous tunnel is offline. Stop its recorded processes before creating a replacement URL.')
    binary=directory/'cloudflared.exe'
    if not binary.exists():
        request=urllib.request.Request('https://api.github.com/repos/cloudflare/cloudflared/releases/latest',headers={'User-Agent':'ExtSecure-deployment'})
        with urllib.request.urlopen(request,timeout=30) as response:release=json.load(response)
        asset=next(a for a in release['assets'] if a['name']=='cloudflared-windows-amd64.exe')
        with urllib.request.urlopen(asset['browser_download_url'],timeout=60) as response:data=response.read()
        digest=asset.get('digest')
        if not digest or not digest.startswith('sha256:') or hashlib.sha256(data).hexdigest()!=digest.split(':',1)[1]:raise RuntimeError('Cloudflared download did not match the official release digest.')
        binary.write_bytes(data);(directory/'download.json').write_text(json.dumps({'release':release['tag_name'],'sha256':digest}))
    environment=dict(os.environ);environment['EXTSECURE_PUBLIC_GATEWAY']='1'
    gateway=hidden([sys.executable,'-m','uvicorn','scripts.lan_gateway:app','--host','127.0.0.1','--port','8768','--no-proxy-headers','--no-access-log'],directory/'gateway.log',environment)
    time.sleep(1)
    if gateway.poll() is not None:raise RuntimeError('Public gateway failed to start.')
    tunnel_log=directory/'tunnel.log'
    log_offset=tunnel_log.stat().st_size if tunnel_log.exists() else 0
    tunnel=hidden([str(binary),'tunnel','--no-autoupdate','--protocol','http2','--url','http://127.0.0.1:8768'],tunnel_log)
    origin=None
    for _ in range(90):
        with tunnel_log.open('rb') as log:
            log.seek(log_offset);content=log.read().decode(errors='replace')
        match=re.search(r'https://[a-z0-9-]+\.trycloudflare\.com',content)
        if match:origin=match.group();break
        if tunnel.poll() is not None:break
        time.sleep(.5)
    if not origin:
        tunnel.terminate();gateway.terminate();raise RuntimeError('No temporary public URL was issued. Inspect the private tunnel log.')
    state.write_text(json.dumps({'origin':origin,'gateway_pid':gateway.pid,'tunnel_pid':tunnel.pid,'enabled':True}))
    with httpx.Client(timeout=10,trust_env=False) as client:
        for _ in range(30):
            try:
                response=client.get(origin+'/health')
                if response.status_code==200 and response.json().get('service')=='TestAPI':break
            except (httpx.HTTPError,ValueError):pass
            time.sleep(1)
        else:raise RuntimeError('Public HTTPS did not become reachable. Inspect the private tunnel log.')
        assert client.get(origin+'/monitor/api/devices').status_code==401
        assert client.get(origin+'/docs').status_code==404
    package(origin);return origin

if __name__=='__main__':print(start())
