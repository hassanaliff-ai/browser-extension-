"""Restart the configured HTTPS gateway without opening a terminal window."""
from pathlib import Path
import json,os,ssl,subprocess,sys,time
import httpx

def start(root):
    directory=root/'.private/lan';config=directory/'config.json'
    if not config.exists():return None
    value=json.loads(config.read_text());origin=f"https://{value['host']}:{int(value['port'])}"
    context=ssl.create_default_context(cafile=str(directory/'ca.pem'))
    def ready():
        try:
            with httpx.Client(verify=context,trust_env=False,timeout=2) as client:return client.get(origin+'/health').json().get('service')=='TestAPI'
        except (httpx.HTTPError,ValueError):return False
    if ready():return origin
    environment=dict(os.environ);environment['EXTSECURE_LAN_SUBNET']=value['subnet']
    with (directory/'gateway.log').open('ab') as log:
        child=subprocess.Popen([sys.executable,'-m','uvicorn','scripts.lan_gateway:app','--host',value['host'],'--port',str(value['port']),'--ssl-certfile',str(directory/'server.pem'),'--ssl-keyfile',str(directory/'server-key.pem'),'--no-proxy-headers','--no-access-log'],cwd=root,env=environment,stdin=subprocess.DEVNULL,stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    (directory/'gateway.pid').write_text(str(child.pid))
    for _ in range(30):
        if child.poll() is not None:break
        if ready():return origin
        time.sleep(.5)
    raise RuntimeError('LAN HTTPS gateway did not start. Check the host IP and private gateway log.')

if __name__=='__main__':print(start(Path(__file__).resolve().parents[1]) or 'LAN deployment is not configured.')
