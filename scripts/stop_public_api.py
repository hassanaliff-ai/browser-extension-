"""Stop only ExtSecure's recorded temporary tunnel and loopback gateway."""
from pathlib import Path
import json,os,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[1]
def stop():
    state=ROOT/'.private/public-api/state.json'
    if not state.exists():return
    value=json.loads(state.read_text())
    for key,marker in [('tunnel_pid','cloudflared'),('gateway_pid','scripts.lan_gateway:app')]:
        pid=int(value[key])
        endpoint='--url http://127.0.0.1:8768' if key=='tunnel_pid' else '--port 8768'
        script=f'''$p=Get-CimInstance Win32_Process -Filter "ProcessId={pid}"; if($p -and $p.CommandLine -like '*{marker}*' -and $p.CommandLine -like '*{endpoint}*') {{ Stop-Process -Id {pid} -ErrorAction Stop }}'''
        subprocess.run(['powershell.exe','-NoProfile','-Command',script],check=True,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    archive=state.parent/('stopped-'+str(int(time.time()))+'.json');state.replace(archive)
if __name__=='__main__':stop();print('Temporary public API stopped. The local API and database remain running.')
