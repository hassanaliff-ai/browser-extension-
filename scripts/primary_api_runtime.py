"""Lifecycle control for the verified SecureScope primary API only."""
from pathlib import Path
import json,os,subprocess,sys,time
import httpx
from activate_postgresql import powershell

ROOT=Path(__file__).resolve().parents[1]
PORT=8765
ORIGIN='http://127.0.0.1:8765'
ENTRYPOINT='prototypes.securescope.backend.primary:create_app'
SERVICE_NAME='TestAPI'


def api_process():
    flags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0
    result=subprocess.run(['netstat.exe','-ano','-p','TCP'],capture_output=True,text=True,check=True,creationflags=flags)
    listeners=set()
    for line in result.stdout.splitlines():
        fields=line.split()
        if len(fields)==5 and fields[0]=='TCP' and fields[1].endswith(':'+str(PORT)) and fields[3]=='LISTENING':listeners.add(int(fields[4]))
    if not listeners:return None
    if len(listeners)!=1:raise RuntimeError('Multiple processes listen on the primary API port')
    pid=next(iter(listeners))
    result=powershell('Get-CimInstance Win32_Process -Filter "ProcessId='+str(pid)+'" | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress')
    value=json.loads(result.stdout.strip()) if result.stdout.strip() else None
    command=(value or {}).get('CommandLine') or ''
    if not value or 'uvicorn' not in command or ENTRYPOINT not in command or '--port '+str(PORT) not in command:
        raise RuntimeError('Primary API port belongs to an unverified process; it was not stopped')
    return value


def stop_api(process):
    if process is None:return
    pid=int(process['ProcessId'])
    # Revalidate immediately before stopping, including protection against PID reuse.
    script='$p=Get-CimInstance Win32_Process -Filter "ProcessId='+str(pid)+'"; if($p -and $p.CommandLine -like "*'+ENTRYPOINT+'*" -and $p.CommandLine -like "*--port '+str(PORT)+'*"){Stop-Process -Id '+str(pid)+' -ErrorAction Stop} elseif($p){throw "Primary API identity changed"}'
    powershell(script)


def start_api(values):
    environment=dict(os.environ);environment.update({k:v for k,v in values.items() if v is not None})
    environment.update(PYTHONPATH=str(ROOT/'src'),OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',MKL_NUM_THREADS='1')
    log=ROOT/'.private/primary-api.log';log.parent.mkdir(exist_ok=True)
    flags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0
    with log.open('ab') as output:
        child=subprocess.Popen([sys.executable,'-m','uvicorn',ENTRYPOINT,'--factory','--host','127.0.0.1','--port',str(PORT)],cwd=ROOT,env=environment,stdin=subprocess.DEVNULL,stdout=output,stderr=output,creationflags=flags)
    with httpx.Client(timeout=2,trust_env=False) as client:
        for _ in range(50):
            if child.poll() is not None:break
            try:
                if client.get(ORIGIN+'/health').json().get('service')==SERVICE_NAME:return
            except (httpx.HTTPError,ValueError):pass
            time.sleep(.5)
    raise RuntimeError('Primary API did not become ready; inspect its private log')
