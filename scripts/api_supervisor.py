"""Hidden, single-instance supervision of TestAPI and its temporary public gateway."""
from pathlib import Path
import argparse,ctypes,json,os,sys,time
import httpx
from dotenv import dotenv_values

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'scripts'),str(ROOT/'src')]
STATE=ROOT/'.private/api-supervisor'

def healthy(url):
    try:
        with httpx.Client(timeout=5,trust_env=False) as client:
            response=client.get(url+'/health')
            return response.status_code==200 and response.json().get('service')=='TestAPI'
    except (httpx.HTTPError,ValueError):return False

def enabled():
    try:return json.loads((STATE/'config.json').read_text(encoding='utf-8-sig')).get('enabled') is True
    except (OSError,ValueError):return False

def checkpoint(**values):
    STATE.mkdir(parents=True,exist_ok=True)
    value={'pid':os.getpid(),'checked_at':time.time(),**values}
    temporary=STATE/'status.tmp';temporary.write_text(json.dumps(value,indent=2),encoding='utf-8');temporary.replace(STATE/'status.json')

def recorded_process_alive(pid,marker,endpoint):
    from activate_postgresql import powershell
    # PIDs are never sufficient evidence: validate the exact application and endpoint.
    command='$p=Get-CimInstance Win32_Process -Filter "ProcessId='+str(int(pid))+'"; if($p -and $p.CommandLine -like \'*'+marker+'*\' -and $p.CommandLine -like \'*'+endpoint+'*\'){\'alive\'}'
    return powershell(command).stdout.strip()=='alive'

def public_processes_alive(state):
    return recorded_process_alive(state['gateway_pid'],'scripts.lan_gateway:app','--port 8768') and recorded_process_alive(state['tunnel_pid'],'cloudflared','--url http://127.0.0.1:8768')

def public_tunnel_expired(state):
    """Recover an explicitly rejected tunnel, without rotating on DNS outages."""
    offset=state.get('tunnel_log_offset')
    if not isinstance(offset,int) or isinstance(offset,bool) or offset<0:return False
    log=ROOT/'.private/public-api/tunnel.log'
    try:
        with log.open('rb') as handle:
            handle.seek(0,2);end=handle.tell()
            handle.seek(max(offset,end-16384))
            recent=handle.read(16384)
        return b'Unauthorized: Tunnel not found' in recent
    except OSError:return False

def publish_package(origin):
    from scripts.start_public_api import package
    import shutil
    archive=package(origin)
    # This host's workspace mirror is optional; it contains no runtime credentials.
    configured=dotenv_values(ROOT/'.env').get('EXTSECURE_WORKSPACE_MIRROR')
    mirror=Path(configured) if configured else ROOT.parent/'OneDrive/Documents/ChatGPT/Alba Project'
    for folder in [mirror,mirror/'SecureScope Integrated']:
        if folder.is_dir():shutil.copy2(archive,folder/archive.name)
    (STATE/'package-origin.txt').write_text(origin,encoding='utf-8')

def cycle(failures):
    from activate_postgresql import api_process,stop_api,start_api
    from scripts.start_public_api import start
    from scripts.stop_public_api import stop
    local=healthy('http://127.0.0.1:8765')
    if not local:
        process=api_process()
        failures=failures+1 if process else 3
        if failures>=3:
            stop_api(process);start_api(dotenv_values(ROOT/'.env'));local=healthy('http://127.0.0.1:8765');failures=0
    else:failures=0
    if not local:
        checkpoint(state='recovering_api',local_api=False);return failures
    state_path=ROOT/'.private/public-api/state.json'
    state=json.loads(state_path.read_text()) if state_path.exists() else None
    # A transient DNS/network failure must not rotate a live tunnel's URL.
    if state is None or not public_processes_alive(state) or public_tunnel_expired(state):
        if state is not None:stop()
        start(wait_for_health=False)
        state=json.loads(state_path.read_text())
    from start_extsecure import ensure_local_ai
    environment=dict(os.environ);environment.update({k:v for k,v in dotenv_values(ROOT/'.env').items() if v is not None})
    # Local inference recovery must never stop the API or rotate its public URL.
    try:local_ai_ready=ensure_local_ai(environment)
    except Exception:local_ai_ready=False
    public=healthy(state['origin'])
    origin_file=STATE/'package-origin.txt'
    if public and (not origin_file.exists() or origin_file.read_text(encoding='utf-8')!=state['origin']):publish_package(state['origin'])
    checkpoint(state='running' if public else 'waiting_for_public_network',local_api=True,public_api=public,origin=state['origin'],local_ai_ready=local_ai_ready)
    return failures

def lock_instance():
    import msvcrt
    STATE.mkdir(parents=True,exist_ok=True)
    handle=(STATE/'supervisor.lock').open('a+b');handle.seek(0);handle.write(b'0');handle.flush();handle.seek(0)
    try:msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
    except OSError:handle.close();return None
    return handle

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--once',action='store_true');parser.add_argument('--stop',action='store_true');args=parser.parse_args()
    if args.stop:
        STATE.mkdir(parents=True,exist_ok=True);(STATE/'config.json').write_text('{"enabled":false}')
        return
    lock=lock_instance()
    if lock is None:return
    failures=0;active=False
    try:
        while enabled():
            active=True
            try:
                # Keep the host awake while this explicitly enabled API is running.
                ctypes.windll.kernel32.SetThreadExecutionState(0x80000001)
                failures=cycle(failures)
            except Exception as error:
                checkpoint(state='retrying',error_type=type(error).__name__)
            if args.once:break
            for _ in range(20):
                if not enabled():return
                time.sleep(1)
    finally:
        ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)
        if active and not enabled():
            # Stop from the same batch logon that owns the child processes.
            from scripts.stop_public_api import stop
            from activate_postgresql import api_process,stop_api
            stop();stop_api(api_process());checkpoint(state='stopped')
        lock.close()

if __name__=='__main__':main()
