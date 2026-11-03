"""Supervise the updated loopback API without stopping legacy Windows workers."""
from pathlib import Path
import ctypes, json, os, socket, subprocess, sys, time
import httpx
from dotenv import dotenv_values

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from alba_security.permissions import WEBSITE_ACCESS_POLICY

STATE=ROOT/'.private/current-api'
PORT=8769
ENTRYPOINT='prototypes.securescope.backend.primary:create_app'


def ready():
    try:
        response=httpx.get(f'http://127.0.0.1:{PORT}/health',timeout=3,trust_env=False)
        data=response.json()
        return response.status_code==200 and data.get('service')=='TestAPI' and data.get('website_access_policy')==WEBSITE_ACCESS_POLICY
    except (httpx.HTTPError,ValueError):return False


def enabled():
    try:return json.loads((STATE/'config.json').read_text(encoding='utf-8-sig')).get('enabled') is True
    except (OSError,ValueError):return False


def checkpoint(**values):
    STATE.mkdir(parents=True,exist_ok=True)
    temporary=STATE/'status.tmp'
    temporary.write_text(json.dumps({'supervisor_pid':os.getpid(),'checked_at':time.time(),**values}))
    temporary.replace(STATE/'status.json')


def ensure_worker():
    if ready():return
    # Never terminate an unrecognized process occupying the selected port.
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
        probe.bind(('127.0.0.1',PORT))
    environment=dict(os.environ)
    environment.update({k:v for k,v in dotenv_values(ROOT/'.env').items() if v is not None})
    environment.update(PYTHONPATH=str(ROOT/'src'),OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',MKL_NUM_THREADS='1')
    STATE.mkdir(parents=True,exist_ok=True)
    with (STATE/'api.log').open('ab') as log:
        child=subprocess.Popen([sys.executable,'-m','uvicorn',ENTRYPOINT,'--factory','--host','127.0.0.1','--port',str(PORT)],
            cwd=ROOT,env=environment,stdin=subprocess.DEVNULL,stdout=log,stderr=log,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    for _ in range(40):
        if child.poll() is not None:raise RuntimeError('Updated API worker exited')
        if ready():
            (STATE/'worker.json').write_text(json.dumps({'port':PORT,'pid':child.pid,'policy':WEBSITE_ACCESS_POLICY}))
            return
        time.sleep(.25)
    if child.poll() is None:child.terminate()
    raise RuntimeError('Updated API did not become ready')


def main():
    import msvcrt
    STATE.mkdir(parents=True,exist_ok=True)
    with (STATE/'supervisor.lock').open('a+b') as lock:
        lock.seek(0);lock.write(b'0');lock.flush();lock.seek(0)
        try:msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
        except OSError:return
        try:
            while enabled():
                try:
                    ctypes.windll.kernel32.SetThreadExecutionState(0x80000001)
                    ensure_worker()
                    from start_extsecure import ensure_local_ai
                    environment=dict(os.environ)
                    environment.update({k:v for k,v in dotenv_values(ROOT/'.env').items() if v is not None})
                    try:ai_ready=ensure_local_ai(environment)
                    except Exception:ai_ready=False
                    checkpoint(state='running',port=PORT,policy=WEBSITE_ACCESS_POLICY,local_ai_ready=ai_ready)
                except Exception as error:checkpoint(state='retrying',error_type=type(error).__name__,port=PORT)
                for _ in range(15):
                    if not enabled():break
                    time.sleep(1)
        finally:
            ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)
            msvcrt.locking(lock.fileno(),msvcrt.LK_UNLCK,1)


if __name__=='__main__':main()
