"""Exercise the real MV3 UI against isolated, temporary security evidence."""
from pathlib import Path
import json, os, secrets, shutil, socket, subprocess, sys, threading, time, uuid
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT)]
import httpx, pyotp, uvicorn
from fastapi import FastAPI
from argon2 import PasswordHasher
from alba_security.api import create_app
from alba_security.admin_auth import AdminAuth
from alba_security.models import PersonalScan, utc_now
from alba_security.registration import RegisteredAdmin


def verify():
    output=ROOT/'.private'/('feedback-browser-'+uuid.uuid4().hex)
    output.mkdir(parents=True)
    extension=output/'extension'
    shutil.copytree(ROOT/'extension',extension,ignore=shutil.ignore_patterns('tests','node_modules','_metadata'))
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
    origin=f'http://127.0.0.1:{port}'
    core=extension/'core.js'
    import re
    core.write_text(re.sub(r"export const API_ORIGIN = '[^']+';",f"export const API_ORIGIN = '{origin}';",core.read_text(encoding='utf-8')),encoding='utf-8')
    manifest=extension/'manifest.json'; data=json.loads(manifest.read_text(encoding='utf-8'))
    data['content_security_policy']['extension_pages']=re.sub(r'connect-src [^;]+;',f'connect-src {origin};',data['content_security_policy']['extension_pages'])
    manifest.write_text(json.dumps(data),encoding='utf-8')
    password=secrets.token_urlsafe(24); head_secret=pyotp.random_base32(); user_secret=pyotp.random_base32()
    hasher=PasswordHasher(time_cost=1,memory_cost=1024,parallelism=1)
    app=create_app(database_url='sqlite:///'+(output/'evidence.sqlite').as_posix(),
        ingest_token=secrets.token_urlsafe(24),admin_auth=AdminAuth('feedback-head',hasher.hash(password),head_secret),alert_notifier=lambda **_:[])
    with app.state.session_factory() as db:
        db.add(RegisteredAdmin(username='feedback-user',password_hash=hasher.hash(password),
            totp_encrypted=app.state.admin_directory.cipher().encrypt(user_secret.encode()).decode(),
            role='normal_user',status='active',approved_by='feedback-head',approved_at=utc_now()))
        db.commit()
    web=FastAPI()
    web.mount('/monitor',app)
    @web.get('/health')
    def health():return {'service':'TestAPI','status':'ok'}
    server=uvicorn.Server(uvicorn.Config(web,host='127.0.0.1',port=port,log_level='error'))
    thread=threading.Thread(target=server.run,daemon=True);thread.start()
    try:
        for _ in range(100):
            if server.started:break
            time.sleep(.05)
        assert server.started
        response=httpx.post(origin+'/monitor/api/scans',headers={'X-Ingest-Token':app.state.ingest_token},json={
            'device_id':'feedback-test-device','device_name':'Isolated feedback test device',
            'target_kind':'url','target':'https://feedback.example/',
            'signals':[{'code':'malicious_url','status':'detected'}]},trust_env=False)
        response.raise_for_status();scan=response.json()
        with app.state.session_factory() as db:
            db.add(PersonalScan(scan_id=scan['id'],username='feedback-user'));db.commit()
        env=dict(os.environ)
        env.update(EXTSECURE_FEEDBACK_EXTENSION=str(extension),EXTSECURE_FEEDBACK_OUTPUT=str(output),
            EXTSECURE_TEST_PASSWORD=password,EXTSECURE_TEST_USER_SECRET=user_secret,
            EXTSECURE_TEST_HEAD_SECRET=head_secret,EXTSECURE_TEST_SCAN=scan['id'])
        node=env.get('EXTSECURE_NODE') or shutil.which('node')
        if not node:raise RuntimeError('Set EXTSECURE_NODE to the Node executable')
        result=subprocess.run([node,str(ROOT/'extension/tests/user-feedback-browser.mjs')],env=env,cwd=ROOT,
            capture_output=True,text=True,encoding='utf-8',timeout=180,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        print(result.stdout,flush=True)
        if result.stderr:print(result.stderr,file=sys.stderr,flush=True)
        if result.returncode:raise RuntimeError('Browser verification failed')
        print('Isolated MV3 feedback verification passed. Evidence: '+str(output))
    finally:
        server.should_exit=True;thread.join(timeout=10);app.state.engine.dispose()


if __name__=='__main__':verify()
