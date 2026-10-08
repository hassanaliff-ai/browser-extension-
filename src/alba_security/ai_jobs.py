"""Short authenticated polling requests for slower local inference."""
import threading
from time import monotonic
from uuid import uuid4

from fastapi import Depends, HTTPException
from fastapi.responses import JSONResponse

from alba_security.permissions import allowed


def install_ai_jobs(app, require_actor, directory):
    jobs, lock = {}, threading.Lock()

    def submit(actor, route, work):
        with lock:
            for key in list(jobs):
                if jobs[key]['state'] in {'completed', 'failed'} and monotonic() - jobs[key]['created'] > 300:
                    del jobs[key]
            if any(j['state'] in {'queued', 'running'} for j in jobs.values()):
                raise HTTPException(429, 'AI generation is already running; try again after it finishes')
            if len(jobs) >= 32:
                oldest = min(jobs, key=lambda key: jobs[key]['created'])
                del jobs[oldest]
            job_id = str(uuid4())
            jobs[job_id] = {'actor': actor, 'route': route, 'created': monotonic(), 'state': 'queued'}

        def run():
            try:
                with lock:
                    jobs[job_id]['state'] = 'running'
                with app.state.session_factory() as db:
                    if not allowed(directory.role(db, actor), 'POST', route):
                        raise HTTPException(403, 'Your role no longer permits this action')
                    result = work(db)
                update = {'state': 'completed', 'result': result}
            except HTTPException as error:
                update = {'state': 'failed', 'status_code': error.status_code, 'detail': error.detail}
            except Exception:
                update = {'state': 'failed', 'status_code': 500, 'detail': 'AI generation failed; no fabricated result was saved'}
            with lock:
                jobs[job_id].update(update)

        threading.Thread(target=run, daemon=True, name='extsecure-ai-generation').start()
        return JSONResponse({'job_id': job_id, 'state': 'queued'}, status_code=202)

    @app.get('/api/ai-jobs/{job_id}')
    def status(job_id: str, actor: str = Depends(require_actor)):
        with lock:
            job = jobs.get(job_id)
            if not job or job['actor'] != actor:
                raise HTTPException(404, 'AI job not found')
            if job['state'] in {'completed', 'failed'} and monotonic() - job['created'] > 300:
                del jobs[job_id]
                raise HTTPException(404, 'AI job expired; check the saved report or explanation')
            with app.state.session_factory() as db:
                if not allowed(directory.role(db, actor), 'POST', job['route']):
                    raise HTTPException(403, 'Your role no longer permits this action')
            return {k: job[k] for k in ('state', 'result', 'status_code', 'detail') if k in job}

    app.state.submit_ai_job = submit
