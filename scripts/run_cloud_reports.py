"""Run open-model reports on a free GitHub-hosted runner, never on the laptop.

Only aggregate counters enter inference. Never print identities, tickets, prompts,
model output, stored reports or HTTP response bodies to public Actions logs.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
ORIGIN = 'https://extsecure-api-htg7.onrender.com'
AUDIENCE = 'extsecure-cloud-reports'
MODEL = 'qwen2.5:7b-instruct-q4_K_M'
DIGEST = '845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e'
PREFIX = '/monitor/api/intelligence/report-automation/'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def safe_open(request, *, timeout):
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open(request,timeout=timeout)


class WorkerFailure(RuntimeError):
    def __init__(self, category):
        self.category = category
        super().__init__(category)


def _read_json(response, limit=131072):
    data = response.read(limit+1)
    if len(data) > limit:
        raise WorkerFailure('response_limit')
    return json.loads(data)


def identity():
    url = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL', '')
    token = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN', '')
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or not parsed.hostname.endswith('.actions.githubusercontent.com') or not token:
        raise WorkerFailure('github_identity_unavailable')
    values = urllib.parse.parse_qsl(parsed.query)
    values = [(k,v) for k,v in values if k != 'audience'] + [('audience', AUDIENCE)]
    url = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(values)))
    request = urllib.request.Request(url, headers={'Authorization':'Bearer '+token})
    with safe_open(request, timeout=25) as response:
        result = _read_json(response)
    value = result.get('value')
    if not isinstance(value, str) or not 100 <= len(value) <= 20000:
        raise WorkerFailure('github_identity_invalid')
    return value


def api(action, payload, *, opener=safe_open, pause=time.sleep):
    # A new short-lived identity is minted per attempt, including after long inference.
    for attempt, wait in enumerate((0, 8, 20, 40, 60)):
        if wait:
            pause(wait)
        token = identity()
        request = urllib.request.Request(ORIGIN+PREFIX+action,
            data=json.dumps(payload, allow_nan=False).encode(),method='POST',
            headers={'Authorization':'Bearer '+token,'Content-Type':'application/json','User-Agent':'ExtSecure-Cloud-Reports'})
        try:
            with opener(request, timeout=95) as response:
                return _read_json(response)
        except urllib.error.HTTPError as error:
            if error.code == 409:
                raise WorkerFailure('snapshot_changed') from None
            if error.code in {401,403,404,422,429}:
                raise WorkerFailure('authorization' if error.code in {401,403} else 'report_rejected') from None
            if error.code not in {502,503,504} or attempt == 4:
                raise WorkerFailure('api_unavailable') from None
        except (urllib.error.URLError, TimeoutError):
            if attempt == 4:
                raise WorkerFailure('api_unavailable') from None
    raise WorkerFailure('api_unavailable')


def jobs_path():
    root = Path(os.environ['RUNNER_TEMP']).resolve()
    if not root.is_dir():
        raise WorkerFailure('runner_temporary_directory_missing')
    return root / 'extsecure-report-jobs.json'


def probe():
    result = api('jobs', {'limit':2})
    jobs = result.get('jobs')
    if not isinstance(jobs,list) or len(jobs)>2:
        raise WorkerFailure('invalid_job_list')
    path = jobs_path()
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as stream:
        json.dump(jobs,stream,ensure_ascii=False,allow_nan=False)
    with open(os.environ['GITHUB_OUTPUT'],'a',encoding='utf-8') as stream:
        stream.write('pending='+('true' if jobs else 'false')+'\n')
    print('Report periods ready:',len(jobs))


def verify_model():
    with urllib.request.urlopen('http://127.0.0.1:11434/api/tags',timeout=10) as response:
        result=_read_json(response)
    if not any(m.get('name')==MODEL and m.get('digest')==DIGEST for m in result.get('models',[])):
        raise WorkerFailure('model_digest_mismatch')


def run():
    from alba_security.llm import write_narrative
    from alba_security.model_provider import LocalModelClient
    path=jobs_path()
    try:
        jobs=json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(jobs,list) or len(jobs)>2:
            raise WorkerFailure('invalid_job_list')
        client=LocalModelClient(timeout_seconds=600)
        failures=0
        for job in jobs:
            try:
                verify_model()
                if job.get('model')!=MODEL or job.get('model_digest')!=DIGEST:
                    raise WorkerFailure('model_digest_mismatch')
                narrative=write_narrative(job['stats'],language=job['language'],
                    purpose=job['kind']+' alert and explanation report',client=client,model=MODEL,
                    evidence_codes=tuple(job['evidence_codes']))
                raw={key:narrative[key] for key in ('summary','evidence_codes','recommendation_codes')}
                result=api('complete',{'ticket':job['ticket'],'narrative':raw,'model':MODEL,'model_digest':DIGEST})
                if result.get('status') not in {'generated','already_saved'}:
                    raise WorkerFailure('report_not_saved')
                print('Report saved:',job['kind'],'—',result['status'])
            except Exception as error:
                failures+=1
                stage='generation' if isinstance(error,WorkerFailure) else 'cloud_ai'
                try:
                    api('failed',{'ticket':job['ticket'],'stage':stage})
                except Exception:
                    pass
                print('Report attempt needs retry:',job.get('kind','unknown'),stage)
        if failures:
            raise WorkerFailure('one_or_more_reports_need_retry')
    finally:
        path.unlink(missing_ok=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe',action='store_true')
    parser.add_argument('--mark-failed',action='store_true')
    args=parser.parse_args()
    try:
        if args.mark_failed:
            path=jobs_path()
            if path.exists():
                for job in json.loads(path.read_text(encoding='utf-8')):
                    api('failed',{'ticket':job['ticket'],'stage':'cloud_ai'})
            print('Cloud inference failure recorded for retry')
        else:
            probe() if args.probe else run()
        return 0
    except Exception as error:
        # Exception details can contain response content or temporary identities.
        print('Cloud report worker:',error.category if isinstance(error,WorkerFailure) else 'operation_failed')
        return 1


if __name__=='__main__':
    raise SystemExit(main())
