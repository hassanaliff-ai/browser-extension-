"""Send a private report trigger; do not receive, process or log project data."""
from __future__ import annotations
import json
import os
import time
import urllib.parse
import urllib.request
import urllib.error

ORIGIN='https://extsecure-api-htg7.onrender.com'
AUDIENCE='extsecure-cloud-reports'
PATH='/monitor/api/intelligence/report-automation/tick'

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


def trigger(*,opener=safe_open,pause=time.sleep):
    for attempt,wait in enumerate((0,8,20,40,60)):
        if wait:pause(wait)
        token=identity()
        request=urllib.request.Request(ORIGIN+PATH,data=b'{}',method='POST',
            headers={'Authorization':'Bearer '+token,'Content-Type':'application/json',
                     'User-Agent':'ExtSecure-Private-Report-Trigger'})
        try:
            with opener(request,timeout=95)as response:
                # An empty success is the only allowed response. No report JSON,
                # counts, dates or identifiers may be delivered to this runner.
                if response.status!=204 or response.read(1):
                    raise WorkerFailure('unexpected_response_payload')
            return
        except urllib.error.HTTPError as error:
            if error.code in {401,403,404,409,422,429}:
                raise WorkerFailure('trigger_rejected_'+str(error.code))from None
            if error.code not in {502,503,504}or attempt==4:
                raise WorkerFailure('service_unavailable')from None
        except(urllib.error.URLError,TimeoutError):
            if attempt==4:raise WorkerFailure('service_unavailable')from None
    raise WorkerFailure('service_unavailable')


def main():
    try:
        trigger()
        print('Private report trigger accepted. No project data was received.')
        return 0
    except Exception as error:
        print('Private report trigger:',error.category if isinstance(error,WorkerFailure)else'operation_failed')
        return 1


if __name__=='__main__':raise SystemExit(main())
