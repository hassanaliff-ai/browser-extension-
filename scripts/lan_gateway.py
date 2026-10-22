"""HTTPS LAN entry point; the existing API and database stay on loopback."""
import asyncio
import ipaddress
import os
import time
from collections import OrderedDict,deque
import httpx

ALLOWED_PATHS=('/monitor/api/','/extension/')
MAX_BODY=2*1024*1024
HOP_HEADERS={'host','connection','keep-alive','transfer-encoding','upgrade','proxy-authorization','proxy-authenticate','trailer','te'}
PUBLIC_REQUESTS=OrderedDict()

async def app(scope,receive,send):
    if scope['type']=='lifespan':
        while True:
            message=await receive()
            if message['type']=='lifespan.startup':await send({'type':'lifespan.startup.complete'})
            else:await send({'type':'lifespan.shutdown.complete'});return
    if scope['type']!='http':return
    async def reply(status,body):
        await send({'type':'http.response.start','status':status,'headers':[(b'content-type',b'application/json'),(b'cache-control',b'no-store')]})
        await send({'type':'http.response.body','body':body})
    path=scope['path']
    if scope['method'] not in {'GET','POST'} or not (path in {'/health','/scan'} or path.startswith(ALLOWED_PATHS)):
        return await reply(404,b'{"detail":"API route unavailable."}')
    peer=scope['client'][0]
    public=os.environ.get('EXTSECURE_PUBLIC_GATEWAY')=='1'
    if public:
        if not ipaddress.ip_address(peer).is_loopback:return await reply(403,b'{"detail":"Use the public HTTPS endpoint."}')
        incoming={k.decode().lower():v.decode('latin1') for k,v in scope['headers']}
        try:peer=str(ipaddress.ip_address(incoming.get('cf-connecting-ip',peer)))
        except ValueError:return await reply(400,b'{"detail":"Invalid connection address."}')
        now=time.monotonic();key=(peer,'auth' if path in {'/monitor/api/admin/login','/monitor/api/admin/register'} else 'api')
        bucket=PUBLIC_REQUESTS.setdefault(key,deque());PUBLIC_REQUESTS.move_to_end(key)
        while bucket and bucket[0]<=now-60:bucket.popleft()
        if len(bucket)>=(10 if key[1]=='auth' else 120):return await reply(429,b'{"detail":"Too many requests. Wait one minute before retrying."}')
        bucket.append(now)
        while len(PUBLIC_REQUESTS)>4096:PUBLIC_REQUESTS.popitem(last=False)
    else:
        network=ipaddress.ip_network(os.environ['EXTSECURE_LAN_SUBNET'])
        if ipaddress.ip_address(peer) not in network:
            return await reply(403,b'{"detail":"Connect from the configured local network."}')
    body=bytearray()
    while True:
        event=await receive()
        if event['type']=='http.disconnect':return
        body.extend(event.get('body',b''))
        if len(body)>MAX_BODY:return await reply(413,b'{"detail":"Request is too large."}')
        if not event.get('more_body'):break
    headers={k.decode('latin1'):v.decode('latin1') for k,v in scope['headers'] if k.decode('latin1').lower() not in HOP_HEADERS|{'x-forwarded-for','x-forwarded-proto','forwarded'}}
    headers.update({'x-forwarded-for':peer,'x-forwarded-proto':'https'})
    target='http://127.0.0.1:8765'+path
    if scope.get('query_string'):target+='?'+scope['query_string'].decode('ascii')
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(120,connect=5),trust_env=False) as client:
            response=await client.request(scope['method'],target,headers=headers,content=bytes(body))
    except httpx.HTTPError:
        return await reply(503,b'{"detail":"The API is unavailable. Start ExtSecure on the host computer."}')
    response_headers=[(k.encode('latin1'),v.encode('latin1')) for k,v in response.headers.items() if k.lower() not in HOP_HEADERS|{'content-length','content-encoding'}]
    response_headers.append((b'cache-control',b'no-store'))
    await send({'type':'http.response.start','status':response.status_code,'headers':response_headers})
    await send({'type':'http.response.body','body':response.content})
