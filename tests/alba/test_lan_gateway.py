import httpx
import pytest
from scripts import lan_gateway

@pytest.fixture
def anyio_backend():return 'asyncio'

@pytest.mark.anyio
async def test_gateway_limits_routes_network_and_request_size(monkeypatch):
    monkeypatch.setenv('EXTSECURE_LAN_SUBNET','192.168.1.0/24')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=lan_gateway.app,client=('192.168.1.2',123)),base_url='https://test') as client:
        assert (await client.get('/docs')).status_code==404
        assert (await client.delete('/monitor/api/devices')).status_code==404
        assert (await client.post('/scan',content=b'x'*(lan_gateway.MAX_BODY+1))).status_code==413
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=lan_gateway.app,client=('203.0.113.2',123)),base_url='https://test') as client:
        assert (await client.get('/health')).status_code==403

@pytest.mark.anyio
async def test_gateway_forwards_to_fixed_backend_and_replaces_forged_peer(monkeypatch):
    monkeypatch.setenv('EXTSECURE_LAN_SUBNET','192.168.1.0/24');original=httpx.AsyncClient
    seen=[]
    def respond(request):
        seen.append(request);return httpx.Response(401,json={'detail':'Sign in required'},headers={'connection':'close'})
    def upstream(**kwargs):return original(transport=httpx.MockTransport(respond),**kwargs)
    monkeypatch.setattr(lan_gateway.httpx,'AsyncClient',upstream)
    async with original(transport=httpx.ASGITransport(app=lan_gateway.app,client=('192.168.1.2',123)),base_url='https://test') as client:
        response=await client.get('/monitor/api/devices',headers={'x-forwarded-for':'8.8.8.8','authorization':'Bearer QA-only'})
    assert response.status_code==401
    assert str(seen[0].url)=='http://127.0.0.1:8765/monitor/api/devices'
    assert seen[0].headers['x-forwarded-for']=='192.168.1.2'
    assert seen[0].headers['authorization']=='Bearer QA-only'
    assert 'connection' not in response.headers

@pytest.mark.anyio
async def test_public_gateway_trusts_only_loopback_connector_and_limits_login(monkeypatch):
    monkeypatch.setenv('EXTSECURE_PUBLIC_GATEWAY','1');lan_gateway.PUBLIC_REQUESTS.clear();original=httpx.AsyncClient;seen=[]
    def respond(request):seen.append(request);return httpx.Response(200,json={'status':'ok'})
    monkeypatch.setattr(lan_gateway.httpx,'AsyncClient',lambda **kwargs:original(transport=httpx.MockTransport(respond),**kwargs))
    async with original(transport=httpx.ASGITransport(app=lan_gateway.app,client=('127.0.0.1',123)),base_url='https://test') as client:
        for _ in range(10):assert (await client.post('/monitor/api/admin/login',headers={'cf-connecting-ip':'203.0.113.20'},json={})).status_code==200
        assert (await client.post('/monitor/api/admin/login',headers={'cf-connecting-ip':'203.0.113.20'},json={})).status_code==429
        assert (await client.get('/health',headers={'cf-connecting-ip':'invalid'})).status_code==400
    assert seen[0].headers['x-forwarded-for']=='203.0.113.20'
    async with original(transport=httpx.ASGITransport(app=lan_gateway.app,client=('192.168.1.20',123)),base_url='https://test') as client:
        assert (await client.get('/health')).status_code==403
