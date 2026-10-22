"""Basel SecureScope primary API, composed with existing ExtSecure services.

The existing account/2FA, database, inventory, incident and reporting modules
are retained. This factory can be staged separately before the old listener
is retired. Run with uvicorn --factory on the verified free primary port.
"""
from __future__ import annotations

import json
from fastapi import HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import Field, field_validator

import main as services
from .app import CheckRequest, RdapRequest, registered_domain_from_origin

SERVICE_NAME='TestAPI'


class BrowserCheckRequest(CheckRequest):
    # Preserve SecureScope's URL/source/timestamp contract. ExtSecure may
    # deliberately supply a cleaned path; private parameters are prohibited.
    url: str = Field(min_length=10,max_length=4096)

    @field_validator('url')
    @classmethod
    def validate_clean_url(cls,value):
        services.ExtensionScanRequest(target=value)
        return value


def install_primary_routes(application):
    if getattr(application.state,'securescope_primary',False):return application
    application.state.securescope_primary=True
    application.title='SecureScope API for ExtSecure'
    application.version='0.5.0'
    application.description='SecureScope scanning and RDAP with the existing authenticated ExtSecure administrator and PostgreSQL services.'
    monitor=application.state.monitoring_app
    if monitor is not None:
        monitor.title='ExtSecure administrator API'
        monitor.openapi_schema=None
    # Only this staged application instance changes; the old running process
    # and its database are untouched. Administrator routes remain mounted.
    replaced={'/','/health','/extension/capabilities'}
    application.router.routes[:]=[r for r in application.router.routes if getattr(r,'path',None) not in replaced]

    @application.get('/',tags=['Health'])
    @application.get('/health',tags=['Health'])
    def health():return {'status':'ok','service':SERVICE_NAME,'api_provider':'SecureScope'}

    @application.get('/extension/capabilities',tags=['Integration'])
    def capabilities(request:Request,response:Response):
        data=services.extension_capabilities(request,response).model_dump()
        return {**data,'api_provider':'SecureScope','scan_endpoint':'/api/v1/check','rdap_endpoint':'/api/v1/rdap'}

    @application.post('/api/v1/check',tags=['SecureScope'])
    async def check(payload:BrowserCheckRequest,request:Request):
        response=await services.extension_scan(services.ExtensionScanRequest(target=payload.url),request)
        data=json.loads(response.body)
        reasons=[str(f.get('detail') or f.get('title'))[:200] for f in data.get('findings',[])][:10]
        if not reasons:
            reasons=['No confirmed threat finding in the available evidence; this does not prove safety.'] if data.get('severity')!='Unknown' else ['Threat evidence unavailable; Unknown is not safe.']
        data.update(api_provider='SecureScope',origin=payload.url,reasons=reasons,
                    lookup_status='complete' if data.get('completeness')=='complete' else 'partial',
                    cached=data.get('lookup',{}).get('cached') is True)
        return JSONResponse(data,status_code=response.status_code,headers={'Cache-Control':'no-store'})

    @application.post('/api/v1/rdap',tags=['SecureScope'])
    async def rdap(payload:RdapRequest,request:Request):
        monitor=request.app.state.monitoring_app
        if monitor is None:raise HTTPException(503,'Account monitoring must be configured')
        if not request.headers.get('authorization','').startswith('Bearer '):
            raise HTTPException(401,'Approved account sign-in required')
        actor=await run_in_threadpool(services._authorize_scan,monitor,request)
        if actor is None:raise HTTPException(401,'Approved account sign-in required')
        retry=request.app.state.extension_scan_limit.retry_after(actor)
        if retry:raise HTTPException(429,'Scan limit reached',headers={'Retry-After':str(retry)})
        try:registered_domain_from_origin(payload.origin)
        except ValueError as error:raise HTTPException(422,str(error)) from error
        evidence=await request.app.state.domain_age.async_lookup(payload.origin)
        public={k:v for k,v in evidence.items() if k in {'status','age_days','registered_at','reason','cached'}}
        return JSONResponse(public,headers={'Cache-Control':'no-store'})

    application.openapi_schema=None
    return application


def create_app():
    # The global module instance has already loaded the private backend settings.
    # Reuse it rather than creating a second connection pool/account store.
    return install_primary_routes(services.app)
