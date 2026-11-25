// Only the anonymous, read-only health probe is retried. Never replay mutations.
export async function probeApi(origin, policy, {fetcher=globalThis.fetch, wait=ms=>new Promise(resolve=>setTimeout(resolve,ms)), timeout=12000}={}) {
  const metadata={api_origin:origin,checked_at:new Date().toISOString()};
  const attempts=/^https:\/\/[a-z0-9-]+\.onrender\.com$/.test(origin)?6:2;
  for(let attempt=1;attempt<=attempts;attempt++) {
    const controller=new AbortController();
    const timer=setTimeout(()=>controller.abort(),timeout);
    let result;
    try {
      const response=await fetcher(origin+'/health',{method:'GET',headers:{Accept:'application/json'},credentials:'omit',cache:'no-store',redirect:'error',signal:controller.signal});
      if(!response.ok)result={status:'offline',reason:'http_error',http_status:response.status};
      else {
        let data;
        try{data=await response.json();}catch{return {...metadata,status:'offline',reason:'invalid_response',attempts:attempt};}
        const ready=data?.status==='ok'&&['TestAPI','ExtSecure API'].includes(data.service);
        result=ready&&data.website_access_policy!==policy
          ? {status:'update_required',reason:'website_access_policy_outdated'}
          : {status:ready?'ready':'offline',reason:ready?null:'unexpected_service'};
      }
    }catch(error){result={status:'offline',reason:controller.signal.aborted||['TimeoutError','AbortError'].includes(error.name)?'timeout':'network_error'};}
    finally{clearTimeout(timer);}
    const transient=['timeout','network_error'].includes(result.reason)||[502,503,504].includes(result.http_status);
    if(!transient||attempt===attempts)return {...metadata,...result,attempts:attempt};
    await wait(400);
  }
}
