import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
let localAccess;
let store={},calls=[],responder=()=>({}),listener,access;
let localStore={},sessionRules=[],hooks={};
const event=name=>({addListener:f=>{const previous=hooks[name];hooks[name]=(...args)=>{previous?.(...args);return f(...args);};}});
globalThis.chrome={
 storage:{session:{setAccessLevel:async v=>{access=v;},get:async()=>structuredClone(store),set:async value=>{store={...store,...structuredClone(value)};},remove:async keys=>{for(const key of Array.isArray(keys)?keys:[keys])delete store[key];}},local:{setAccessLevel:async v=>{localAccess=v;},get:async()=>structuredClone(localStore),remove:async key=>{delete localStore[key];},set:async v=>{localStore={...localStore,...v};}}},
 permissions:{contains:async()=>true},management:{onEnabled:event('inventory-enabled'),onDisabled:event('inventory-disabled'),onInstalled:event('inventory-installed'),onUninstalled:event('inventory-uninstalled'),getAll:async()=>[{id:'a'.repeat(32),name:'ExtSecure',version:'0.7.0',enabled:true,type:'extension'}]},
 runtime:{id:'test-extension',getManifest:()=>({name:'ExtSecure',version:'0.7.0'}),getPlatformInfo:async()=>({os:'win'}),getURL:path=>'chrome-extension://test-extension/'+path,onMessage:{addListener:f=>listener=f},onStartup:event('startup'),onInstalled:event('installed')},
 tabs:{query:async()=>[{url:'https://example.com/private?token=x'}],create:async v=>calls.push(v),update:async(id,v)=>calls.push({tabId:id,...v}),onRemoved:event('removed')},
 webNavigation:{onBeforeNavigate:event('before'),onCommitted:event('committed'),onErrorOccurred:event('error')},
 alarms:{onAlarm:event('alarm'),create:async()=>{},clear:async()=>true},
 declarativeNetRequest:{getSessionRules:async()=>structuredClone(sessionRules),isRegexSupported:async()=>({isSupported:true}),updateSessionRules:async({removeRuleIds=[],addRules=[]})=>{sessionRules=sessionRules.filter(r=>!removeRuleIds.includes(r.id));sessionRules.push(...structuredClone(addRules));}},
 action:{setBadgeText:async v=>calls.push(v),setBadgeBackgroundColor:async()=>{}}
};
globalThis.fetch=async(url,options)=>{calls.push({url,options});return new Response(JSON.stringify(responder(url,options)),{status:200,headers:{'Content-Type':'application/json'}});};
const {handleMessage}=await import('../background.js');
const {VERSION,WORKER_CAPABILITIES,OPERATIONS_API_CONTRACT}=await import('../core.js');
const reset=()=>{store={};calls=[];localStore={};sessionRules=[];responder=()=>({});};

test('Actual Chrome message listener forwards every workflow and control route to the authenticated API',async()=>{
 const uuid='12345678-1234-4234-8234-123456789abc',notice='a'.repeat(64);
 const routes=[['GET','/api/operations/status'],['GET','/api/workflow/rules'],['GET','/api/workflow/notifications'],['GET','/api/controls/reviews'],
  ...[7,30,90,365].map(days=>['GET','/api/controls/effectiveness?days='+days]),
  ['POST','/api/workflow/rules'],['POST',`/api/workflow/rules/${uuid}/update`],['POST','/api/workflow/run'],['POST',`/api/workflow/notifications/${notice}/acknowledge`],['POST','/api/controls/reviews'],['POST','/api/controls/navigation']];
 for(const [method,path] of routes){
  reset();store.session={token:'test-token',expires_at:new Date(Date.now()+60000).toISOString()};responder=()=>({recorded:true});
  const body=method==='POST'?{reason:'Synthetic worker dispatch test'}:undefined;
  const response=await new Promise(resolve=>listener({type:'API',path,method,body},{id:chrome.runtime.id,url:chrome.runtime.getURL('console.html')},resolve));
  assert.deepEqual(response,{ok:true,data:{recorded:true}},path);assert.equal(calls.length,1,path);
  assert.equal(calls[0].url,'http://127.0.0.1:8765/monitor'+path);assert.equal(calls[0].options.method,method);
  assert.equal(calls[0].options.headers.Authorization,'Bearer test-token');
  assert.equal(calls[0].options.body,body===undefined?undefined:JSON.stringify(body));
 }
});
test('Actual worker listener denies invalid task routes before any network request',async()=>{
 for(const [method,path] of [['GET','/api/workflow/unknown'],['DELETE','/api/workflow/rules'],['GET','/api/controls/effectiveness?days=30&token=x'],['POST','/api/workflow/rules/not-an-id/update'],['GET','https://other.test/api/workflow/rules']]){
  reset();store.session={token:'test-token',expires_at:new Date(Date.now()+60000).toISOString()};
  const response=await new Promise(resolve=>listener({type:'API',path,method},{id:chrome.runtime.id,url:chrome.runtime.getURL('console.html')},resolve));
  assert.equal(response.ok,false);assert.equal(response.error,'This API action is not supported.');assert.equal(calls.length,0);
 }
});

test('Health checks use only the fixed local endpoint without account or device credentials',async()=>{
 reset();store.session={token:'private-account-token',expires_at:new Date(Date.now()+60000).toISOString()};localStore.deviceCredential={token:'private-device-token'};
 responder=()=>({status:'ok',service:'TestAPI',private_value:'not forwarded'});
 const result=await handleMessage({type:'HEALTH',url:'https://other.test'});
 assert.equal(result.status,'ready');assert.equal(calls[0].url,'http://127.0.0.1:8765/health');
 assert.deepEqual(calls[0].options.headers,{Accept:'application/json'});assert.equal(JSON.stringify(result).includes('private'),false);
});
test('Health checks remain compatible with the former API name during upgrades',async()=>{
 reset();responder=()=>({status:'ok',service:'ExtSecure API'});
 assert.equal((await handleMessage({type:'HEALTH'})).status,'ready');
});
test('Health checks work anonymously and never mislabel an unreachable API as connected',async()=>{
 reset();const original=fetch;globalThis.fetch=async()=>{throw new Error('Offline');};
 try{assert.equal((await handleMessage({type:'HEALTH'})).status,'offline');assert.equal(store.session,undefined);}
 finally{globalThis.fetch=original;}
 reset();responder=()=>({status:'ok',service:'another service'});assert.equal((await handleMessage({type:'HEALTH'})).status,'offline');
});
test('A successful delayed protected response cannot cross an account switch',async()=>{
 reset();store.session={token:'old-account',expires_at:new Date(Date.now()+60000).toISOString()};const original=fetch;let release;
 globalThis.fetch=async()=>new Promise(resolve=>release=()=>resolve(new Response(JSON.stringify([{secret:'old-account-record'}]))));
 try{const pending=handleMessage({type:'API',path:'/api/scans'});await new Promise(resolve=>setImmediate(resolve));
  store.session={token:'new-account',expires_at:new Date(Date.now()+60000).toISOString()};release();
  await assert.rejects(pending,error=>error.status===409);assert.equal(store.session.token,'new-account');
 }finally{globalThis.fetch=original;}
});
test('Malformed successful responses remain errors instead of empty scan verdicts',async()=>{
 reset();store.session={token:'test-token',expires_at:new Date(Date.now()+60000).toISOString()};const original=fetch;
 globalThis.fetch=async()=>new Response('<html>Proxy error</html>',{status:200});
 try{await assert.rejects(handleMessage({type:'SCAN_URL',target:'https://example.com'}),/invalid response/);assert.equal(calls.some(c=>c.text==='?'),false);}
 finally{globalThis.fetch=original;}
});
test('A timeout gives recovery guidance and never reports a safe scan',async()=>{
 reset();store.session={token:'test-token',expires_at:new Date(Date.now()+60000).toISOString()};const original=fetch;
 globalThis.fetch=async()=>{const error=new Error('request delayed');error.name='TimeoutError';throw error;};
 try{await assert.rejects(handleMessage({type:'SCAN_URL',target:'https://example.com'}),/timed out.*history.*No result has been marked safe/);}
 finally{globalThis.fetch=original;}
});
test('Browser settings and file tabs do not offer an invalid website scan',async()=>{
 reset();const original=chrome.tabs.query;
 try{for(const url of ['chrome://newtab','chrome://extensions','file:///C:/private.txt']){chrome.tabs.query=async()=>[{url}];assert.deepEqual(await handleMessage({type:'ACTIVE_TAB'}),{url:'',host:''});}}
 finally{chrome.tabs.query=original;}
});
test('AI generation polls a protected job and returns its completed report',async()=>{
 reset();store.session={token:'synthetic-ai-token',expires_at:new Date(Date.now()+60000).toISOString()};
 const previous=fetch;const id='12345678-1234-1234-1234-123456789abc';let posts=0,gets=0;
 globalThis.fetch=async(url,options)=>{
  assert.equal(options.headers.Authorization,'Bearer synthetic-ai-token');
  if(options.method==='POST'){posts++;assert.equal(options.headers.Prefer,'respond-async');return new Response(JSON.stringify({job_id:id,state:'queued'}),{status:202});}
  gets++;assert.ok(url.endsWith('/api/ai-jobs/'+id));return new Response(JSON.stringify({state:'completed',result:{kind:'weekly',narrative:{summary:'Synthetic report'}}}));
 };
 try{const result=await handleMessage({type:'API',path:'/api/intelligence/reports/generate',method:'POST',body:{kind:'weekly',period:'2026-09-28'}});assert.equal(result.kind,'weekly');assert.equal(posts,1);assert.equal(gets,1);}finally{globalThis.fetch=previous;}
});
test('An AI job failure never becomes a successful report',async()=>{
 reset();store.session={token:'synthetic-ai-token',expires_at:new Date(Date.now()+60000).toISOString()};const previous=fetch;
 globalThis.fetch=async(url,options)=>options.method==='POST'?new Response(JSON.stringify({job_id:'12345678-1234-1234-1234-123456789abc'}),{status:202}):new Response(JSON.stringify({state:'failed',status_code:502,detail:'Model generation failed'}));
 try{await assert.rejects(handleMessage({type:'API',path:'/api/reports/monthly/generate',method:'POST',body:{year:2026,month:9}}),error=>error.status===502);}finally{globalThis.fetch=previous;}
});
test('An expired session during AI polling clears authentication',async()=>{
 reset();store.session={token:'synthetic-ai-token',expires_at:new Date(Date.now()+60000).toISOString()};const previous=fetch;
 globalThis.fetch=async(url,options)=>options.method==='POST'?new Response(JSON.stringify({job_id:'12345678-1234-1234-1234-123456789abc'}),{status:202}):new Response('{}',{status:401});
 try{await assert.rejects(handleMessage({type:'API',path:'/api/intelligence/reports/generate',method:'POST',body:{kind:'weekly',period:'2026-09-28'}}),error=>error.status===401);assert.equal(store.session,undefined);}finally{globalThis.fetch=previous;}
});
test('Registration submits requested role without granting a session',async()=>{
 reset();store.session={enrollment_token:'synthetic-enrollment'};
 await handleMessage({type:'REGISTER_VERIFY',code:'123456',role:'manager'});
 const payload=JSON.parse(calls.find(c=>c.url?.endsWith('/register/verify')).options.body);
 assert.equal(payload.role,'manager');assert.equal(payload.totp_code,'123456');
 assert.equal(store.session,undefined);
});
test('A delayed profile refresh cannot restore a signed-out session',async()=>{
 reset();store.session={token:'old-token',expires_at:new Date(Date.now()+60000).toISOString()};
 const previous=fetch;let release;
 globalThis.fetch=async()=>new Promise(resolve=>release=()=>resolve(new Response(JSON.stringify({username:'old-owner',role:'head_administrator'}))));
 try{const refreshing=handleMessage({type:'STATE'});await new Promise(resolve=>setImmediate(resolve));
 delete store.session;release();await assert.rejects(refreshing,error=>error.status===409);assert.equal(store.session,undefined);
 }finally{globalThis.fetch=previous;}
});
test('A delayed unauthorized response cannot revoke a newer account session',async()=>{
 reset();store.session={token:'old-token',expires_at:new Date(Date.now()+60000).toISOString()};
 const previous=fetch;let release;
 globalThis.fetch=async()=>new Promise(resolve=>release=()=>resolve(new Response('{}',{status:401})));
 try{const pending=handleMessage({type:'API',path:'/api/overview'});await new Promise(resolve=>setImmediate(resolve));
 store.session={token:'new-token',expires_at:new Date(Date.now()+60000).toISOString()};
 release();await assert.rejects(pending,error=>error.status===401);assert.equal(store.session.token,'new-token');
 }finally{globalThis.fetch=previous;}
});
test('Sessions are restricted to trusted extension contexts',()=>assert.deepEqual(access,{accessLevel:'TRUSTED_CONTEXTS'}));
test('Anonymous protected API calls never reach fetch',async()=>{reset();await assert.rejects(handleMessage({type:'API',path:'/api/overview'}),/Sign in/);assert.equal(calls.length,0);});
test('Password login stores only a challenge and never a password',async()=>{reset();responder=()=>({challenge_token:'synthetic-challenge',expires_at:new Date(Date.now()+60000).toISOString()});await handleMessage({type:'LOGIN',username:'test-owner',password:'Test-only password'});assert.equal(store.session.challenge_token,'synthetic-challenge');assert.equal(JSON.stringify(store).includes('password'),false);assert.equal(store.session.token,undefined);});
test('Expired challenge is rejected without upstream verification',async()=>{reset();store={session:{challenge_token:'expired',challenge_expires_at:'2000-01-01T00:00:00Z'}};await assert.rejects(handleMessage({type:'VERIFY',code:'123456'}),/expired/);assert.equal(calls.some(call=>call.options),false);assert.equal(store.session,undefined);});
test('Successful verification returns profile without exposing the bearer token',async()=>{reset();store={session:{challenge_token:'synthetic',challenge_expires_at:new Date(Date.now()+60000).toISOString()}};responder=url=>url.endsWith('/verify')?{access_token:'test-session-token',expires_at:new Date(Date.now()+60000).toISOString()}:{role:'head_administrator',username:'test-owner'};const result=await handleMessage({type:'VERIFY',code:'123456'});assert.equal(result.profile.role,'head_administrator');assert.equal(JSON.stringify(result).includes('test-session-token'),false);assert.equal(store.session.token,'test-session-token');});
test('STATE validates profile server-side and never exposes the token',async()=>{reset();store={session:{token:'test-token',expires_at:new Date(Date.now()+60000).toISOString()}};responder=()=>({role:'normal_user',username:'personal'});const result=await handleMessage({type:'STATE'});assert.equal(result.profile.role,'normal_user');assert.equal(JSON.stringify(result).includes('test-token'),false);assert.equal(calls[0].options.headers.Authorization,'Bearer test-token');});
test('Expired sessions are discarded',async()=>{reset();store={session:{token:'expired',expires_at:'2000-01-01T00:00:00Z'}};assert.equal((await handleMessage({type:'STATE'})).profile,undefined);assert.deepEqual(store,{});});
test('Content scripts and foreign senders cannot request credentials or API actions',()=>{reset();let response;assert.equal(listener({type:'STATE'},{id:'test-extension',url:'https://untrusted.test'},r=>response=r),false);assert.equal(response.ok,false);assert.equal(listener({type:'STATE'},{id:'other',url:'chrome-extension://test-extension/popup.html'},r=>response=r),false);assert.equal(calls.length,0);});
test('Generic API messages cannot bypass the dedicated sign-in handler',async()=>{reset();await assert.rejects(handleMessage({type:'API',path:'/api/admin/login',method:'POST'}),/dedicated/);});
test('Logout revokes the backend session and removes local state',async()=>{reset();store={session:{token:'test-token',expires_at:new Date(Date.now()+60000).toISOString()}};await handleMessage({type:'LOGOUT'});assert.equal(calls[0].url,'http://127.0.0.1:8765/monitor/api/admin/logout');assert.deepEqual(store,{});});
test('Scanning strips query and fragment before transmission and shows Unknown badge',async()=>{reset();store={session:{token:'test-token',expires_at:new Date(Date.now()+60000).toISOString()}};responder=()=>({severity:'Unknown'});await handleMessage({type:'SCAN_URL',target:'https://example.com/private?secret=x#private'});assert.deepEqual(JSON.parse(calls[0].options.body),{target:'https://example.com/'});assert.equal(calls.at(-1).text,'?');});
test('Console opens an extension URL, not a website',async()=>{reset();await handleMessage({type:'OPEN_CONSOLE'});assert.equal(calls[0].url,'chrome-extension://test-extension/console.html');});
test('Network failures remain errors and cannot become a safe verdict',async()=>{reset();store={session:{token:'test-token',expires_at:new Date(Date.now()+60000).toISOString()}};const previous=fetch;globalThis.fetch=async()=>{throw new Error('offline');};try{await assert.rejects(handleMessage({type:'API',path:'/api/overview'}),/No result has been marked safe/);}finally{globalThis.fetch=previous;}});
test('Manifest has MV3 popup, worker, explicit navigation permissions and bundled scripts',async()=>{const manifest=JSON.parse(await fs.readFile(new URL('../manifest.json',import.meta.url)));assert.equal(manifest.manifest_version,3);assert.equal(manifest.background.type,'module');assert.equal(manifest.action.default_popup,'popup.html');assert.deepEqual(manifest.permissions,['storage','activeTab','declarativeNetRequest','webNavigation','alarms']);assert.equal(manifest.content_security_policy.extension_pages.includes("script-src 'self'"),true);assert.equal(manifest.host_permissions.includes('<all_urls>'),false);assert.deepEqual(manifest.web_accessible_resources[0].resources,['blocked.html']);});
test('Downloaded-file findings update the toolbar badge',async()=>{reset();store={session:{token:'test-token',expires_at:new Date(Date.now()+60000).toISOString()}};responder=()=>({severity:'Critical'});await handleMessage({type:'API',path:'/api/admin/downloads/scan',method:'POST',body:{sha256:'a'.repeat(64)}});assert.equal(calls.at(-1).text,'!');});
test('Revoked session clears local credentials when server denies the request',async()=>{reset();store={session:{token:'revoked-test-token',expires_at:new Date(Date.now()+60000).toISOString()}};const previous=fetch;globalThis.fetch=async()=>new Response('{}',{status:401});try{await assert.rejects(handleMessage({type:'API',path:'/api/overview'}),/Sign-in/);assert.deepEqual(store,{});}finally{globalThis.fetch=previous;}});
test('Failed logout still removes all local session state',async()=>{reset();store={session:{token:'test-token',expires_at:new Date(Date.now()+60000).toISOString()}};const previous=fetch;globalThis.fetch=async()=>{throw new Error('offline');};try{await assert.rejects(handleMessage({type:'LOGOUT'}));assert.deepEqual(store,{});}finally{globalThis.fetch=previous;}});

const blockedSender={id:'test-extension',frameId:0,tab:{id:7},url:'chrome-extension://test-extension/blocked.html'};
const signed=()=>{store={session:{token:'test-token',expires_at:new Date(Date.now()+60000).toISOString()},'blocked:7':{url:'https://example.com/private?original=local-only',captured_at:Date.now()}};};
const flush=()=>new Promise(resolve=>setImmediate(resolve));
test('Settings save only validated preferences and never send them to the backend',async()=>{reset();await handleMessage({type:'SAVE_PREFERENCES',preferences:{language:'ar',timeZone:'Asia/Riyadh',theme:'dark',token:'not-saved'}});assert.deepEqual(localStore,{preferences:{language:'ar',timeZone:'Asia/Riyadh',theme:'dark',tableSize:'standard'}});assert.equal(calls.length,0);await assert.rejects(handleMessage({type:'SAVE_PREFERENCES',preferences:{timeZone:'invalid'}}));});
test('Blocked destination metadata is private and only available in its top-level tab',async()=>{reset();signed();responder=()=>({allowed:false});const data=await handleMessage({type:'BLOCKED_STATE'},blockedSender);assert.equal(data.target,'https://example.com/private');assert.equal(JSON.stringify(data).includes('local-only'),false);assert.deepEqual(JSON.parse(calls[0].options.body),{target:'https://example.com/private'});await assert.rejects(handleMessage({type:'BLOCKED_STATE'},{...blockedSender,frameId:1}));await assert.rejects(handleMessage({type:'BLOCKED_STATE'},{...blockedSender,tab:{id:8}}));});
test('Pending requests never install a rule or navigate',async()=>{reset();signed();responder=()=>({allowed:false});await assert.rejects(handleMessage({type:'OPEN_APPROVED'},blockedSender),/not been approved/);assert.equal(sessionRules.length,0);assert.equal(calls.some(c=>c.tabId===7),false);});
test('Opening consumes approval before creating a tab-scoped rule and preserves original query locally',async()=>{reset();signed();responder=()=>({allowed:true,kind:'once'});const data=await handleMessage({type:'OPEN_APPROVED'},blockedSender);assert.equal(data.opened,true);assert.equal(calls[0].url.endsWith('/api/access/consume'),true);assert.equal(sessionRules.length,1);assert.deepEqual(sessionRules[0].condition.tabIds,[7]);assert.equal(calls.at(-1).url,'https://example.com/private?original=local-only');assert.equal(calls.at(-1).tabId,7);});
test('Committed navigation removes the temporary permission; it cannot become a permanent whitelist',async()=>{reset();signed();responder=()=>({allowed:true,kind:'once'});await handleMessage({type:'OPEN_APPROVED'},blockedSender);hooks.committed({tabId:7,frameId:0,url:'https://example.com/private'});await flush();assert.equal(sessionRules.length,0);assert.equal(store['blocked:7'],undefined);});
test('Navigation error, tab closure and expiry alarm each remove temporary access',async()=>{for(const eventName of ['error','removed','alarm']){reset();signed();responder=()=>({allowed:true,kind:'once'});await handleMessage({type:'OPEN_APPROVED'},blockedSender);if(eventName==='error')hooks.error({tabId:7,frameId:0});if(eventName==='removed')hooks.removed(7);if(eventName==='alarm')hooks.alarm({name:'visit:7'});await flush();assert.equal(sessionRules.length,0,eventName);}});
test('Backend outage keeps navigation blocked',async()=>{reset();signed();const previous=fetch;globalThis.fetch=async()=>{throw new Error('offline');};try{await assert.rejects(handleMessage({type:'OPEN_APPROVED'},blockedSender));assert.equal(sessionRules.length,0);assert.equal(calls.some(c=>c.tabId===7),false);}finally{globalThis.fetch=previous;}});
test('Expired session cannot consume permission or create a navigation rule',async()=>{reset();signed();store.session.expires_at='2000-01-01T00:00:00Z';await assert.rejects(handleMessage({type:'OPEN_APPROVED'},blockedSender),/Sign in/);assert.equal(sessionRules.length,0);assert.equal(calls.some(call=>call.options),false);});
test('Logout and browser startup remove any remaining temporary access',async()=>{reset();signed();responder=()=>({allowed:true,kind:'once'});await handleMessage({type:'OPEN_APPROVED'},blockedSender);await handleMessage({type:'LOGOUT'});assert.equal(sessionRules.length,0);assert.equal(store.session,undefined);sessionRules=[{id:100007}];hooks.startup();await flush();assert.equal(sessionRules.length,0);});
test('Logout clears authentication even if Chrome rule cleanup fails',async()=>{reset();signed();const previous=chrome.declarativeNetRequest.updateSessionRules;chrome.declarativeNetRequest.updateSessionRules=async()=>{throw new Error('Chrome cleanup failed');};try{await assert.rejects(handleMessage({type:'LOGOUT'}));assert.equal(store.session,undefined);}finally{chrome.declarativeNetRequest.updateSessionRules=previous;}});

test('Malformed session expiry removes stale profile and temporary permissions without fetching',async()=>{
 reset();signed();store.session.expires_at='invalid';store.session.profile={role:'head_administrator'};sessionRules=[{id:100007}];
 assert.equal((await handleMessage({type:'STATE'})).profile,undefined);
 assert.deepEqual(store,{});assert.equal(sessionRules.length,0);assert.equal(calls.some(call=>call.options),false);
});
test('A profile without a bearer session is never treated as signed in',async()=>{
 reset();store.session={profile:{role:'head_administrator'}};assert.equal((await handleMessage({type:'STATE'})).profile,undefined);
});
test('Malformed challenge expiry cannot reach the MFA endpoint',async()=>{
 reset();store.session={challenge_token:'synthetic',challenge_expires_at:'invalid'};
 await assert.rejects(handleMessage({type:'VERIFY',code:'123456'}),error=>error.status===401&&/expired/.test(error.message));
 assert.equal(calls.some(call=>call.options),false);assert.equal(store.session,undefined);
});
test('Revocation clears navigation grants and exposes status without exposing credentials',async()=>{
 reset();signed();sessionRules=[{id:100007}];const previous=fetch;globalThis.fetch=async()=>new Response('{}',{status:401});
 try {const reply=await new Promise(resolve=>listener({type:'API',path:'/api/overview'},{id:'test-extension',url:'chrome-extension://test-extension/console.html'},resolve));
 assert.equal(reply.ok,false);assert.equal(reply.status,401);assert.equal(sessionRules.length,0);assert.equal(store.session,undefined);assert.equal(JSON.stringify(reply).includes('test-token'),false);
 }finally{globalThis.fetch=previous;}
});
test('Anonymous sign-in preserves the blocked destination while clearing any leftover grant',async()=>{
 reset();store['blocked:7']={url:'https://example.com/private?local=1',captured_at:Date.now()};sessionRules=[{id:100007}];
 responder=()=>({challenge_token:'synthetic',expires_at:new Date(Date.now()+60000).toISOString()});
 await handleMessage({type:'LOGIN',username:'test-owner',password:'test-only'});
 assert.equal(store['blocked:7'].url,'https://example.com/private?local=1');assert.equal(sessionRules.length,0);
});
test('A new destination during approval cannot be replaced by the stale approved URL',async()=>{
 reset();signed();const previous=fetch;let release;
 globalThis.fetch=async()=>new Promise(resolve=>release=()=>resolve(new Response(JSON.stringify({allowed:true,kind:'once'}),{status:200})));
 try {const opening=handleMessage({type:'OPEN_APPROVED'},blockedSender);await flush();
 hooks.before({tabId:7,frameId:0,url:'https://other.example/new'});release();
 await assert.rejects(opening,/tab or sign-in changed/);assert.equal(sessionRules.length,0);assert.equal(calls.some(call=>call.tabId===7),false);
 }finally{globalThis.fetch=previous;}
});
test('Sign-out during approval cancels the in-flight navigation and leaves no rule',async()=>{
 reset();signed();const previous=fetch;let release;
 globalThis.fetch=async url=>url.endsWith('/consume')?new Promise(resolve=>release=()=>resolve(new Response(JSON.stringify({allowed:true,kind:'once'}),{status:200}))):new Response('{}',{status:200});
 try {const opening=handleMessage({type:'OPEN_APPROVED'},blockedSender);await flush();await handleMessage({type:'LOGOUT'});release();
 await assert.rejects(opening,/sign-in changed/);assert.equal(sessionRules.length,0);assert.equal(store.session,undefined);assert.equal(calls.some(call=>call.tabId===7),false);
 }finally{globalThis.fetch=previous;}
});
test('Queued private destination capture cannot repopulate storage after sign-out',async()=>{
 reset();signed();hooks.before({tabId:7,frameId:0,url:'https://example.com/private?secret=local'});
 await handleMessage({type:'LOGOUT'});await flush();assert.equal(store['blocked:7'],undefined);
});
test('Malformed or future blocked timestamps cannot open a website',async()=>{
 for(const captured_at of [NaN,'invalid',Date.now()+60000]){reset();signed();store['blocked:7'].captured_at=captured_at;
 await assert.rejects(handleMessage({type:'OPEN_APPROVED'},blockedSender),/expired/);assert.equal(calls.some(call=>call.options),false);assert.equal(sessionRules.length,0);}
});


test('Persistent device identity storage is restricted to trusted extension contexts',()=>assert.deepEqual(localAccess,{accessLevel:'TRUSTED_CONTEXTS'}));
test('Device pairing collects Chrome self metadata and returns no credential',async()=>{
 reset();signed();const previous=chrome.runtime.id;chrome.runtime.id='a'.repeat(32);
 responder=url=>url.endsWith('/inventory/pair')?{device_token:'test-device-credential',device_id:'device-test',device_name:'Workstation'}:{};
 try{const result=await handleMessage({type:'PAIR_DEVICE',code:'test-one-time-pair-code'});
  const payload=JSON.parse(calls.find(c=>c.url?.endsWith('/inventory/pair')).options.body);
  assert.deepEqual(payload,{code:'test-one-time-pair-code',extension:{id:'a'.repeat(32),name:'ExtSecure',version:'0.7.0'},operating_system:'Windows'});
  assert.equal(localStore.deviceCredential.token,'test-device-credential');assert.equal(JSON.stringify(result).includes('test-device-credential'),false);
 }finally{chrome.runtime.id=previous;}
});
test('Backend calls attach the browser credential separately from account authorization',async()=>{
 reset();signed();localStore.deviceCredential={token:'test-device-token',device_id:'device-test'};
 await handleMessage({type:'API',path:'/api/overview'});
 assert.equal(calls[0].options.headers['X-ExtSecure-Device'],'test-device-token');
 assert.equal(calls[0].options.headers.Authorization,'Bearer test-token');
});
test('Device credentials never enter public authentication calls or STATE',async()=>{
 reset();signed();localStore.deviceCredential={token:'hidden-device-token'};
 await handleMessage({type:'STATE'});assert.equal(JSON.stringify(await handleMessage({type:'STATE'})).includes('hidden-device-token'),false);
 await handleMessage({type:'LOGIN',username:'test',password:'fixture password'});
 assert.equal(calls.find(c=>c.url?.endsWith('/login')).options.headers['X-ExtSecure-Device'],undefined);
});
test('Chrome permission must be granted before extension metadata is read',async()=>{
 reset();signed();localStore.deviceCredential={token:'test-device-token'};
 const contains=chrome.permissions.contains,getAll=chrome.management.getAll;let reads=0;
 chrome.permissions.contains=async()=>false;chrome.management.getAll=async()=>{reads++;return [];};
 try{await assert.rejects(handleMessage({type:'SYNC_INVENTORY'}),/Allow Chrome/);assert.equal(reads,0);assert.equal(calls.some(c=>c.options),false);}
 finally{chrome.permissions.contains=contains;chrome.management.getAll=getAll;}
});
test('Inventory cannot sync from an unpaired browser',async()=>{
 reset();signed();await assert.rejects(handleMessage({type:'SYNC_INVENTORY'}),/Link this Chrome/);assert.equal(calls.some(c=>c.options),false);
});
test('A paired browser without an account session cannot read or upload Chrome inventory',async()=>{
 reset();localStore.deviceCredential={token:'test-device-token'};const original=chrome.management.getAll;let reads=0;
 chrome.management.getAll=async()=>{reads++;return [];};
 try{await assert.rejects(handleMessage({type:'SYNC_INVENTORY'}),error=>error.status===401);assert.equal(reads,0);assert.equal(calls.some(c=>c.options),false);}
 finally{chrome.management.getAll=original;}
});
test('Chrome sync sends a minimal enabled snapshot and records the explicit opt-in',async()=>{
 reset();signed();localStore.deviceCredential={token:'test-device-token'};const original=chrome.management.getAll;
 chrome.management.getAll=async()=>[{id:'a'.repeat(32),name:'ExtSecure',version:'0.7.0',enabled:true,type:'extension',permissions:['tabs']},{id:'b'.repeat(32),name:'Disabled',version:'1',enabled:false,type:'extension'}];
 try{await handleMessage({type:'SYNC_INVENTORY'});const call=calls.find(c=>c.url?.endsWith('/inventory/sync'));
  assert.deepEqual(JSON.parse(call.options.body),{extensions:[{id:'a'.repeat(32),name:'ExtSecure',version:'0.7.0'}]});
  assert.equal(localStore.inventoryConnected,true);
 }finally{chrome.management.getAll=original;}
});
test('Generic API actions cannot extract pairing credentials or forge Chrome sync snapshots',async()=>{
 reset();signed();for(const path of ['/api/inventory/pair','/api/inventory/sync'])await assert.rejects(handleMessage({type:'API',path,method:'POST'}),/dedicated Chrome/);
 assert.equal(calls.some(c=>c.options),false);
});
test('A blocked device denial clears temporary navigation grants and preserves its recovery credential',async()=>{
 reset();signed();sessionRules=[{id:100007}];localStore.deviceCredential={token:'device-blocked-token'};const previous=fetch;
 globalThis.fetch=async()=>new Response(JSON.stringify({detail:'This device is blocked. Contact an administrator.'}),{status:403});
 try{await assert.rejects(handleMessage({type:'API',path:'/api/overview'}),/device is blocked/);assert.equal(sessionRules.length,0);assert.equal(localStore.deviceCredential.token,'device-blocked-token');assert.equal(store.session.token,'test-token');}
 finally{globalThis.fetch=previous;}
});
test('Signing out preserves the device link but removes account access',async()=>{
 reset();signed();localStore.deviceCredential={token:'test-device-token'};await handleMessage({type:'LOGOUT'});
 assert.equal(store.session,undefined);assert.equal(localStore.deviceCredential.token,'test-device-token');
});
test('Enabled-extension changes refresh opted-in inventory only while signed in',async()=>{
 reset();signed();localStore={deviceCredential:{token:'test-device-token'},inventoryConnected:true};
 hooks['inventory-enabled']();await flush();await flush();assert.equal(calls.filter(c=>c.url?.endsWith('/inventory/sync')).length,1);
 calls=[];delete store.session;hooks['inventory-disabled']();await flush();assert.equal(calls.some(c=>c.options),false);
});


test('Basic device connection uses Chrome metadata and keeps its key out of the UI response',async()=>{
 reset();signed();const previous=chrome.permissions.contains;chrome.permissions.contains=async()=>false;
 responder=url=>url.endsWith('/inventory/connect')?{device_id:'device-basic',device_name:'Windows Chrome',linked:true,pending:false,blocked:false}:{};
 try{const result=await handleMessage({type:'CONNECT_DEVICE',initial_access:'trusted'});const call=calls.find(c=>c.url?.endsWith('/inventory/connect')),body=JSON.parse(call.options.body);
  assert.equal(body.operating_system,'Windows');assert.equal(body.name,undefined);assert.equal(body.ip_address,undefined);
  assert.equal(body.initial_access,'trusted');
  assert.match(body.browser_token,/^[a-f0-9]{64}$/);assert.equal(localStore.deviceCredential.token,body.browser_token);
  assert.equal(result.inventory_status,'permission_required');assert.equal(JSON.stringify(result).includes(body.browser_token),false);
  assert.equal(localStore.pendingDeviceConnection,undefined);
 }finally{chrome.permissions.contains=previous;}
});
test('Lost connection responses preserve a stable key for duplicate-free retries',async()=>{
 reset();signed();const previous=fetch,contains=chrome.permissions.contains;chrome.permissions.contains=async()=>false;
 globalThis.fetch=async()=>{throw new Error('lost network response');};
 try{await assert.rejects(handleMessage({type:'CONNECT_DEVICE',initial_access:'trusted'}),/Cannot reach/);const key=localStore.pendingDeviceConnection;assert.match(key,/^[a-f0-9]{64}$/);
  globalThis.fetch=previous;responder=()=>({device_id:'device-retry',device_name:'Retry device',pending:false,blocked:false});
  await handleMessage({type:'CONNECT_DEVICE',initial_access:'trusted'});const body=JSON.parse(calls.find(c=>c.url?.endsWith('/inventory/connect')).options.body);
  assert.equal(body.browser_token,key);assert.equal(localStore.deviceCredential.token,key);
 }finally{globalThis.fetch=previous;chrome.permissions.contains=contains;}
});
test('Pending device requests do not enumerate or sync other extensions',async()=>{
 reset();signed();const original=chrome.management.getAll;let reads=0;chrome.management.getAll=async()=>{reads++;return [];};
 responder=()=>({device_id:'device-pending',device_name:'Pending device',pending:true,blocked:false});
 try{const result=await handleMessage({type:'CONNECT_DEVICE',initial_access:'trusted'});assert.equal(result.inventory_status,'pending');assert.equal(reads,0);assert.equal(calls.some(c=>c.url?.endsWith('/inventory/sync')),false);}
 finally{chrome.management.getAll=original;}
});
test('Blocked device reconnection does not reset the existing key or sync inventory',async()=>{
 reset();signed();localStore.deviceCredential={token:'existing-blocked-device-key',device_id:'device-blocked'};
 responder=()=>({device_id:'device-blocked',device_name:'Blocked device',pending:false,blocked:true});
 const result=await handleMessage({type:'CONNECT_DEVICE',initial_access:'trusted'});assert.equal(result.inventory_status,'blocked');
 assert.equal(localStore.deviceCredential.token,'existing-blocked-device-key');assert.equal(calls.some(c=>c.url?.endsWith('/inventory/sync')),false);
});
test('One device button connects the current profile then syncs permitted enabled extensions',async()=>{
 reset();signed();responder=url=>url.endsWith('/inventory/connect')?{device_id:'device-simple',device_name:'Current device',pending:false,blocked:false}:{enabled_count:1};
 const result=await handleMessage({type:'CONNECT_DEVICE',initial_access:'trusted'});assert.equal(result.inventory_status,'ready');assert.equal(result.enabled_count,1);
 const callsWithBody=calls.filter(c=>c.options);assert.equal(callsWithBody[0].url.endsWith('/inventory/connect'),true);assert.equal(callsWithBody[1].url.endsWith('/inventory/sync'),true);
 assert.equal(callsWithBody[1].options.headers['X-ExtSecure-Device'],localStore.deviceCredential.token);
});
test('Partial inventory failure retains the connected device and gives an explicit retry status',async()=>{
 reset();signed();const previous=fetch;
 globalThis.fetch=async(url,options)=>{calls.push({url,options});return url.endsWith('/inventory/connect')?new Response(JSON.stringify({device_id:'device-partial',device_name:'Current device',pending:false,blocked:false})):new Response('{}',{status:503});};
 try{const result=await handleMessage({type:'CONNECT_DEVICE',initial_access:'trusted'});assert.equal(result.inventory_status,'retry_required');assert.equal(localStore.deviceCredential.device_id,'device-partial');}
 finally{globalThis.fetch=previous;}
});
test('Anonymous device connection cannot create even a local enrollment key',async()=>{
 reset();await assert.rejects(handleMessage({type:'CONNECT_DEVICE',initial_access:'trusted'}),error=>error.status===401);
 assert.equal(localStore.pendingDeviceConnection,undefined);assert.equal(calls.some(c=>c.options),false);
});
test('Generic API messages cannot expose the enrollment key through basic connection',async()=>{
 reset();signed();await assert.rejects(handleMessage({type:'API',path:'/api/inventory/connect',method:'POST'}),/dedicated Chrome/);assert.equal(calls.some(c=>c.options),false);
});
test('Repeated basic clicks reuse the current device key instead of generating another identity',async()=>{
 reset();signed();const original=chrome.permissions.contains;chrome.permissions.contains=async()=>false;
 responder=()=>({device_id:'device-stable',device_name:'Stable device',pending:false,blocked:false});
 try{await handleMessage({type:'CONNECT_DEVICE',initial_access:'trusted'});await handleMessage({type:'CONNECT_DEVICE',initial_access:'trusted'});
  const bodies=calls.filter(c=>c.url?.endsWith('/inventory/connect')).map(c=>JSON.parse(c.options.body));assert.equal(bodies.length,2);assert.equal(bodies[0].browser_token,bodies[1].browser_token);
 }finally{chrome.permissions.contains=original;}
});

test('A permission API error after registration still returns the connected device',async()=>{
 reset();signed();const original=chrome.permissions.contains;
 chrome.permissions.contains=async()=>{throw new Error('Chrome permission API failed');};
 responder=()=>({device_id:'device-permission-error',device_name:'Connected device',pending:false,blocked:false});
 try {const result=await handleMessage({type:'CONNECT_DEVICE',initial_access:'trusted'});
  assert.equal(result.device_id,'device-permission-error');assert.equal(result.inventory_status,'permission_required');
  assert.equal(localStore.deviceCredential.device_id,'device-permission-error');
 } finally {chrome.permissions.contains=original;}
});

test('Worker state reports its running version and inventory capabilities',async()=>{
 reset();const state=await handleMessage({type:'STATE'});
 assert.equal(state.version,VERSION);assert.deepEqual(state.capabilities,[...WORKER_CAPABILITIES]);assert.equal(state.operations_api_contract,OPERATIONS_API_CONTRACT);
 assert.equal(calls.some(c=>c.options),false);
});
test('Chrome message listener dispatches device connection instead of an unknown action',async()=>{
 reset();signed();responder=url=>url.endsWith('/inventory/connect')?{device_id:'device-listener',device_name:'Listener device',pending:false,blocked:false}:{enabled_count:1};
 const response=await new Promise(resolve=>{
  assert.equal(listener({type:'CONNECT_DEVICE',initial_access:'trusted'},{id:'test-extension',url:'chrome-extension://test-extension/console.html'},resolve),true);
 });
 assert.equal(response.ok,true);assert.equal(response.data.device_id,'device-listener');
 assert(calls.some(c=>c.url?.endsWith('/inventory/connect')));
 assert.equal(JSON.stringify(response).includes(localStore.deviceCredential.token),false);
});

test('New device connection rejects a missing or invalid access choice before generating a key',async()=>{
 for(const choice of [undefined,'',true,'approved']){
  reset();signed();const message={type:'CONNECT_DEVICE'};if(choice!==undefined)message.initial_access=choice;
  await assert.rejects(handleMessage(message),/Choose Trusted device or Blocked device/);
  assert.equal(localStore.pendingDeviceConnection,undefined);assert.equal(calls.some(c=>c.options),false);
 }
});
test('Blocked selection is sent to the API and never starts extension sync',async()=>{
 reset();signed();responder=()=>({device_id:'device-chosen-blocked',device_name:'Blocked device',blocked:true,pending:false});
 const result=await handleMessage({type:'CONNECT_DEVICE',initial_access:'blocked'});
 const body=JSON.parse(calls.find(c=>c.url?.endsWith('/inventory/connect')).options.body);
 assert.equal(body.initial_access,'blocked');assert.equal(result.inventory_status,'blocked');
 assert.equal(calls.some(c=>c.url?.endsWith('/inventory/sync')),false);
 assert.equal(localStore.deviceCredential.device_id,'device-chosen-blocked');
});
test('Refreshing an already connected device does not require a creation access choice',async()=>{
 reset();signed();localStore.deviceCredential={token:'existing-device-token',device_id:'device-existing'};
 responder=url=>url.endsWith('/inventory/connect')?{device_id:'device-existing',device_name:'Existing device',blocked:false,pending:false}:{enabled_count:1};
 const result=await handleMessage({type:'CONNECT_DEVICE'});
 assert.equal(result.device_id,'device-existing');
 assert.equal(JSON.parse(calls.find(c=>c.url?.endsWith('/inventory/connect')).options.body).initial_access,undefined);
});

test('A backend-issued 24-hour session is accepted until expiry and cleared exactly at the deadline',async()=>{
 reset();signed();const NativeDate=globalThis.Date;
 const start=NativeDate.parse('2026-10-07T12:00:00Z'),deadline=start+24*60*60*1000;
 let now=deadline-1;
 store.session.expires_at=new NativeDate(deadline).toISOString();
 globalThis.Date=class extends NativeDate {static now(){return now;}};
 try {
  await handleMessage({type:'API',path:'/api/overview'});
  const fetched=calls.filter(c=>c.options).length;assert.equal(fetched,1);
  now=deadline;
  await assert.rejects(handleMessage({type:'API',path:'/api/overview'}),error=>error.status===401);
  assert.equal(store.session,undefined);assert.equal(calls.filter(c=>c.options).length,fetched);
 } finally {globalThis.Date=NativeDate;}
});

const tinyLogo='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jZ1cAAAAASUVORK5CYII=';
test('Every role can save and remove only its own account logo',async()=>{
 const original=globalThis.createImageBitmap;
 globalThis.createImageBitmap=async()=>({close(){}});
 try{
  for(const role of ['normal_user','manager','administrator','head_administrator']){
   reset();signed();responder=()=>({username:role,role});
   await handleMessage({type:'SAVE_ACCOUNT_LOGO',logo:tinyLogo,username:'another-user'});
   assert.equal((await handleMessage({type:'STATE'})).profile.logo,tinyLogo);
   assert.equal(Object.keys(localStore).filter(k=>k.startsWith('accountLogo:')).length,1);
   responder=()=>({username:'another-user',role});
   assert.equal((await handleMessage({type:'STATE'})).profile.logo,null);
   responder=()=>({username:role,role});
   assert.equal((await handleMessage({type:'STATE'})).profile.logo,tinyLogo);
   await handleMessage({type:'SAVE_ACCOUNT_LOGO',logo:null});
   assert.equal((await handleMessage({type:'STATE'})).profile.logo,null);
  }
 }finally{globalThis.createImageBitmap=original;}
});
test('Account logo writes require a verified session and reject unsafe images',async()=>{
 reset();await assert.rejects(handleMessage({type:'SAVE_ACCOUNT_LOGO',logo:tinyLogo}),/Sign in/);
 signed();responder=()=>({username:'image-owner',role:'normal_user'});
 for(const logo of ['https://example.com/photo.png','data:image/svg+xml;base64,PHN2Zz4=',tinyLogo+'<script>',undefined,'data:image/png;base64,'+'A'.repeat(150000)])
  await assert.rejects(handleMessage({type:'SAVE_ACCOUNT_LOGO',logo}),/valid PNG/);
 const original=globalThis.createImageBitmap;
 globalThis.createImageBitmap=async()=>{throw new Error('broken decoder');};
 try{await assert.rejects(handleMessage({type:'SAVE_ACCOUNT_LOGO',logo:tinyLogo}),/could not be opened/);assert.deepEqual(localStore,{});}
 finally{globalThis.createImageBitmap=original;}
});
test('A changed sign-in cannot save a decoded logo into the previous account',async()=>{
 reset();signed();responder=()=>({username:'previous-owner',role:'administrator'});
 const original=globalThis.createImageBitmap;
 globalThis.createImageBitmap=async()=>{store.session.token='different-login';return {close(){}};};
 try{await assert.rejects(handleMessage({type:'SAVE_ACCOUNT_LOGO',logo:tinyLogo}),/sign-in changed/);assert.deepEqual(localStore,{});}
 finally{globalThis.createImageBitmap=original;}
});


test('Table size choices persist locally and reject unsupported sizes without API requests',async()=>{
 reset();
 for(const tableSize of ['compact','standard','spacious']){
  const preferences={language:'ar',timeZone:'Asia/Riyadh',theme:'dark',tableSize};
  await handleMessage({type:'SAVE_PREFERENCES',preferences});
  assert.deepEqual(await handleMessage({type:'PREFERENCES'}),preferences);
 }
 await assert.rejects(handleMessage({type:'SAVE_PREFERENCES',preferences:{tableSize:'giant'}}),/supported table size/);
 assert.equal(localStore.preferences.tableSize,'spacious');assert.equal(calls.length,0);
});
