import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
let store={},calls=[],responder=()=>({}),listener,access;
let localStore={},sessionRules=[],hooks={};
const event=name=>({addListener:f=>hooks[name]=f});
globalThis.chrome={
 storage:{session:{setAccessLevel:async v=>{access=v;},get:async()=>structuredClone(store),set:async value=>{store={...store,...structuredClone(value)};},remove:async keys=>{for(const key of Array.isArray(keys)?keys:[keys])delete store[key];}},local:{get:async()=>structuredClone(localStore),set:async v=>{localStore={...v};}}},
 runtime:{id:'test-extension',getURL:path=>'chrome-extension://test-extension/'+path,onMessage:{addListener:f=>listener=f},onStartup:event('startup'),onInstalled:event('installed')},
 tabs:{query:async()=>[{url:'https://example.com/private?token=x'}],create:async v=>calls.push(v),update:async(id,v)=>calls.push({tabId:id,...v}),onRemoved:event('removed')},
 webNavigation:{onBeforeNavigate:event('before'),onCommitted:event('committed'),onErrorOccurred:event('error')},
 alarms:{onAlarm:event('alarm'),create:async()=>{},clear:async()=>true},
 declarativeNetRequest:{getSessionRules:async()=>structuredClone(sessionRules),isRegexSupported:async()=>({isSupported:true}),updateSessionRules:async({removeRuleIds=[],addRules=[]})=>{sessionRules=sessionRules.filter(r=>!removeRuleIds.includes(r.id));sessionRules.push(...structuredClone(addRules));}},
 action:{setBadgeText:async v=>calls.push(v),setBadgeBackgroundColor:async()=>{}}
};
globalThis.fetch=async(url,options)=>{calls.push({url,options});return new Response(JSON.stringify(responder(url,options)),{status:200,headers:{'Content-Type':'application/json'}});};
const {handleMessage}=await import('../background.js');
const reset=()=>{store={};calls=[];localStore={};sessionRules=[];responder=()=>({});};
test('A delayed profile refresh cannot restore a signed-out session',async()=>{
 reset();store.session={token:'old-token',expires_at:new Date(Date.now()+60000).toISOString()};
 const previous=fetch;let release;
 globalThis.fetch=async()=>new Promise(resolve=>release=()=>resolve(new Response(JSON.stringify({username:'old-owner',role:'head_administrator'}))));
 try{const refreshing=handleMessage({type:'STATE'});await new Promise(resolve=>setImmediate(resolve));
 delete store.session;release();await assert.rejects(refreshing,error=>error.status===401);assert.equal(store.session,undefined);
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
test('Settings save only validated preferences and never send them to the backend',async()=>{reset();await handleMessage({type:'SAVE_PREFERENCES',preferences:{language:'ar',timeZone:'Asia/Riyadh',token:'not-saved'}});assert.deepEqual(localStore,{preferences:{language:'ar',timeZone:'Asia/Riyadh'}});assert.equal(calls.length,0);await assert.rejects(handleMessage({type:'SAVE_PREFERENCES',preferences:{timeZone:'invalid'}}));});
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
 await assert.rejects(opening,/tab or sign-in changed/);assert.equal(sessionRules.length,0);assert.equal(store.session,undefined);assert.equal(calls.some(call=>call.tabId===7),false);
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
