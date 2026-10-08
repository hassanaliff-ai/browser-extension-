import {validateLogo,logoKey} from './account-logo.js';
import {API_ORIGIN, VERSION, OPERATIONS_API_CONTRACT, WORKER_CAPABILITIES, privateTarget, safeApiPath, apiError} from './core.js';
import {registerNavigationGate,reportNavigation} from './access.js';
import {normalizePreferences} from './locale.js';
import {enabledExtensions,platformName} from './inventory.js';
import {safeActiveTab} from './workspace-kit.js';

const storageReady = Promise.all([
  chrome.storage.session.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'}),
  chrome.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'})
]);
const AUTH_PUBLIC = new Set(['/api/admin/login','/api/admin/verify','/api/admin/register','/api/admin/register/verify','/api/admin/register/cancel','/api/admin/register/qr']);
const futureExpiry = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) && Date.parse(value) > Date.now();
function failure(message,status) { return Object.assign(new Error(message),{status}); }
async function invalidateSession(preserveBlocked=false) {
  await chrome.storage.session.remove('session');
  try { await gate.clear({preserveBlocked}); } finally { await chrome.action.setBadgeText({text:''}); }
}
export async function loadSession() {
  const {session = {}} = await chrome.storage.session.get('session');
  if (session.token && !futureExpiry(session.expires_at)) {
    await invalidateSession(); return {};
  }
  return session;
}
async function store(session) { await chrome.storage.session.set({session}); }
async function accountLogo(profile) {
  if(typeof profile?.username!=="string"||!profile.username)return {...profile,logo:null};
  const key=await logoKey(profile.username),saved=(await chrome.storage.local.get(key))[key];
  try{if(saved){validateLogo(saved);return {...profile,logo:saved};}}catch{/* Keep corrupt local data out of the UI. */}
  return {...profile,logo:null};
}

async function updateBadge(data) {
  if (!['Low','Medium','High','Critical','Unknown'].includes(data?.severity)) return;
  await chrome.action.setBadgeBackgroundColor({color:['High','Critical'].includes(data.severity) ? '#c54446' : '#1d6c65'});
  await chrome.action.setBadgeText({text:['High','Critical'].includes(data.severity) ? '!' : data.severity === 'Unknown' ? '?' : ''});
}
async function request(path, method = 'GET', body, direct = false) {
  if (!direct && !safeApiPath(path,method)) throw new Error('This API action is not supported.');
  const session = await loadSession();
  if (!AUTH_PUBLIC.has(path) && !session.token) throw failure('Sign in with your approved account first.',401);
  const headers = {'Accept':'application/json'};
  if (session.token && !AUTH_PUBLIC.has(path)) headers.Authorization = 'Bearer '+session.token;
  const {deviceCredential}=await chrome.storage.local.get('deviceCredential');
  if(session.token&&!AUTH_PUBLIC.has(path)&&deviceCredential?.token)headers['X-ExtSecure-Device']=deviceCredential.token;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const aiGeneration=method==='POST'&&(/^\/api\/intelligence\/(reports\/generate|scans\/[a-zA-Z0-9-]+\/explain)$/.test(path)||path==='/api/reports/monthly/generate');
  if(aiGeneration)headers.Prefer='respond-async';
  let response;
  try { response = await fetch(API_ORIGIN+(direct ? path : '/monitor'+path), {method,headers,body:body === undefined ? undefined : JSON.stringify(body),cache:'no-store',credentials:'omit',redirect:'error',signal:AbortSignal.timeout(25000)}); }
  catch(error) { throw new Error(error.name==='TimeoutError'||error.name==='AbortError'?'The request timed out. Check scan history or saved reports before retrying. No result has been marked safe.':'Cannot reach the ExtSecure backend. Start the API service, then try again. No result has been marked safe.'); }
  if (path === '/api/admin/register/qr' && response.ok) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    return {image:'data:image/png;base64,'+btoa(String.fromCharCode(...bytes))};
  }
  let data;
  try {data=await response.json();}
  catch {if(response.ok)throw new Error('The backend returned an invalid response. Refresh and try again; no safe verdict was assigned.');data={};}
  if (!response.ok) {
    if(response.status===403&&/device is blocked|Link this Chrome profile|Add this device|device is waiting|device connection was revoked/.test(data.detail??''))
      await gate.clear({preserveBlocked:true});
    if (response.status === 401 && !AUTH_PUBLIC.has(path)) {
      // A delayed response from a previous account must not revoke a newer login.
      const current = await loadSession();
      if (current.token === session.token) {
        try { await invalidateSession(); } catch { /* Credentials remain removed if Chrome cleanup fails. */ }
      }
    }
    throw failure(apiError(response.status,data),response.status);
  }
  if(session.token&&!AUTH_PUBLIC.has(path)) {
    const current=await loadSession();
    if(current.token!==session.token)throw failure('Your sign-in changed. Refresh the extension.',409);
  }
  if(aiGeneration&&response.status===202&&/^[a-f0-9-]{36}$/.test(data.job_id??'')) {
    for(let poll=0;poll<90;poll++) {
      if((await loadSession()).token!==session.token)throw failure('Your sign-in changed. Refresh the extension.',409);
      const job=await request('/api/ai-jobs/'+data.job_id);
      if(job.state==='completed')return job.result;
      if(job.state==='failed')throw failure(apiError(job.status_code,{detail:job.detail}),job.status_code);
      if(!['queued','running'].includes(job.state))throw new Error('The AI job returned an invalid status. Try again.');
      await new Promise(resolve=>setTimeout(resolve,2000));
    }
    throw new Error('AI generation is taking longer than expected. Check Reports for the saved draft before trying again.');
  }
  return data;
}
const gate = registerNavigationGate(request,loadSession);
let syncQueue=Promise.resolve();
let connectQueue=Promise.resolve();
const inventoryEventsRegistered=new Set();
function registerInventoryEvents() {
  for(const name of ['onInstalled','onUninstalled','onEnabled','onDisabled']) {
    if(inventoryEventsRegistered.has(name)||!chrome.management?.[name])continue;
    try {
      chrome.management[name].addListener(()=>void autoSyncInventory().catch(()=>{}));
      inventoryEventsRegistered.add(name);
    } catch { /* Optional permission may not yet be granted in this Chrome profile. */ }
  }
}
async function syncInventory() {
  // Serialise snapshots so a slow older update cannot overwrite a newer one.
  const operation=syncQueue.catch(()=>{}).then(async()=>{
    if(!(await loadSession()).token)throw failure('Sign in with your approved account first.',401);
    if(!await chrome.permissions.contains({permissions:['management']}))throw new Error('Allow Chrome extension inventory access first.');
    registerInventoryEvents();
    const {deviceCredential}=await chrome.storage.local.get('deviceCredential');
    if(!deviceCredential?.token)throw new Error('Link this Chrome profile to a device in My account first.');
    const items=enabledExtensions(await chrome.management.getAll());
    return request('/api/inventory/sync','POST',{extensions:items});
  });
  syncQueue=operation;
  return operation;
}
async function autoSyncInventory() {
  await storageReady;
  const {inventoryConnected}=await chrome.storage.local.get('inventoryConnected');
  const session=await loadSession();
  if(inventoryConnected&&session.token&&!session.profile?.inventory?.pending&&!session.profile?.inventory?.blocked)await syncInventory();
}
registerInventoryEvents();
chrome.alarms.onAlarm.addListener(alarm=>{if(alarm.name==='inventory-sync')void autoSyncInventory().catch(()=>{});});
export async function handleMessage(message,sender={}) {
  await storageReady;
  if (!message || typeof message.type !== 'string') throw new Error('Invalid extension request.');
  if(message.type==='HEALTH') {
    // Fixed local health endpoint only; never attach account or device credentials.
    try {
      const response=await fetch(API_ORIGIN+'/health',{method:'GET',headers:{Accept:'application/json'},credentials:'omit',cache:'no-store',redirect:'error',signal:AbortSignal.timeout(5000)});
      const data=await response.json();
      return {status:response.ok&&data.status==='ok'&&data.service==='ExtSecure API'?'ready':'offline',checked_at:new Date().toISOString()};
    } catch {return {status:'offline',checked_at:new Date().toISOString()};}
  }
  if (message.type === 'PREFERENCES') return normalizePreferences((await chrome.storage.local.get('preferences')).preferences);
  if (message.type === 'SAVE_PREFERENCES') {
    const preferences=normalizePreferences(message.preferences,true);
    await chrome.storage.local.set({preferences}); return preferences;
  }
  if(message.type==='CONNECT_DEVICE') {
    const operation=connectQueue.catch(()=>{}).then(async()=>{
      const session=await loadSession();
      if(!session.token)throw failure('Sign in with your approved account first.',401);
      const stored=await chrome.storage.local.get(['deviceCredential','pendingDeviceConnection']);
      if(message.initial_access!==undefined&&!['trusted','blocked'].includes(message.initial_access))
        throw new Error('Choose Trusted device or Blocked device before adding this device.');
      if(!stored.deviceCredential?.token&&message.initial_access===undefined)
        throw new Error('Choose Trusted device or Blocked device before adding this device.');
      let token=stored.deviceCredential?.token??stored.pendingDeviceConnection;
      if(!token) {
        token=Array.from(crypto.getRandomValues(new Uint8Array(32)),byte=>byte.toString(16).padStart(2,'0')).join('');
        // Save before sending. Retrying after a lost response uses the same key.
        await chrome.storage.local.set({pendingDeviceConnection:token});
      }
      const manifest=chrome.runtime.getManifest(),platform=await chrome.runtime.getPlatformInfo();
      const body={browser_token:token,operating_system:platformName(platform.os),
        extension:{id:chrome.runtime.id,name:manifest.name,version:manifest.version}};
      if(message.initial_access!==undefined)body.initial_access=message.initial_access;
      if(typeof message.name==='string'&&message.name.trim())body.name=message.name.trim();
      if(typeof message.ip_address==='string'&&message.ip_address.trim())body.ip_address=message.ip_address.trim();
      const device=await request('/api/inventory/connect','POST',body);
      if((await loadSession()).token!==session.token)throw failure('Your sign-in changed. Click Add this device again.',401);
      await chrome.storage.local.set({deviceCredential:{token,device_id:device.device_id}});
      await chrome.storage.local.remove('pendingDeviceConnection');
      await gate.clear({preserveBlocked:true});
      // Registration already succeeded. A permission API failure must not turn
      // that success into a failed device-add result.
      let permission=false;
      try { permission=await chrome.permissions.contains({permissions:['management']}); }
      catch { /* Other extensions remain unavailable until explicitly connected. */ }
      if(permission){
        await chrome.storage.local.set({inventoryConnected:true});
        await chrome.alarms.create('inventory-sync',{periodInMinutes:30});
      }
      let inventory_status=device.pending?'pending':device.blocked?'blocked':permission?'ready':'permission_required',enabled_count;
      if(!device.pending&&!device.blocked&&permission) {
        try {const synced=await syncInventory();enabled_count=synced.enabled_count;}
        catch {inventory_status='retry_required';}
      }
      return {...device,inventory_status,enabled_count};
    });
    connectQueue=operation;
    return operation;
  }
  if(message.type==='PAIR_DEVICE') {
    if(typeof message.code!=='string')throw new Error('Enter the one-time device pairing code.');
    const manifest=chrome.runtime.getManifest(),platform=await chrome.runtime.getPlatformInfo();
    const data=await request('/api/inventory/pair','POST',{code:message.code.trim(),
      extension:{id:chrome.runtime.id,name:manifest.name,version:manifest.version},operating_system:platformName(platform.os)});
    await chrome.storage.local.set({deviceCredential:{token:data.device_token,device_id:data.device_id}});
    await gate.clear({preserveBlocked:true});
    return {device_id:data.device_id,device_name:data.device_name};
  }
  if(message.type==='SYNC_INVENTORY') {
    const result=await syncInventory();
    await chrome.storage.local.set({inventoryConnected:true});
    await chrome.alarms.create('inventory-sync',{periodInMinutes:30});
    return result;
  }
  if (message.type === 'BLOCKED_STATE') {
    const context=await gate.context(sender),{target}=context;
    const session=await loadSession();
    if(session.token)void reportNavigation(request,loadSession,context,'blocked');
    return {target,signed_in:!!session.token,role:session.profile?.role,...(session.token?await request('/api/access/check','POST',{target}):{allowed:false})};
  }
  if (message.type === 'OPEN_APPROVED') return gate.open(sender);
  if (message.type === 'SAVE_ACCOUNT_LOGO') {
    const session=await loadSession();
    const profile=await request('/api/admin/me');
    const key=await logoKey(profile.username);
    if(message.logo!==null) {
      const bytes=validateLogo(message.logo);
      let bitmap;
      try{bitmap=await createImageBitmap(new Blob([bytes],{type:'image/png'}));}
      catch{throw new Error('This image could not be opened. Choose another image.');}
      bitmap.close();
    }
    if((await loadSession()).token!==session.token)throw failure('Your sign-in changed. Refresh the extension.',409);
    if(message.logo===null)await chrome.storage.local.remove(key);
    else await chrome.storage.local.set({[key]:message.logo});
    return {logo:message.logo};
  }
  if (message.type === 'STATE') {
    const session = await loadSession();
    let profile = session.token ? session.profile : undefined;
    if (session.token) {
      profile = await request('/api/admin/me');
      const current = await loadSession();
      if (current.token !== session.token) throw failure('Your sign-in changed. Refresh the extension.',401);
      await store({...current,profile});
      if(profile.inventory?.blocked)await gate.clear({preserveBlocked:true});
      if(session.profile?.inventory?.pending&&profile.inventory?.linked&&!profile.inventory?.blocked&&!profile.inventory?.pending)void autoSyncInventory().catch(()=>{});
    }
    return {profile:profile?await accountLogo(profile):undefined, expires_at:session.expires_at, challenge:!!session.challenge_token, enrollment:!!session.enrollment_token,version:VERSION,operations_api_contract:OPERATIONS_API_CONTRACT,capabilities:[...WORKER_CAPABILITIES]};
  }
  if (message.type === 'LOGIN') {
    if (typeof message.username !== 'string' || typeof message.password !== 'string') throw new Error('Enter your username and password.');
    const data = await request('/api/admin/login','POST',{username:message.username.trim(),password:message.password});
    await invalidateSession(!(await loadSession()).token);
    await store({challenge_token:data.challenge_token,challenge_expires_at:data.expires_at});
    return {step:'verify'};
  }
  if (message.type === 'VERIFY') {
    const session = await loadSession();
    if (!session.challenge_token || !futureExpiry(session.challenge_expires_at)) {
      await invalidateSession();
      throw failure('The sign-in challenge expired. Start sign-in again.',401);
    }
    const data = await request('/api/admin/verify','POST',{challenge_token:session.challenge_token,totp_code:message.code});
    await store({token:data.access_token,expires_at:data.expires_at});
    const profile = await request('/api/admin/me');
    await store({token:data.access_token,expires_at:data.expires_at,profile});
    void autoSyncInventory().catch(()=>{});
    return {profile:await accountLogo(profile),expires_at:data.expires_at};
  }
  if (message.type === 'REGISTER') {
    const data = await request('/api/admin/register','POST',{username:message.username,password:message.password});
    await invalidateSession(!(await loadSession()).token);
    await store({enrollment_token:data.enrollment_token,enrollment_expires_at:data.expires_at});
    return {secret:data.totp_secret,expires_at:data.expires_at,...await request('/api/admin/register/qr','POST',{enrollment_token:data.enrollment_token})};
  }
  if (message.type === 'ENROLLMENT_QR') {
    const session = await loadSession();
    if (!session.enrollment_token) throw new Error('Start account registration first.');
    return request('/api/admin/register/qr','POST',{enrollment_token:session.enrollment_token});
  }
  if (message.type === 'REGISTER_VERIFY') {
    const session = await loadSession();
    const data = await request('/api/admin/register/verify','POST',{enrollment_token:session.enrollment_token,totp_code:message.code,role:message.role??'normal_user'});
    await chrome.storage.session.remove('session'); return data;
  }
  if (message.type === 'RESET_AUTH') {
    const session = await loadSession();
    try { if (session.enrollment_token) await request('/api/admin/register/cancel','POST',{enrollment_token:session.enrollment_token}); }
    finally { await invalidateSession(); }
    return {};
  }
  if (message.type === 'LOGOUT') {
    let revoked = false;
    try { await request('/api/admin/logout','POST'); revoked = true; }
    finally { await invalidateSession(); }
    return {revoked};
  }
  if (message.type === 'API') {
    if (AUTH_PUBLIC.has(message.path) || message.path === '/api/admin/logout') throw new Error('Use the dedicated sign-in action.');
    if(['/api/inventory/connect','/api/inventory/pair','/api/inventory/sync'].includes(message.path))throw new Error('Use the dedicated Chrome inventory action.');
    const data = await request(message.path,message.method ?? 'GET',message.body);
    if (message.path === '/api/admin/downloads/scan') await updateBadge(data);
    return data;
  }
  if (message.type === 'ACTIVE_TAB') {
    const [tab] = await chrome.tabs.query({active:true,currentWindow:true});
    let url=tab?.url??'';
    if(url.startsWith(chrome.runtime.getURL('blocked.html'))){
      const item=(await chrome.storage.session.get('blocked:'+tab.id))['blocked:'+tab.id];
      url=item&&Date.now()-item.captured_at<30*60*1000?privateTarget(item.url,true):'';
    }
    return safeActiveTab({url});
  }
  if (message.type === 'SCAN_URL') {
    const target = privateTarget(message.target,!!message.includePath);
    const data = await request('/extension/scan','POST',{target},true);
    await updateBadge(data);
    return data;
  }
  if (message.type === 'OPEN_CONSOLE') {
    await chrome.tabs.create({url:chrome.runtime.getURL('console.html'+(message.view ? '#'+encodeURIComponent(message.view) : ''))});
    return {};
  }
  throw new Error('Unknown extension action.');
}
chrome.runtime.onMessage.addListener((message,sender,sendResponse)=>{
  if (sender.id !== chrome.runtime.id || !sender.url?.startsWith(chrome.runtime.getURL(''))) { sendResponse({ok:false,error:'Only trusted ExtSecure pages can perform this action.'}); return false; }
  handleMessage(message,sender).then(data=>sendResponse({ok:true,data})).catch(error=>sendResponse({ok:false,error:error.message,status:error.status}));
  return true;
});
