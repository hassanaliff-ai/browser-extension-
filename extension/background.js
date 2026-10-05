import {API_ORIGIN, VERSION, privateTarget, safeApiPath, apiError} from './core.js';
import {registerNavigationGate} from './access.js';
import {normalizePreferences} from './locale.js';

const storageReady = chrome.storage.session.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'});
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
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  let response;
  try { response = await fetch(API_ORIGIN+(direct ? path : '/monitor'+path), {method,headers,body:body === undefined ? undefined : JSON.stringify(body),cache:'no-store',credentials:'omit',redirect:'error',signal:AbortSignal.timeout(90000)}); }
  catch { throw new Error('Cannot reach the ExtSecure backend. Start the API service, then try again. No result has been marked safe.'); }
  if (path === '/api/admin/register/qr' && response.ok) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    return {image:'data:image/png;base64,'+btoa(String.fromCharCode(...bytes))};
  }
  const data = await response.json().catch(()=>({}));
  if (!response.ok) {
    if (response.status === 401 && !AUTH_PUBLIC.has(path)) {
      // A delayed response from a previous account must not revoke a newer login.
      const current = await loadSession();
      if (current.token === session.token) {
        try { await invalidateSession(); } catch { /* Credentials remain removed if Chrome cleanup fails. */ }
      }
    }
    throw failure(apiError(response.status,data),response.status);
  }
  return data;
}
const gate = registerNavigationGate(request,loadSession);
export async function handleMessage(message,sender={}) {
  await storageReady;
  if (!message || typeof message.type !== 'string') throw new Error('Invalid extension request.');
  if (message.type === 'PREFERENCES') return normalizePreferences((await chrome.storage.local.get('preferences')).preferences);
  if (message.type === 'SAVE_PREFERENCES') {
    const preferences=normalizePreferences(message.preferences,true);
    await chrome.storage.local.set({preferences}); return preferences;
  }
  if (message.type === 'BLOCKED_STATE') {
    const {target}=await gate.context(sender);
    const session=await loadSession();
    return {target,signed_in:!!session.token,...(session.token?await request('/api/access/check','POST',{target}):{allowed:false})};
  }
  if (message.type === 'OPEN_APPROVED') return gate.open(sender);
  if (message.type === 'STATE') {
    const session = await loadSession();
    let profile = session.token ? session.profile : undefined;
    if (session.token) {
      profile = await request('/api/admin/me');
      const current = await loadSession();
      if (current.token !== session.token) throw failure('Your sign-in changed. Refresh the extension.',401);
      await store({...current,profile});
    }
    return {profile, expires_at:session.expires_at, challenge:!!session.challenge_token, enrollment:!!session.enrollment_token,version:VERSION};
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
    return {profile,expires_at:data.expires_at};
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
    const data = await request('/api/admin/register/verify','POST',{enrollment_token:session.enrollment_token,totp_code:message.code});
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
    return {url,host:url ? new URL(url).hostname : ''};
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
