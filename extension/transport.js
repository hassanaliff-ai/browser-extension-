import {normalizePreferences} from './locale.js';
import {API_ORIGIN, apiError, safeApiPath, privateTarget} from './core.js';
export const isExtension = location.protocol === 'chrome-extension:' && !!globalThis.chrome?.runtime?.id;
// The ordinary-browser adapter exists only for an explicitly labelled local UI
// review. Chrome uses the service worker and chrome.storage.session instead.
let previewSession = {};
const previewAllowed = !isExtension && ['127.0.0.1','localhost'].includes(location.hostname) && location.port === '8911';
const previewOrigin = 'http://127.0.0.1:8767';
async function previewRequest(path,method='GET',body,direct=false) {
  if (!direct && !safeApiPath(path,method)) throw new Error('Unsupported action.');
  const headers = {'Accept':'application/json'};
  if (previewSession.token) headers.Authorization = 'Bearer '+previewSession.token;
  if (body !== undefined) headers['Content-Type']='application/json';
  let response;
  try { response=await fetch(previewOrigin+(direct ? path : '/monitor'+path),{method,headers,body:body===undefined?undefined:JSON.stringify(body),cache:'no-store',credentials:'omit',redirect:'error',signal:AbortSignal.timeout(90000)}); }
  catch { throw new Error('The isolated UI test backend is not running.'); }
  if(path==='/api/admin/register/qr' && response.ok) {
    const bytes=new Uint8Array(await response.arrayBuffer());
    return {image:'data:image/png;base64,'+btoa(String.fromCharCode(...bytes))};
  }
  const data=await response.json().catch(()=>({}));
  if(!response.ok){if(response.status===401&&!path.startsWith('/api/admin/register'))previewSession={};throw Object.assign(new Error(apiError(response.status,data)),{status:response.status});}
  return data;
}
export async function send(message) {
  if(isExtension){const result=await chrome.runtime.sendMessage(message);if(!result?.ok)throw Object.assign(new Error(result?.error??'The extension service worker did not respond.'),{status:result?.status});return result.data;}
  if(!previewAllowed)throw new Error('Load the ExtSecure folder as an unpacked Chrome extension. This interface is not a standalone website.');
  switch(message.type){
    case 'PREFERENCES':{try{return normalizePreferences(JSON.parse(localStorage.getItem('extsecure-preview-preferences')??'{}'));}catch{return normalizePreferences();}}
    case 'SAVE_PREFERENCES':{const prefs=normalizePreferences(message.preferences,true);localStorage.setItem('extsecure-preview-preferences',JSON.stringify(prefs));return prefs;}
    case 'BLOCKED_STATE':return {target:'https://example.com/',signed_in:!!previewSession.token,allowed:false};
    case 'OPEN_APPROVED':throw new Error('Chrome navigation enforcement requires loading the extension.');
    case 'STATE':return {profile:previewSession.profile,challenge:!!previewSession.challenge_token,enrollment:!!previewSession.enrollment_token,expires_at:previewSession.expires_at};
    case 'LOGIN':{const data=await previewRequest('/api/admin/login','POST',{username:message.username,password:message.password});previewSession={...data};return {step:'verify'};}
    case 'VERIFY':{const data=await previewRequest('/api/admin/verify','POST',{challenge_token:previewSession.challenge_token,totp_code:message.code});previewSession={token:data.access_token,expires_at:data.expires_at};previewSession.profile=await previewRequest('/api/admin/me');return {profile:previewSession.profile};}
    case 'REGISTER':{const data=await previewRequest('/api/admin/register','POST',{username:message.username,password:message.password});previewSession={enrollment_token:data.enrollment_token};return {secret:data.totp_secret,...await previewRequest('/api/admin/register/qr','POST',previewSession)};}
    case 'ENROLLMENT_QR':return previewRequest('/api/admin/register/qr','POST',{enrollment_token:previewSession.enrollment_token});
    case 'REGISTER_VERIFY':{const data=await previewRequest('/api/admin/register/verify','POST',{enrollment_token:previewSession.enrollment_token,totp_code:message.code});previewSession={};return data;}
    case 'RESET_AUTH':if(previewSession.enrollment_token)await previewRequest('/api/admin/register/cancel','POST',{enrollment_token:previewSession.enrollment_token});previewSession={};return {};
    case 'LOGOUT':try{return await previewRequest('/api/admin/logout','POST');}finally{previewSession={};}
    case 'API':return previewRequest(message.path,message.method??'GET',message.body);
    case 'ACTIVE_TAB':return {url:'https://example.com/',host:'example.com'};
    case 'SCAN_URL':return previewRequest('/extension/scan','POST',{target:privateTarget(message.target,!!message.includePath)},true);
    case 'OPEN_CONSOLE':location.href='console.html'+(message.view?'#'+message.view:'');return {};
    default:throw new Error('Unsupported preview action.');
  }
}
export const previewNotice = isExtension ? '' : '<div class="preview-banner"><strong>Extension UI preview</strong> · Isolated test data. Chrome APIs require loading the unpacked extension.</div>';
