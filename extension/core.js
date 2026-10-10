export const API_ORIGIN = 'http://127.0.0.1:8765';

export function reviewableAccessRequests(rows, now=Date.now()) {
  return rows.filter(r=>r.status==='pending' && r.can_review===true && Date.parse(r.expires_at)>now);
}
export function accessReviewBody(request, form) {
  if(form.confirmed!==true && form.confirmed!=='on')throw new Error('Confirm you have reviewed the destination and the business need.');
  const body={expected_revision:request.revision,reason:form.reason,confirmed:true};
  if(form.decision==='reject')return {...body,decision:'reject'};
  if(form.decision!=='approve')throw new Error('Choose an approval decision.');
  if(form.duration==='forever')return {...body,decision:'whitelist',whitelist_forever:true};
  if(!['24','168'].includes(form.duration))throw new Error('Choose 24 hours, 7 days or Forever.');
  return {...body,decision:'temporary',duration_hours:Number(form.duration)};
}
export const VERSION = '0.8.13';
export const WORKER_CAPABILITIES = Object.freeze(['device-enrollment','chrome-inventory','device-access-choice']);
export const MAX_FILE_SIZE = 32 * 1024 * 1024;
export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
export const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function privateTarget(value, includePath = false) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) throw new Error('Choose an HTTP or HTTPS page. Browser settings and local files cannot be scanned.');
  if (url.username || url.password) throw new Error('URLs containing a username or password are not sent for checking.');
  url.search = ''; url.hash = '';
  if (!includePath) url.pathname = '/';
  return url.href;
}
export function roleCanWrite(profile, area) {
  if (['workflow','controls','policies'].includes(area)) return false;
  const role = profile?.role;
  if (area === 'accounts') return role === 'head_administrator';
  if (area === 'scan') return ['head_administrator','administrator','normal_user'].includes(role);
  if (['alerts','cases','access'].includes(area)) return ['head_administrator','administrator','manager'].includes(role);
  return ['head_administrator','administrator'].includes(role);
}
export function completedMonth(date = new Date()) {
  const previous = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() - 1, 1));
  return previous.toISOString().slice(0, 7);
}
export function reportPeriod(value, date = new Date()) {
  if (!/^20\d{2}-(0[1-9]|1[0-2])$/.test(value) || value >= date.toISOString().slice(0,7)) throw new Error('Select a completed month in UTC.');
  return {year:Number(value.slice(0,4)), month:Number(value.slice(5))};
}
export async function hashFile(file) {
  if (!file || typeof file.arrayBuffer !== 'function') throw new Error('Choose a downloaded file first.');
  if (file.size > MAX_FILE_SIZE) throw new Error('Choose a file of 32 MiB or less.');
  const bytes = await file.arrayBuffer();
  try {
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2,'0')).join('');
  } finally {new Uint8Array(bytes).fill(0);}
}
export function validDigest(value) {
  if (!/^[a-f0-9]{64}$/i.test(value.trim())) throw new Error('Enter a 64-character SHA-256 file hash.');
  return value.trim().toLowerCase();
}
export function safeApiPath(path, method = 'GET') {
  if(method==='GET'&&path==='/api/threat-blocks')return true;
  if(method==='POST'&&/^\/api\/threat-blocks\/(?:host|file|ip|extension):[a-f0-9]{32,64}\/release$/.test(path))return true;
  if(method==='GET'&&/^\/api\/ai-jobs\/[a-f0-9-]{36}$/.test(path))return true;
  if(method==='GET'&&path==='/api/inventory/self')return true;
  if(method==='POST'&&/^\/api\/inventory\/(connect|pair|sync|devices(?:\/device-[a-f0-9-]+\/(status|pairing-code))?)$/.test(path))return true;
  if(method==='GET'&&/^\/api\/intelligence\/(scans\/[a-zA-Z0-9-]+|reports(?:\?limit=\d{1,3})?)$/.test(path))return true;
  if(method==='POST'&&/^\/api\/intelligence\/(scans\/[a-zA-Z0-9-]+\/explain|reports\/generate)$/.test(path))return true;
  if (method === 'GET' && /^\/api\/access\/(requests|whitelist)$/.test(path)) return true;
  if (method === 'POST' && /^\/api\/access\/(requests(?:\/[a-zA-Z0-9-]+\/review)?|whitelist\/[a-zA-Z0-9-]+\/revoke|check|consume)$/.test(path)) return true;
  if (method === 'GET') return /^\/api\/(admin\/(me|accounts|registrations)|overview|risk-policy|devices|extensions|findings|scans(?:\/[a-zA-Z0-9-]+)?|my\/scans(?:\/[a-zA-Z0-9-]+)?|overrides(?:\/audit)?|reports\/monthly(?:\/(stats|ml))?|alerts|events|cases(?:\/[a-zA-Z0-9-]+)?|case-assignees|privacy(?:\/retention-preview)?|evaluations|usability|governance\/audit)(?:\?[a-zA-Z0-9=&-]+)?$/.test(path);
  if (method !== 'POST') return false;
  return /^\/api\/(admin\/(login|verify|logout|register(?:\/(verify|cancel|qr))?|downloads\/scan|registrations\/[a-z0-9._-]+\/(approve|reject)|accounts\/[a-z0-9._-]+\/(role|disable))|overrides(?:\/[a-zA-Z0-9-]+\/deactivate)?|reports\/monthly\/(generate|20\d{2}-(0[1-9]|1[0-2])\/send)|alerts\/[a-zA-Z0-9-]+\/status|cases(?:\/[a-zA-Z0-9-]+\/(notes|status))?|privacy(?:\/retention-apply)?|evaluations|usability(?:\/[a-zA-Z0-9-]+\/status)?)$/.test(path);
}
export function apiError(status, body) {
  if (status === 401) return 'Sign-in or verification was not accepted. Check your credentials; expired sessions need a new sign-in.';
  if (status === 403) return /High-risk threat is blocked|device is blocked|Link this Chrome profile|Add this device|Pairing code|device is waiting|device connection was revoked/.test(body?.detail??'')?body.detail:'Your account does not have permission for this action.';
  if (status === 429) return 'Too many requests. Wait one minute and try again.';
  if (status === 503 && /OPENAI|OLLAMA|LLM|report model|API key/i.test(body?.detail ?? '')) return 'AI reporting is unavailable. Check the configured local model or provider settings on the backend.';
  if (Array.isArray(body?.detail)) return body.detail.map(r => `${r.loc?.at(-1) ?? 'Input'}: ${r.msg}`).join(' · ');
  return typeof body?.detail === 'string' ? body.detail : `The service could not complete this request (${status}).`;
}
