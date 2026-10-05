export const API_ORIGIN = 'http://127.0.0.1:8765';
export const VERSION = '0.6.0';
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
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  new Uint8Array(bytes).fill(0);
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2,'0')).join('');
}
export function validDigest(value) {
  if (!/^[a-f0-9]{64}$/i.test(value.trim())) throw new Error('Enter a 64-character SHA-256 file hash.');
  return value.trim().toLowerCase();
}
export function safeApiPath(path, method = 'GET') {
  if(method==='GET'&&/^\/api\/intelligence\/(scans\/[a-zA-Z0-9-]+|reports(?:\?limit=\d{1,3})?)$/.test(path))return true;
  if(method==='POST'&&/^\/api\/intelligence\/(scans\/[a-zA-Z0-9-]+\/explain|reports\/generate)$/.test(path))return true;
  if (method === 'GET' && /^\/api\/access\/(requests|whitelist)$/.test(path)) return true;
  if (method === 'POST' && /^\/api\/access\/(requests(?:\/[a-zA-Z0-9-]+\/review)?|whitelist\/[a-zA-Z0-9-]+\/revoke|check|consume)$/.test(path)) return true;
  if (method === 'GET') return /^\/api\/(admin\/(me|accounts|registrations)|overview|risk-policy|devices|extensions|findings|scans(?:\/[a-zA-Z0-9-]+)?|my\/scans(?:\/[a-zA-Z0-9-]+)?|overrides(?:\/audit)?|reports\/monthly(?:\/(stats|ml))?|alerts|events|cases(?:\/[a-zA-Z0-9-]+)?|case-assignees|policies|privacy(?:\/retention-preview)?|evaluations|usability|governance\/audit)(?:\?[a-zA-Z0-9=&-]+)?$/.test(path);
  if (method !== 'POST') return false;
  return /^\/api\/(admin\/(login|verify|logout|register(?:\/(verify|cancel|qr))?|downloads\/scan|registrations\/[a-z0-9._-]+\/(approve|reject)|accounts\/[a-z0-9._-]+\/(role|disable))|overrides(?:\/[a-zA-Z0-9-]+\/deactivate)?|reports\/monthly\/(generate|20\d{2}-(0[1-9]|1[0-2])\/send)|alerts\/[a-zA-Z0-9-]+\/status|cases(?:\/[a-zA-Z0-9-]+\/(notes|status))?|policies(?:\/[a-zA-Z0-9-]+\/(review|activate))?|privacy(?:\/retention-apply)?|evaluations|usability(?:\/[a-zA-Z0-9-]+\/status)?)$/.test(path);
}
export function apiError(status, body) {
  if (status === 401) return 'Sign-in or verification was not accepted. Check your credentials; expired sessions need a new sign-in.';
  if (status === 403) return 'Your account does not have permission for this action.';
  if (status === 429) return 'Too many requests. Wait one minute and try again.';
  if (status === 503 && /OPENAI|LLM|report model|API key/i.test(body?.detail ?? '')) return 'AI reporting is not configured. Ask the administrator to configure the report model and API key on the backend.';
  if (Array.isArray(body?.detail)) return body.detail.map(r => `${r.loc?.at(-1) ?? 'Input'}: ${r.msg}`).join(' · ');
  return typeof body?.detail === 'string' ? body.detail : `The service could not complete this request (${status}).`;
}
