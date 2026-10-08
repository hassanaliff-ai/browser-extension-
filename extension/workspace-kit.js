import {escapeHtml as esc} from './core.js';

export function validateReportPeriod(kind,value,now=new Date()) {
  const month=/^20\d{2}-(0[1-9]|1[0-2])$/;
  if(kind==='monthly'){
    if(!month.test(value)||value>=now.toISOString().slice(0,7))throw new Error('Select a completed month in UTC.');
    return value;
  }
  if(kind!=='weekly'||!/^20\d{2}-(0[1-9]|1[0-2])-\d{2}$/.test(value))throw new Error('Choose a completed week beginning on Monday in UTC.');
  const start=new Date(value+'T00:00:00Z');
  if(!Number.isFinite(start.getTime())||start.toISOString().slice(0,10)!==value||start.getUTCDay()!==1||start.getTime()+7*86400000>now.getTime())throw new Error('Choose a completed week beginning on Monday in UTC.');
  return value;
}

export function requestedRole(profile,request) {
  return (profile?.approvable_roles??[]).includes(request?.role)?request.role:'';
}

export function updateAccountReview(form,profile,requests) {
  if(form?.dataset.form!=='account-review')return;
  const username=form.querySelector('[name="username"]')?.value;
  const role=form.querySelector('[name="role"]');
  if(role){const value=requestedRole(profile,requests.find(row=>row.username===username));if(value)role.value=value;}
  // A review of one person cannot carry an identity confirmation to another.
  const confirmed=form.querySelector('[name="confirmed"]');if(confirmed)confirmed.checked=false;
  const reason=form.querySelector('[name="reason"]');if(reason)reason.value='';
}

export function resetDestinationReview(form) {
  if(form?.dataset.form!=='access-review')return;
  const confirmed=form.querySelector('[name="confirmed"]');if(confirmed)confirmed.checked=false;
  const reason=form.querySelector('[name="reason"]');if(reason)reason.value='';
}

export function filterRecords(container,query) {
  const rows=Array.from(container?.querySelectorAll('tbody tr')??[]);
  const key=String(query).trim().toLocaleLowerCase();
  let visible=0;
  for(const row of rows){row.hidden=!row.textContent.toLocaleLowerCase().includes(key);if(!row.hidden)visible++;}
  return {visible,total:rows.length};
}

export function connectionBadge(status='unchecked') {
  const label={ready:'API connected',offline:'API unavailable',checking:'Checking API…',unchecked:'Check API connection'}[status]??'Check API connection';
  return `<button type="button" class="connection-chip ${esc(status)}" data-action="check-connection" aria-label="Check API connection"><span class="dot" aria-hidden="true"></span><span>${esc(label)}</span></button>`;
}

export function connectionPanel(status='unchecked') {
  return `<section class="panel stack"><div class="row between"><h2>Connection and recovery</h2><div data-connection-badge>${connectionBadge(status)}</div></div><p class="muted">Check the existing local API before running scans or generating reports.</p><ol class="recovery-steps"><li>Run Start ExtSecure.cmd from your installed project folder.</li><li>Reload ExtSecure on chrome://extensions after an update, then reopen its console.</li><li>Sign in with your approved account and authenticator. Add this Chrome device if requested.</li></ol><p class="meta">A connected API does not guarantee provider availability or a safe result.</p><p class="code">http://127.0.0.1:8765</p></section>`;
}

export function safeActiveTab(tab) {
  try{const url=new URL(tab?.url);if(!['https:','http:'].includes(url.protocol)||url.username||url.password)return {url:'',host:''};return {url:url.href,host:url.hostname};}
  catch{return {url:'',host:''};}
}
