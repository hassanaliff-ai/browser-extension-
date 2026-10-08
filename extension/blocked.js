import {escapeHtml as esc} from './core.js';
import {send,previewNotice} from './transport.js';
import {LANGUAGES,TIME_ZONES,THEMES,getPreferences,setPreferences,translate,observeLocalization} from './locale.js';
const app=document.querySelector('#app');
let context={},state={},busy=false;
const opts=(rows,value)=>rows.map(([key,label])=>`<option value="${esc(key)}" ${key===value?'selected':''}>${esc(label)}</option>`).join('');
function render(error=''){
 const prefs=getPreferences();
 app.innerHTML=previewNotice+`<main id="main" class="blocked-layout"><section class="blocked-card stack"><div class="brand"><img src="icons/brand.svg" alt=""><div>ExtSecure<small>Browser security</small></div></div><div class="blocked-emblem" aria-hidden="true"><svg width="38" height="38" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M5 10h14v12H5z M8 10V6c0-6 8-6 8 0v4 M12 15v3"/></svg></div><div class="eyebrow">Website approval required</div><h1>This website is blocked</h1><p class="muted">The website stays blocked until an approved visit is opened.</p>${context.target?`<div class="blocked-destination"><div class="meta">Destination</div><bdi class="code">${esc(context.target)}</bdi></div>`:''}${error?`<div class="notice error" role="alert">${esc(error)}</div>`:''}${context.target?context.signed_in?context.allowed?`<div class="notice success">Visit approval is ready.</div><button class="btn primary" data-action="open">Open approved website</button>`:`<div class="notice warning">${context.role==='head_administrator'?'You may review your own request. Submit it, then open the approval queue.':'Waiting for approval by a higher role.'}</div><form class="form" data-form="request"><label class="field"><span>Request reason</span><textarea name="reason" required minlength="8" maxlength="1000"></textarea></label><button class="btn primary" type="submit">Request access</button></form>`:`<div class="notice">Sign in to request access</div><button class="btn primary" data-action="sign-in">Sign in</button>`:''}<div class="row"><button class="btn" data-action="refresh">Check approval</button><button class="btn ghost" data-action="queue">Open approval queue</button></div><p class="meta">Temporary approval allows repeat visits for 24 hours or 7 days. After expiry, request access again. Forever adds the URL to the shared whitelist until revoked.</p><p class="meta">The exact scheme, host, port and path are approved. Query strings and fragments are not stored in approval requests.</p><details><summary>Appearance, language and time</summary><form class="form" data-form="preferences"><div class="fields appearance-fields"><label class="field"><span>Appearance</span><select name="theme">${opts(THEMES,prefs.theme)}</select></label><label class="field"><span>Language</span><select name="language">${opts(LANGUAGES,prefs.language)}</select></label><label class="field"><span>Time zone</span><select name="timeZone">${opts(TIME_ZONES,prefs.timeZone)}</select></label></div><button class="btn small" type="submit">Save preferences</button></form></details></section></main>`;
}
async function refresh(){state=await send({type:'STATE'});context=await send({type:'BLOCKED_STATE'});render();if(context.allowed&&['whitelist','temporary'].includes(context.kind))await send({type:'OPEN_APPROVED'});}
async function action(task){if(busy)return;busy=true;app.querySelectorAll('button').forEach(el=>el.disabled=true);try{await task();}catch(error){render(error.message);}finally{busy=false;app.querySelectorAll('button').forEach(el=>el.disabled=false);}}
app.addEventListener('click',event=>{const button=event.target.closest('[data-action]');if(!button)return;void action(async()=>{
 if(button.dataset.action==='refresh')await refresh();
 if(button.dataset.action==='sign-in')await send({type:'OPEN_CONSOLE',view:'account'});
 if(button.dataset.action==='queue')await send({type:'OPEN_CONSOLE',view:'access'});
 if(button.dataset.action==='open')await send({type:'OPEN_APPROVED'});
});});
app.addEventListener('submit',event=>{event.preventDefault();const f=event.target,data=Object.fromEntries(new FormData(f));void action(async()=>{
 if(f.dataset.form==='preferences'){setPreferences(await send({type:'SAVE_PREFERENCES',preferences:{...getPreferences(),...data}}));render();}
 if(f.dataset.form==='request'){
   await send({type:'API',path:'/api/access/requests',method:'POST',body:{target:context.target,reason:data.reason}});
   render();const toast=document.querySelector('#toast');toast.textContent=translate('Access request sent. The website remains blocked until approval.');toast.hidden=false;
 }
});});
observeLocalization();
try{if(window.top!==window.self)throw new Error('Open the blocked website in its own browser tab.');setPreferences(await send({type:'PREFERENCES'}));await refresh();}catch(error){render(error.message);}
