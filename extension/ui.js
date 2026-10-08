import {avatar,prepareLogo} from './account-logo.js';

import {explanationForm,runExplanation,intelligenceReports,runPeriodReport,downloadPeriodReport,changePeriodInput} from './intelligence-ui.js';

import {connectionBadge,connectionPanel,filterRecords,requestedRole,updateAccountReview,resetDestinationReview} from './workspace-kit.js';

import {updateAccessDecision} from './review-controls.js';

import {lookupFeedback} from './scan-feedback.js';

import {consoleNavigation,filterConsoleNavigation,toggleConsoleNavigation} from './console-navigation.js';

import {THEMES,resolvedTheme} from './theme.js';

import {escapeHtml as esc,SEVERITIES,roleCanWrite,completedMonth,reportPeriod,hashFile,validDigest,privateTarget,VERSION,reviewableAccessRequests,accessReviewBody} from './core.js';

import {send,isExtension,previewNotice,inventoryCompatibility,restartExtension} from './transport.js';

import {TABLE_SIZES,LANGUAGES,TIME_ZONES,setPreferences,getPreferences,formatDate,formatNumber,translate,observeLocalization} from './locale.js';



const popup=document.body.classList.contains('popup');

const app=document.querySelector('#app');

let state={},view='',authMode='login',qr='',manualSecret='',pageData={},selected='',period=completedMonth(),scanResult=null,requestSequence=0,busy=false,loading=false,queuedView='';

let devicePairing=null,deviceFilter='all',connectionStatus='unchecked',toastTimer,monthlyOpen=false;

async function checkConnection(silent=false){

 connectionStatus='checking';paintConnection();

 try{connectionStatus=(await send({type:'HEALTH'})).status;}catch{connectionStatus='offline';}

 paintConnection();if(!silent)toast(connectionStatus==='ready'?'The local API is reachable. Provider checks may still be unavailable.':'The API is unavailable. Run Start ExtSecure.cmd, then check again.',connectionStatus!=='ready');

}

function paintConnection(){for(const element of app.querySelectorAll?.('[data-connection-badge]')??[])element.innerHTML=connectionBadge(connectionStatus);}

const ICONS={shield:'M12 3l8 3v6c0 5-5 8-8 10-3-2-8-5-8-10V6z M8 12l3 3 5-6',grid:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',alert:'M12 3l10 18H2z M12 9v5 M12 18h.01',search:'M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16 M16 16l6 6',file:'M6 2h8l5 5v15H6z M14 2v6h5 M9 13h7 M9 17h7',clock:'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20 M12 6v6l4 2',device:'M3 4h18v13H3z M8 21h8 M12 17v4',extension:'M4 4h5c-2-5 8-5 6 0h5v5c5-2 5 8 0 6v5h-5c2-5-8-5-6 0H4z',chart:'M3 3v18h18 M7 15l5-6 4 3 5-8',check:'M5 12l4 4 10-10',arrow:'M5 12h14 M14 7l5 5-5 5',users:'M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8 M2 21v-3c0-6 14-6 14 0v3 M17 4c5 0 5 7 0 7 M18 15c4 0 4 3 4 6',case:'M3 7h18v14H3z M8 7V3h8v4 M3 12h18 M10 12v3h4v-3',sliders:'M4 3v18 M12 3v18 M20 3v18 M1 8h6 M9 16h6 M17 10h6',lock:'M5 10h14v12H5z M8 10V6c0-6 8-6 8 0v4 M12 15v3',help:'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20 M9 8c0-4 8-4 6 1l-3 3v2 M12 18h.01',logout:'M9 3H3v18h6 M9 12h12 M17 8l4 4-4 4',refresh:'M20 8A9 9 0 1 0 20 16 M20 2v6h-6',download:'M12 3v12 M7 10l5 5 5-5 M3 17v4h18v-4',globe:'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20 M2 12h20 M12 2c-5 6-5 14 0 20 M12 2c5 6 5 14 0 20'};

const icon=name=>`<svg class="icon" aria-hidden="true" viewBox="0 0 24 24"><path d="${ICONS[name]??ICONS.shield}"/></svg>`;

const brand=()=>'<div class="brand"><img src="icons/brand.svg" alt=""><div>ExtSecure<small>Browser security</small></div></div>';

const tag=value=>`<span class="tag ${esc(String(value??'Unknown').toLowerCase().replace(/[^a-z_]/g,''))}"><span class="dot"></span>${esc(value??'Unknown')}</span>`;

const btn=(text,action='',cls='',attrs='')=>`<button class="btn ${cls}" ${action?`data-action="${esc(action)}"`:''} ${attrs}>${esc(text)}</button>`;

const notice=(text,type='',preserve=false)=>`<div class="notice ${type}"${preserve?' data-no-translate':''}>${esc(text)}</div>`;

const evidence=value=>`<span data-no-translate>${esc(value)}</span>`;

const empty=(title='No records yet',text='Completed checks will appear here with their evidence and next steps.')=>`<div class="empty">${icon('shield')}<h3>${esc(title)}</h3><p>${esc(text)}</p></div>`;

const field=(label,name,type='text',value='',attrs='')=>`<label class="field"><span>${esc(label)}</span><input name="${name}" type="${type}" value="${esc(value)}" ${attrs}></label>`;

const textarea=(label,name,value='',attrs='')=>`<label class="field"><span>${esc(label)}</span><textarea name="${name}" ${attrs}>${esc(value)}</textarea></label>`;

const options=(rows,current)=>rows.map(row=>{const [value,label]=Array.isArray(row)?row:[row,row];return `<option value="${esc(value)}" ${value===current?'selected':''}>${esc(label)}</option>`;}).join('');

const select=(label,name,rows,current='',attrs='')=>`<label class="field"><span>${esc(label)}</span><select name="${name}" ${attrs}>${options(rows,current)}</select></label>`;

const reason=()=>textarea('Decision reason','reason','','required minlength="8" maxlength="2000" placeholder="Record the evidence and why this action is appropriate."');

const check=(text,name,checked=false,required=false)=>`<label class="check"><input type="checkbox" name="${name}" ${checked?'checked':''} ${required?'required aria-required="true"':''}>${esc(text)}</label>`;

const form=(action,content,submit='Save change',cls='primary')=>`<form class="form" data-form="${action}">${content}<div class="notice error form-error" role="alert" tabindex="-1" hidden></div><div>${btn(submit,'',cls,'type="submit"')}</div></form>`;

const details=(title,content)=>`<details><summary>${esc(title)}</summary>${content}</details>`;

const number=formatNumber;

const date=formatDate;

const short=value=>String(value??'').length>38?String(value).slice(0,35)+'…':String(value??'—');

const json=value=>esc(JSON.stringify(value,null,2));

const api=(path,method='GET',body)=>send({type:'API',path:'/api/'+path,method,body});

const can=area=>roleCanWrite(state.profile,area);

const table=(rows,columns,extra='')=>!Array.isArray(rows)||!rows.length?empty('Nothing to review',extra||'No records are available for this selection.'):`<div class="table-block"><div class="table-controls">${select('Table size','tableSize',TABLE_SIZES,getPreferences().tableSize,'data-table-size')}</div><div class="table-wrap"><table><thead><tr>${columns.map(([label])=>`<th scope="col">${label}</th>`).join('')}</tr></thead><tbody>${rows.map(r=>`<tr>${columns.map(([,key])=>`<td>${typeof key==='function'?key(r):evidence(typeof r[key]==='object'?JSON.stringify(r[key]):r[key]??'—')}</td>`).join('')}</tr>`).join('')}</tbody></table></div></div>`;

const metrics=rows=>`<div class="metrics ${rows.length===3?'three':''}">${rows.map(([label,value,note,i])=>`<div class="metric"><div class="metric-top"><span>${esc(label)}</span>${icon(i??'chart')}</div><strong>${number(value)}</strong><small>${esc(note??'Recorded results')}</small></div>`).join('')}</div>`;

const VIEWS=[

 ['overview','Overview','grid','Monitor','A clear view of browser risk and the decisions that need attention.'],

 ['scan','Scan a page','globe','Monitor','Check a web destination without sending query strings or fragments.'],

 ['alerts','Alerts','alert','Monitor','Review high-severity threats and document the response.'],

 ['findings','Findings','search','Monitor','Inspect confirmed signals and the evidence behind each score.'],

 ['risks','Risk levels','chart','Monitor','Understand the active policy and how confirmed signals affect severity.'],

 ['files','Downloaded-file checks','file','Monitor','Calculate SHA-256 in the extension; send only the file hash for lookup.'],

 ['history','Scan history','clock','Monitor','Follow past checks, assessment completeness and recorded decisions.'],

 ['devices','Devices','device','Inventory','Register devices, link Chrome profiles and manage blocked access.'],

 ['extensions','Extensions','extension','Inventory','Sync enabled Chrome extensions and inspect their device inventory.'],

 ['events','Security events','clock','Investigate','Trace scans, threats, alert decisions and notification delivery.'],

 ['cases','Incident cases','case','Investigate','Assign an investigation, record evidence and track it through resolution.'],

 ['access','Website access','globe','Investigate','Request website access or review approvals before a blocked page can open.'],

 ['overrides','Whitelist & overrides','check','Investigate','Manage controlled exceptions while preserving the original risk evidence.'],

 ['reports','Reports','chart','Investigate','Review weekly and monthly reports, aggregate statistics and machine-learning evidence.'],

 ['policies','Security policies','sliders','Govern','Draft scoring changes, request independent review and activate approved policies.'],

 ['privacy','Privacy governance','lock','Govern','Define collection rules, access and retention for security evidence.'],

 ['evaluation','Detection evaluation','search','Govern','Compare scoring against labelled scenarios and examine incorrect outcomes.'],

 ['usability','Usability and accessibility','users','Govern','Record walkthroughs, accessibility issues and verified fixes.'],

 ['accounts','Accounts','users','Govern','Approve registrations and assign each account the minimum appropriate access.'],

 ['guidance','Security guidance','help','Support','Understand findings and choose a sensible next action.'],

 ['settings','Settings','sliders','Support','Personalize the extension appearance, language and display times.'],

 ['account','My account','lock','Support','Review your assigned role and current verified session.'],

 ['myhistory','My file history','clock','Support','Review only the checks submitted through your own account.'],

];

function inventoryRecovery(){const i=state.profile?.inventory;return i?.pending||i?.blocked||(i?.enrollment_required&&!i?.linked);}

function allowedViews(){return VIEWS.filter(([key,label])=>inventoryRecovery()?['account','settings',...(can('inventory')?['devices','extensions']:[])].includes(key):key==='settings'?true:key==='scan'?can('scan'):state.profile?.views?.includes(label));}

function devicePairForm(){return isExtension?form('device-pair',field('One-time device pairing code','code','text','','required minlength="20" maxlength="100" autocomplete="off"'),'Link this Chrome profile'):notice('Device pairing requires loading ExtSecure in Chrome.','warning');}

function deviceConnection(){

 const i=state.profile?.inventory??{};

 const compatibility=inventoryCompatibility(state);

 if(isExtension&&!compatibility.ready)return `<section class="panel stack"><h2>Update the Chrome connection</h2>${notice('Chrome is running an older ExtSecure worker. Restart the extension to enable device and extension connection.','warning')}<p class="meta">${esc('Console '+compatibility.ui_version+' · Worker '+compatibility.worker_version)}</p>${btn('Restart ExtSecure','restart-extension','primary')}<p class="muted">After restarting, close this console tab, reopen ExtSecure from the Chrome extension icon and sign in. Device records stay saved.</p><p class="meta">${esc('Load the extension folder: C:\\Users\\hassa\\browser-extension-\\extension')}</p></section>`;

 const message=i.pending?'Device added. Waiting for administrator approval.':i.blocked?'This device is blocked. An administrator must unblock it before scans or website access can continue.':i.linked?'This Chrome profile is connected.':'Add this device to connect Chrome inventory automatically.';

 const optional=details('Optional device details',`<div class="fields">${field('Device name (optional)','name','text','','maxlength="120" placeholder="Automatically named"')}${field('IP address (optional)','ip_address','text','','maxlength="45" placeholder="Enter a LAN IP if needed"')}</div>`);

 const initialAccess=i.linked?'':select('Device access before adding','initial_access',[['','Choose device access'],['trusted','Trusted device'],['blocked','Blocked device']],'','required')+notice(can('inventory')?'Trusted device allows ExtSecure activity. Blocked device records this device but denies scans and website access until an administrator allows it.':'Trusted device requests administrator approval. Blocked device records this device with access denied until an administrator allows it.');

 const connect=isExtension&&!i.blocked&&!i.pending?form('device-connect',initialAccess+optional,i.linked?'Refresh devices & extensions':'Add this device'):'';

 if(isExtension&&i.linked&&!i.blocked&&!i.pending)return `<section class="panel stack"><div class="row between"><div><h2>Device & Chrome connection</h2><p class="meta" data-no-translate>${esc(i.device_name??'')}</p></div>${tag('Connected')}</div><div>${btn('Connect enabled Chrome extensions','sync-inventory')}</div>${details('Connection details',`<div class="stack">${connect}<p class="meta">Only enabled extension IDs, names and versions are synced.</p>${details('Existing device connection (advanced)',devicePairForm())}</div>`)}</section>`;

 return `<section class="panel stack"><h2>Device & Chrome connection</h2>${notice(message,i.blocked?'error':i.pending?'warning':i.linked?'success':'')}${i.linked?`<p class="meta" data-no-translate>${esc(i.device_name)}</p>`:''}${connect}${isExtension&&i.linked&&!i.blocked&&!i.pending?btn('Connect enabled Chrome extensions','sync-inventory','primary'):''}${i.pending?btn('Check approval status','refresh'):''}${i.blocked&&can('inventory')?btn('Manage device access','go-devices'):''}<p class="muted">Add this device registers this Chrome profile and ExtSecure first. Then click Connect enabled Chrome extensions and allow Chrome's permission prompt to include the other enabled extensions. The operating system is detected automatically.</p><p class="meta">IP is optional. Localhost is not saved as your computer's LAN address. Only enabled extension IDs, names and versions are synced.</p>${!isExtension?notice('Load ExtSecure in Chrome to add this device.','warning'):''}${isExtension?details('Existing device connection (advanced)',devicePairForm()):''}</section>`;

}

async function devicesPage(){

 const rows=await api('devices');pageData={rows};const registered=rows.filter(r=>r.registered),shown=registered.filter(r=>deviceFilter==='all'||(deviceFilter==='blocked'?r.blocked:deviceFilter==='pending'?r.pending:!r.blocked&&!r.pending));

 const columns=[['Device','name'],['Requested by','requested_by'],['IP address',r=>r.ip_address?evidence(r.ip_address)+`<div class="meta">${esc(translate(r.ip_source))}</div>`:esc(translate('Not provided'))],['Operating system','operating_system'],['Status',r=>tag(r.status)],['Scans','scan_count'],['Highest risk',r=>tag(r.highest_severity)],['Last sync',r=>esc(date(r.last_sync))]];

 return metrics([['Registered devices',registered.length,'Managed inventory','device'],['Pending approval',registered.filter(r=>r.pending).length,'Administrator review needed','users'],['Blocked devices',registered.filter(r=>r.blocked).length,'Backend access denied','lock']])+deviceConnection()+`<section class="panel stack"><div class="row between"><h2>Device inventory</h2>${select('Show devices','device_filter',[['all','All devices'],['pending','Pending approval'],['active','Active devices'],['blocked','Blocked devices']],deviceFilter)}</div>${table(shown,columns,'Click Add this device on the computer you want to connect.')}</section>${can('inventory')&&registered.length?`<section class="panel stack"><h2>Manage device access</h2>${form('device-status',select('Device','device_id',registered.map(r=>[r.id,r.name+' · '+r.status]))+select('Device access','blocked',[['false','Allow device'],['true','Block device']])+reason(),'Save device access')}<p class="meta">Allow device approves a pending request or unblocks a device. Block device denies ExtSecure scans and website approvals.</p>${details('Advanced connection recovery',form('device-code',select('Device','device_id',registered.map(r=>[r.id,r.name]))+reason(),'Issue new pairing code','small'))}${devicePairing?`<div class="stack">${field('One-time pairing code','pairing_code','text',devicePairing.pairing_code,'readonly autocomplete="off" data-no-translate')}<p class="meta">${esc(date(devicePairing.expires_at))}</p></div>`:''}</section>`:''}${rows.some(r=>!r.registered)?details('Older scan records',table(rows.filter(r=>!r.registered),[['Device','name'],['Scans','scan_count'],['Highest risk',r=>tag(r.highest_severity)]])):''}`;

}

async function extensionsPage(){const rows=await api('extensions');pageData={rows};return deviceConnection()+`<section class="panel stack"><h2>Chrome enabled extension inventory</h2>${notice('Snapshots update after extension changes, at sign-in and every 30 minutes while signed in, after permission is granted. Older scan records remain labelled Unverified. Inventory metadata is not a malware verdict.')} ${table(rows,[['Extension','name'],['Chrome extension ID','extension_key'],['Version','version'],['Device','device_name'],['Status',r=>tag(r.status)],['Source','source'],['Last sync',r=>esc(date(r.last_sync))],['Scans','scan_count'],['Highest risk',r=>tag(r.highest_severity)]])}</section>`;}

function toast(text,error=false){const el=document.querySelector('#toast');clearTimeout(toastTimer);el.textContent=text;el.className=error?'error':'';el.setAttribute?.('role',error?'alert':'status');el.hidden=false;toastTimer=setTimeout(()=>el.hidden=true,error?10000:6500);}

function shell(content){

  const item=VIEWS.find(r=>r[0]===view)??VIEWS[0];

  const nav=consoleNavigation(allowedViews(),view,icon);

  app.innerHTML=previewNotice+`<div class="workspace"><aside class="sidebar" aria-label="Extension navigation"><div class="console-brand-row">${brand()}${btn('Menu','toggle-navigation','small nav-toggle','aria-controls="console-nav" aria-expanded="false"')}</div>${nav}<div class="sidebar-account"><div class="row">${avatar(state.profile)}<div><strong>${esc(state.profile?.display_name)}</strong><div class="meta">${esc(state.profile?.role_label)}</div></div></div>${btn('Sign out','logout','ghost small')}</div></aside><div class="workspace-body"><header class="topbar"><div class="breadcrumbs"><span>Extension console</span><span>/</span><strong>${esc(item[1])}</strong></div><div class="row"><div data-connection-badge>${connectionBadge(connectionStatus)}</div>${tag('2FA verified')}${btn('Dark mode','toggle-theme','small',`data-theme-toggle aria-pressed="${resolvedTheme()==='dark'}"`)}${btn('Refresh','refresh','small')}${btn('Sign out','logout','small mobile-signout')}</div></header><main id="main" class="page" tabindex="-1"><div class="page-title"><div><div class="eyebrow">${item[3]} · ExtSecure</div><h1>${esc(item[1])}</h1><p>${esc(item[4])}</p></div>${view==='overview'&&can('scan')?btn('Check a page','go-scan','primary'):''}</div><div id="content" class="stack">${content}</div></main><footer class="footer"><span>ExtSecure ${VERSION} · ${translate('Chrome extension')}</span><span>${esc(getPreferences().timeZone)} · ${translate('Report periods')}: UTC</span></footer></div></div>`;

}

async function renderAuth(){

  const verifying=state.challenge,enrolling=state.enrollment;

  let content;

  if(enrolling){

    if(!qr)try{qr=(await send({type:'ENROLLMENT_QR'})).image;}catch(error){toast(error.message,true);}

    content=`<h1>Set up your authenticator</h1><p class="muted">Scan the QR code in your authenticator app, then verify a six-digit code.</p><div class="step"><span>02</span>Authenticator enrollment</div>${qr?`<img class="qr" src="${esc(qr)}" alt="Private QR code for ExtSecure authenticator enrollment">`:notice('Authenticator setup could not be loaded. Start registration again.','warning')}${manualSecret?details('Enter the setup key manually',`<p class="meta mb14">Use a time-based account named ExtSecure.</p><input aria-label="Authenticator setup key" value="${esc(manualSecret)}" readonly class="code" autocomplete="off">`):''}${form('register-verify',select('Requested role','role',[['normal_user','Normal user'],['manager','Manager'],['administrator','Administrator']])+field('Six-digit authenticator code','code','password','','required inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"'),'Verify account','primary full')}<p class="auth-aside">Setup expires after 15 minutes. Access requires approval by a higher role.</p>${btn('Cancel registration','reset-auth','ghost full')}`;

  }else if(verifying){

    content=`<h1>Verify it’s you</h1><p class="muted">Use the current code from your authenticator app to complete sign-in.</p><div class="step"><span>02</span>Password accepted · Authenticator required</div>${form('verify',field('Six-digit authenticator code','code','password','','required inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"'),'Verify and sign in','primary full')}${btn('Start sign-in again','reset-auth','ghost full')}<p class="auth-aside">The backend verifies both steps before granting access.</p>`;

  }else{

    const register=authMode==='register';

    content=`<h1>${register?'Create your account':'Welcome to ExtSecure'}</h1><p class="muted">${register?'Set up an account and authenticator, then request administrator approval.':'Sign in to your approved account to review browser security.'}</p><div class="tabs" role="group" aria-label="Account access">${['login','register'].map(mode=>`<button data-auth-mode="${mode}" class="${mode===authMode?'selected':''}" aria-pressed="${mode===authMode}">${mode==='login'?'Log in':'Register account'}</button>`).join('')}</div><div class="step"><span>01</span>${register?'Account details':'Your credentials'}</div>${form(register?'register':'login',field('Username','username','text','','required autocomplete="username" maxlength="80"'+(register?' pattern="[a-z0-9][a-z0-9._-]{2,79}"':''))+field('Password','password','password','','required autocomplete="'+(register?'new-password':'current-password')+'"'+(register?' minlength="12" maxlength="128"':''))+(register?field('Confirm password','confirm','password','','required autocomplete="new-password" minlength="12" maxlength="128"')+notice('Choose at least 12 characters. Select your requested role at the authenticator step. A higher role must approve it.') : ''),register?'Set up authenticator':'Continue securely','primary full')}<p class="auth-aside">${register?'No invitation code required.':'New accounts need approval. Every role uses password and authenticator verification.'}</p>`;

  }

  app.innerHTML=previewNotice+(popup?`<header class="popup-header">${brand()}</header>`:'')+`<div class="auth-layout"><aside class="auth-story">${brand()}<div><div class="eyebrow">A calmer view of browser security</div><h1>Clear signals.<br>Confident decisions.</h1><p>Check destinations, investigate threats and keep the evidence together in your browser.</p></div><div class="stack"><div class="auth-proof">${icon('lock')}Approved accounts. Two required sign-in steps.</div><div class="auth-proof">${icon('file')}Local file hashing. Backend-owned risk scores.</div></div></aside><main id="main" class="auth-content"><div class="auth-card"><div class="auth-mobile-brand">${brand()}</div>${content}<div class="preferences-inline"><div class="mb14" data-connection-badge>${connectionBadge(connectionStatus)}</div>${details('Appearance, language and time',preferencesForm())}</div></div></main></div>`;

}

function activity(rows=[]){return !rows.length?empty('No recent activity','New scans and security decisions will appear here.'): `<div class="activity-list">${rows.slice(0,5).map(r=>`<div class="activity-item"><div class="activity-icon">${icon(r.event_type==='threat_detected'?'alert':'shield')}</div><div><p data-no-translate>${esc(r.message)}</p><div class="meta">${esc(date(r.created_at))}</div></div>${tag(r.severity)}</div>`).join('')}</div>`;}

function chart(rows=[]){

  if(!rows.length)return empty('Activity is unavailable');

  const max=Math.max(1,...rows.map(r=>Math.max(r.scans,r.high_risk))),last=rows.length-1;

  const points=key=>rows.map((r,i)=>`${30+i*460/Math.max(1,last)},${110-Number(r[key]??0)*85/max}`).join(' ');

  return `<svg class="chart" viewBox="0 0 520 145" role="img" aria-label="${esc(rows.length+' days of scan activity. '+rows.reduce((t,r)=>t+r.scans,0)+' total scans; '+rows.reduce((t,r)=>t+r.high_risk,0)+' high risk.')}" preserveAspectRatio="xMidYMid meet"><line class="gridline" x1="30" y1="25" x2="490" y2="25"/><line class="gridline" x1="30" y1="68" x2="490" y2="68"/><line class="gridline" x1="30" y1="110" x2="490" y2="110"/><polyline class="mainline" points="${points('scans')}"/><polyline class="riskline" points="${points('high_risk')}"/><text x="30" y="135">${esc(rows[0].date)}</text><text x="490" y="135" text-anchor="end">${esc(rows[last].date)}</text><text x="4" y="28">${max}</text><text x="12" y="113">0</text></svg><div class="legend"><span><span class="dot"></span>All scans</span><span><span class="dot risk-dot"></span>High / Critical</span></div>`;

}

function severityRows(counts={}){const max=Math.max(1,...Object.values(counts).filter(Number.isFinite));return SEVERITIES.map(label=>`<div class="severity-row">${tag(label)}<svg class="bar" viewBox="0 0 100 6" preserveAspectRatio="none" aria-hidden="true"><rect class="bar-meter" width="${100*(counts[label]??0)/max}" height="6" fill="${label==='High'||label==='Critical'?'#b85964':label==='Medium'?'#ae6b50':label==='Unknown'?'#788e9f':'#4f9476'}"/></svg><strong>${number(counts[label]??0)}</strong></div>`).join('');}

async function overview(){

  const d=await api('overview'); pageData=d;

  return `${d.pending_alerts?`<div class="attention-strip"><span>Alerts need your review.</span>${btn('Review alerts','go-alerts','small')}</div>`:''}${metrics([['Total scans',d.total_scans,'Lifetime recorded checks','shield'],['High / Critical',d.high_risk,'Confirmed high-severity results','alert'],['Awaiting review',d.pending_alerts,'Open and acknowledged alerts','case'],['Devices seen',d.devices,`${number(d.extensions)} extension identities`,'device']])}${workflowActions()}<div class="grid2"><section class="panel"><div class="section-head"><h2>Activity over 14 days</h2><span class="meta">UTC · Recorded scans</span></div>${chart(d.daily_activity)}</section><section class="panel"><div class="section-head"><h2>Risk distribution</h2><span class="meta">All time</span></div>${severityRows(d.severity_counts)}</section></div><section class="panel"><div class="section-head"><h2>Recent security events</h2>${btn('View all','go-events','small ghost')}</div>${activity(d.recent_events)}</section><p class="overview-note">${d.total_scans?'The score reflects confirmed rules and available evidence. Low does not guarantee safety.':'There are no scans yet. Start with a page or downloaded file; its evidence will appear here.'}</p>`;

}

function resultCard(result,compact=false){

  pageData.inspectedScan=result;

  const feedback=lookupFeedback(result);

  if(compact){

    const findingContent=result.findings?.length?`<h3>Confirmed findings</h3><ul class="result-list">${result.findings.map(r=>`<li><strong data-no-translate>${esc(r.title)}</strong> · ${number(r.points)} points<br>${evidence(r.detail)}</li>`).join('')}</ul>`:'<p class="meta">This assessment found no confirmed signals in the checks performed.</p>';

    const metadata=`<div class="stack"><p class="code" data-no-translate>${esc(result.target_display)}</p>${!result.findings?.length?findingContent:''}<p class="meta"><span>Policy</span> <bdi data-no-translate>${esc(result.risk_policy_version??'—')}</bdi></p><p class="meta"><span>Reference</span> <bdi data-no-translate>${esc(result.id??'—')}</bdi></p><p class="meta">Risk is scored by the backend.</p>${feedback&&!feedback.warning?`<p class="meta">${esc(feedback.message)}</p>${feedback.cached?'<p class="meta">Cached reputation result</p>':''}`:''}${btn('Download scan evidence','download-scan','small')}</div>`;

    return `<section class="panel results compact-result stack risk-${esc(String(result.severity??'Unknown').toLowerCase())}" aria-label="Risk assessment"><div class="result-heading"><h2>Risk result</h2>${tag(result.severity)}</div><div class="result-score"><div class="score">${result.score===null||result.score===undefined?'—':number(result.score)}<small> / 100</small></div>${tag(result.completeness)}</div>${result.target_kind==='download'?`<p class="code" data-no-translate>${esc(result.target_display)}</p>`:''}${notice(result.suggested_action??'Review available evidence before proceeding.',result.severity==='High'||result.severity==='Critical'?'warning':'',true)}${result.findings?.length?findingContent:''}${result.unknown_codes?.length?notice('Unavailable checks: '+result.unknown_codes.join(', '),'warning'):''}${feedback?.warning?`<div class="notice ${feedback.warning?'warning':''}"><span>${esc(feedback.message)}</span>${feedback.retry?`<p class="meta"><span>Retry after</span> <bdi>${number(feedback.retry)}</bdi> <span>seconds.</span></p>`:''}${feedback.cached?'<p class="meta">Cached reputation result</p>':''}</div>`:''}${result.override_id?notice('An administrator exception applies. Original risk evidence remains recorded.','warning'):''}<p class="meta">${result.severity==='Unknown'?'No usable evidence was available for this assessment. Unknown is not a safe result.':'The score reflects confirmed rules and available evidence. Low does not guarantee safety.'}</p>${details('Scan details',metadata)}</section>${btn('Open evidence workspace','open-history','ghost full result-workspace')}`;

  }

  return `<section class="panel results stack risk-${esc(String(result.severity??'Unknown').toLowerCase())}" aria-label="Risk assessment"><div class="row between"><h2>Risk result</h2>${tag(result.severity)}</div><div class="row between"><div class="score">${result.score===null||result.score===undefined?'—':number(result.score)}<small> / 100</small></div><div>${tag(result.completeness)}<div class="meta mt14"><span>Policy</span> <bdi>${esc(short(result.risk_policy_version))}</bdi></div></div></div><p class="code">${esc(result.target_display)}</p>${notice(result.suggested_action??'Review available evidence before proceeding.',result.severity==='High'||result.severity==='Critical'?'warning':'',true)}<div>${result.findings?.length?`<h3>Confirmed findings</h3><ul class="result-list">${result.findings.map(r=>`<li><strong data-no-translate>${esc(r.title)}</strong> · ${number(r.points)} points<br>${evidence(r.detail)}</li>`).join('')}</ul>`:empty('No confirmed findings',result.severity==='Unknown'?'No usable evidence was available for this assessment. Unknown is not a safe result.':'This assessment found no confirmed signals in the checks performed.')}</div>${result.unknown_codes?.length?notice('Unavailable checks: '+result.unknown_codes.join(', '),'warning'):''}${feedback?`<div class="notice ${feedback.warning?'warning':''}"><span>${esc(feedback.message)}</span>${feedback.retry?`<p class="meta mt14"><span>Retry after</span> <bdi>${number(feedback.retry)}</bdi> <span>seconds.</span></p>`:''}${feedback.cached?'<p class="meta mt14">Cached reputation result</p>':''}</div>`:''}${result.override_id?notice('An administrator exception applies. Original risk evidence remains recorded.','warning'):''}<div class="status-rail"><span><span>Reference</span> <bdi>${esc(short(result.id))}</bdi></span><span>Risk is scored by the backend.</span></div><p class="meta">The score reflects confirmed rules and available evidence. Low does not guarantee safety.</p>${btn('Download scan evidence','download-scan','small ghost')}</section>${compact?btn('Open evidence workspace','open-history','dark full'):explanationForm(result)}`;

}

function fileForm(){return form('file-scan',`<div class="drop-zone">${icon('download')}<h3>Choose a downloaded file</h3><p class="meta">File contents stay here. Only SHA-256 goes to the backend.</p><input aria-label="Downloaded file" name="file" type="file"><p class="meta">Maximum 32 MiB · Nothing is uploaded automatically</p></div><div class="meta">Or paste an existing file hash</div>${field('SHA-256 hash','sha256','text','','placeholder="64 hexadecimal characters" autocomplete="off" maxlength="64"')}<p class="meta">The backend checks hash reputation with VirusTotal and records an explainable risk result.</p>`,'Check file hash','primary full');}

async function files(){return `<div class="grid-even"><section class="panel"><h2>File reputation check</h2>${fileForm()}</section><div class="stack">${scanResult?.target_kind==='download'?resultCard(scanResult):`<section class="panel stack"><h2>Before you open the file</h2>${notice('An unknown hash or unavailable lookup means Unknown. Never treat it as a clean file.','warning')}<p class="muted">Use a file you are authorized to check. Large files can be hashed separately and checked using their SHA-256 digest.</p>${btn('Review my history','go-myhistory','ghost')}</section>`}</div></div>`;}

function urlForm(value=''){return form('url-scan',field('Web address','target','url',value,'required placeholder="https://example.com/"')+check('Include the page path in the lookup. Query strings and fragments are always removed.','includePath')+notice('By default, only the site origin is checked. The cleaned address is sent through your backend to VirusTotal after you choose Check destination.')+'<div id="clean-target" class="meta code"></div>','Check destination','primary full');}

async function scan(){return `<div class="grid-even"><section class="panel"><h2>Check a web destination</h2>${urlForm()}</section><div class="stack">${scanResult?.target_kind==='url'?resultCard(scanResult):`<section class="panel stack"><h2>A private first step</h2>${notice('URL credentials are rejected. Only submitted destinations are reputation-checked. Approval requests keep the exact URL path, without query strings or fragments.')}<p class="muted">The toolbar popup can read the active page after you open the extension. New website visits are blocked before loading. Original destinations stay temporarily in browser memory; only explicit access requests reach the approval queue.</p></section>`}</div></div>`;}

const scanColumns=[['Destination','target_display'],['Risk',r=>tag(r.severity)],['Score',r=>r.score===null?'—':number(r.score)],['Assessment',r=>tag(r.completeness)],['Checked',r=>esc(date(r.created_at))],['Evidence',r=>btn('Inspect','inspect-scan','small',`data-id="${esc(r.id)}"`)]];

async function listPage(path,columns){const data=await api(path);pageData={rows:data};return `<section class="panel"><div class="section-head"><h2>Recorded results</h2><input id="filter" class="filter" type="search" aria-label="Filter recorded results" placeholder="Filter results…" aria-controls="records-table" aria-describedby="filter-count"></div><div id="records-table">${table(data,columns)}</div><p id="filter-count" class="meta mt14" role="status" aria-live="polite"><span>${number(data.length)}</span> <span>records returned</span></p><div id="filter-empty" hidden>${empty('No matching results','Change the search text to see more recorded results.')}</div><p class="meta">Filtering searches only the records returned in this view.</p></section>`;}

function selectRows(label,rows,current){return select(label,'selected',rows.map(r=>[r.id,`${short(r.title??r.target_display??r.username??r.id)} · ${r.status??r.severity??''}`]),current,'data-select-record');}

async function alerts(){const rows=await api('alerts');pageData={rows};const row=rows.find(r=>r.id===selected)??rows[0];selected=row?.id??'';return `<section class="panel">${table(rows,[['Threat','message'],['Risk',r=>tag(r.severity)],['Status',r=>tag(r.status)],['Detected',r=>esc(date(r.created_at))]])}</section>${row?`<section class="panel stack"><h2>Review an alert</h2>${selectRows('Alert',rows,selected)}${notice('Delivery outcomes are recorded under Security events. Changing status does not resend notifications.')}${row.status==='suppressed'?notice('This alert is suppressed by an administrator exception. Review the exception before running a new check.','warning'):can('alerts')?form('alert-status',select('New status','status',['open','acknowledged','resolved'],row.status)+reason(),'Record alert decision'):notice('Your role has view-only access.')}</section>`:''}`;}

async function scanHistory(personal=false){const path=personal?'my/scans':'scans';const content=await listPage(path,scanColumns);pageData.personal=personal;return content;}

async function risks(){const d=await api('risk-policy');pageData=d;return `<div class="grid-even"><section class="panel stack"><h2>Severity levels</h2>${table(d.severity_bands,[['Risk',r=>tag(r.severity)],['Minimum','min_score'],['Maximum','max_score']])}${notice('Unknown means that no check could be assessed. It is separate from Low risk.','warning')}</section><section class="panel stack"><h2>How the score works</h2><p>Only confirmed signals contribute points. The backend caps the score at 100 and preserves missing checks in assessment completeness.</p><p class="meta">Policy ${esc(d.version)}</p>${btn('Review security policies','go-policies','ghost')}</section></div><section class="panel"><h2>Points per confirmed signal</h2>${table(d.signals,[['Signal','title'],['Points','points'],['Explanation','description']])}</section>`;}

function websiteWhitelistPanel(entries,permanentOnly=false){

 const whitelist=permanentOnly?entries.filter(r=>r.permanent):entries;

 return `<section class="panel stack"><h2>${permanentOnly?'Permanent website whitelist':'Approved URL whitelist'}</h2>${permanentOnly?notice('Forever website approvals appear here and in Website access. Revoking an entry updates both views. Website access approval does not suppress threat alerts or change risk scores.'):''}${table(whitelist,[['Destination',r=>`<bdi class="code">${esc(r.target)}</bdi>`],['Reviewed by','reviewer'],['Reason','reason'],['Expires',r=>r.permanent?esc(translate('Forever')):esc(date(r.expires_at))]])}${can('access')&&whitelist.length?details('Revoke whitelist entry',form('access-revoke',select('Select whitelist entry','entry_id',whitelist.map(r=>[r.id,r.target]))+reason(),'Revoke access','danger')):''}</section>`;

}

async function overrides(){const [rows,audit,whitelist]=await Promise.all([api('overrides'),api('overrides/audit'),api('access/whitelist')]);pageData={rows};const row=rows.find(r=>r.id===selected)??rows[0];selected=row?.id??'';return `${websiteWhitelistPanel(whitelist,true)}<section class="panel stack">${notice('Exceptions change notification handling. They do not lower a score or erase the original finding.','warning')}${table(rows,[['Type','kind'],['Destination','target_display'],['Reason','reason'],['State',r=>tag(r.effective?'active':r.active?'expired':'inactive')],['Expires',r=>r.permanent?esc(translate('Forever')):esc(date(r.expires_at))]])}${details('Add a controlled exception',form('override-create',select('Match type','kind',['domain','url'])+field('Exact URL or domain','target','text','','required maxlength="4096"')+field('Expiry (UTC)','expires_at','datetime-local','','required')+reason(),'Save exception'))}${row?details('Deactivate an exception',selectRows('Exception',rows,selected)+form('override-deactivate',check('Deactivate this exception. Original risk evidence stays recorded.','confirmed'),'Deactivate exception','danger')):''}</section><section class="panel"><h2>Exception audit trail</h2>${table(audit,[['Action','action'],['Administrator','actor'],['Reason',r=>esc(r.details?.reason??'—')],['Time',r=>esc(date(r.created_at))]])}</section>`;}

async function reports(){const p=reportPeriod(period);const [stats,rows]=await Promise.all([api(`reports/monthly/stats?year=${p.year}&month=${p.month}`),api('reports/monthly')]);const report=rows.find(r=>r.period===period);pageData={stats,rows,report};return `${await intelligenceReports(can('reports'))}<details class="monthly-workspace" ${monthlyOpen?'open':''}><summary>Monthly analysis and delivery</summary><div class="report-workspace"><section class="panel"><div class="section-head"><div><h2>Monthly evidence</h2><p class="meta">Choose a completed calendar month in UTC.</p></div><label class="field"><span>Report month</span><input type="month" name="period" id="report-period" value="${period}" min="2000-01" max="${completedMonth()}"></label></div>${metrics([['Scans',stats.total_scans,'Monthly total','shield'],['High / Critical',stats.high_risk_scans,'Recorded high-severity results','alert'],['Unknown',stats.severity_counts?.Unknown,'Unassessable checks','search'],['Alerts',stats.alerts_total,'Monthly alert records','case']])}</section><div class="grid-even"><section class="panel stack"><div class="section-head"><div><h2>Machine-learning review</h2><p class="meta">Isolation Forest · Daily activity</p></div>${tag('Evidence')}</div><p class="muted">Learns from 90 days before the selected month. Unusual activity supports investigation; it does not establish a threat or change scan risk.</p>${btn('Run monthly ML analysis','run-ml','primary')}<div id="ml-result">${empty('Run an activity review','At least 30 active historical days and three distinct observations are needed.')}</div></section><section class="panel stack"><h2>AI-written monthly summary</h2><p class="muted">The backend combines aggregate statistics with the ML evidence. Review the saved draft before delivering it to administrators.</p>${report?`<div class="row between">${tag(report.status)}<span class="meta">${esc(date(report.generated_at))}</span></div><h3 data-no-translate>${esc(report.subject)}</h3><label class="field"><span>Saved report body · Read only</span><textarea readonly rows="10" data-no-translate>${esc(report.body)}</textarea></label>${can('reports')&&report.status!=='sent'?btn('Send reviewed report','send-report','primary'):''}${table(report.delivery_outcomes??[],[['Channel','channel'],['Status','status'],['Reason',r=>esc(r.reason??r.error_type??'—')]])}`:can('reports')?btn('Generate LLM draft','generate-report','primary'):notice('Managers can review saved reports and ML results. Administrators prepare and deliver reports.')}</section></div><section class="panel"><h2>Saved report history</h2>${table(rows,[['Month','period'],['Status',r=>tag(r.status)],['Scans',r=>number(r.stats?.total_scans)],['Generated',r=>esc(date(r.generated_at))],['Sent',r=>esc(date(r.sent_at))]])}</section></div></details>`;}

async function accounts(){const [requests,rows]=await Promise.all([api('admin/registrations'),api('admin/accounts')]);pageData={requests,rows};return `<section class="panel stack">${notice('Approval pyramid: normal users → managers → administrators → head administrator. Higher roles may approve lower roles. Only the head changes existing account privileges. Every account requires 2FA.')}<h2>Pending registrations</h2>${table(requests,[['Username','username'],['Requested role','role'],['Status',r=>tag(r.status)],['Requested',r=>esc(date(r.created_at))]])}${requests.length?details('Review an access request',form('account-review',select('Registration','username',requests.map(r=>[r.username,r.username+' · '+r.role]),'', 'data-account-request')+select('Assign role','role',(state.profile.approvable_roles??[]).map(r=>[r,{normal_user:'Normal user',manager:'Manager',administrator:'Administrator'}[r]]),requestedRole(state.profile,requests[0]))+select('Decision','decision',['approve','reject'])+check('I verified this person’s identity and authorized their access.','confirmed')+reason(),'Record access decision')):''}</section><section class="panel stack"><h2>Approved accounts</h2>${table(rows,[['Username','username'],['Role','role_label'],['Source','source']])}${state.profile.can_manage_accounts&&rows.some(r=>r.role!=='head_administrator')?details('Change account access',form('account-role',select('Account','username',rows.filter(r=>r.role!=='head_administrator').map(r=>r.username))+select('Role','role',[['normal_user','Normal user'],['manager','Manager'],['administrator','Administrator']])+select('Action','operation',['role','disable'])+check('Revoke this account’s current sessions when applying the change.','confirmed')+reason(),'Apply access change')):''}</section><section class="panel"><h2>Privilege guide</h2>${table([{role:'Normal user',access:'Check files and destinations; request website access; own history and guidance.'},{role:'Manager',access:'Review monitoring and reports; manage alerts, cases and normal-user approvals.'},{role:'Administrator',access:'Security operations, policies, exceptions, privacy, manager approvals and report delivery.'},{role:'Head of Administrator',access:'All workflows, approval of administrators, account access control and own website requests.'}],[['Role','role'],['Access','access']])}</section>`;}

async function cases(){const [rows,scans,people]=await Promise.all([api('cases'),api('scans'),api('case-assignees')]);let row=rows.find(r=>r.id===selected)??rows[0];selected=row?.id??'';if(row)row=await api('cases/'+row.id);pageData={rows,row,people};const names=people.map(r=>r.username);return `<section class="panel stack">${notice('Linked scan evidence is held during investigation. Resolving a case preserves its score and history.')}${table(rows,[['Case','title'],['Risk',r=>tag(r.severity)],['Assigned to','assignee'],['Status',r=>tag(r.status)]])}${can('cases')&&scans.length&&names.length?details('Open an investigation',form('case-create',select('Source scan','scan_id',scans.map(r=>[r.id,`${r.severity} · ${r.target_display}`]))+field('Case title','title','text','','required minlength="8" maxlength="160"')+select('Assign to','assignee',names),'Open incident case')):''}</section>${row?`<section class="panel stack"><h2>Investigation workspace</h2>${selectRows('Case',rows,selected)}<div class="row">${tag(row.status)}${tag(row.severity)}<span class="meta">Revision ${row.revision}</span>${btn('Inspect source evidence','inspect-scan','small',`data-id="${esc(row.scan_id)}"`)}</div><h3>Investigation notes</h3>${row.notes?.length?row.notes.map(n=>`<div class="risk-pill"><p data-no-translate>${esc(n.body)}</p><p class="meta mt14">${esc(n.author)} · ${esc(date(n.created_at))}</p></div>`).join(''):empty('No notes yet','Record evidence references without private URLs, passwords or personal details.')}${can('cases')?details('Add an investigation note',form('case-note',textarea('Note','body','','required minlength="8" maxlength="4000"'),'Add note'))+details('Update case or record resolution',form('case-status',select('Status','status',{'open':['open','investigating'],'investigating':['investigating','resolved','open'],'resolved':['resolved','open']}[row.status],row.status)+select('Assigned investigator','assignee',names,row.assignee)+reason(),'Update investigation')):''}</section>`:''}`;}

async function policies(){const d=await api('policies');pageData=d;const p=d.active,bands=Object.fromEntries(p.severity_bands.map(r=>[r.severity,r.min_score]));const row=d.revisions.find(r=>r.id===selected)??d.revisions[0];selected=row?.id??'';return `<section class="panel stack"><div class="row between"><h2>Active scoring policy</h2><span class="meta">Version ${esc(short(p.version))}</span></div>${notice('Drafts do not affect live scores. A different approved administrator must review a draft before activation.')}${!d.independent_review_available?notice('Only one administrator is available. Add and approve an independent reviewer before approving a policy change.','warning'):''}${table(p.severity_bands,[['Severity',r=>tag(r.severity)],['Starts at','min_score'],['Ends at','max_score']])}${details('Draft a scoring change',form('policy-create',`<div class="fields">${p.signals.map(s=>field(s.title,'weight_'+s.code,'number',s.points,'required min="1" max="100" step="1"')).join('')}${['Medium','High','Critical'].map(label=>field(label+' starts at',label.toLowerCase(),'number',bands[label],'required min="1" max="100" step="1"')).join('')}</div>`+reason(),'Save policy draft'))}</section><section class="panel stack"><h2>Policy revisions</h2>${table(d.revisions,[['Author','author'],['Status',r=>tag(r.status)],['Reviewer','reviewer'],['Reason','reason']])}${row?selectRows('Revision',d.revisions,selected)+table(row.policy.signals,[['Signal','title'],['Proposed points','points']])+table(row.policy.severity_bands,[['Severity',r=>tag(r.severity)],['Proposed minimum','min_score']])+(row.status==='draft'?row.author===state.profile.username?notice('You created this draft. Another administrator must review it.','warning'):form('policy-review',select('Decision','decision',['approved','rejected'])+reason(),'Submit independent review'):row.status==='approved'?form('policy-activate',reason(),'Activate approved policy'):notice('This revision is '+row.status+'.')):''}</section>`;}

async function privacy(){const [rules,preview]=await Promise.all([api('privacy'),api('privacy/retention-preview')]);pageData={rules,preview};return `<section class="panel stack"><h2>Data collection and access</h2>${table(rules.inventory,[['Data','data'],['Stored','stored'],['Purpose','purpose']])}<p class="meta">${esc(rules.retention_scope)}</p>${notice(rules.note_guidance??'Keep personal information, passwords and private URLs out of notes.')}${form('privacy-save',textarea('Collection purpose','collection_purpose',rules.collection_purpose,'required minlength="15" maxlength="1000"')+field('Scan retention period (days)','retention_days','number',rules.retention_days,'required min="7" max="3650"')+check('Retain and display hostnames in URL scan results.','show_hostnames',rules.show_hostnames)+reason(),'Save privacy rules')}</section><section class="panel stack"><h2>Retention preview</h2>${metrics([['Eligible scans',preview.eligible_scans,'Past the retention cutoff','clock'],['Held for cases',preview.protected_case_scans,'Investigation evidence is preserved','case'],['Retention days',rules.retention_days,'Configured period','lock']])}<p class="meta">Cutoff ${esc(date(preview.cutoff))}. Saved monthly reports remain snapshots.</p>${preview.eligible_scans?form('retention-apply',notice('This permanently deletes eligible scan evidence. Review the preview and any applicable retention requirements before proceeding.','warning')+check('Permanently delete the eligible scan evidence shown in this preview.','confirmed'),'Permanently apply retention','danger'):notice('No scan records are currently eligible for deletion.')}</section>`;}

const fixtures=[{name:'Confirmed malicious URL',expected:'threat',signals:[{code:'malicious_url',status:'detected'}]},{name:'Clear URL check',expected:'benign',signals:[{code:'malicious_url',status:'clear'}]},{name:'Unavailable lookup',expected:'unknown',signals:[{code:'malicious_url',status:'unknown'}]}];

async function evaluation(){const rows=await api('evaluations');pageData={rows};const row=rows.find(r=>r.id===selected)??rows[0];selected=row?.id??'';return `<section class="panel stack">${notice('Synthetic scoring scenarios measure rule behavior, not real-world malware detection accuracy. Unknown outcomes are reported separately.')}${details('Run a labelled scoring evaluation',form('evaluation-run',field('Dataset version','dataset_version','text','synthetic-example-v1','required maxlength="80"')+textarea('Labelled scenarios (JSON)','scenarios',JSON.stringify(fixtures,null,2),'required class="code-editor"')+'<p class="meta">Replace the sample with reviewed scenarios. Scenario names must not contain private identifiers.</p>','Compare policy with baseline'))}${table(rows,[['Dataset','dataset_version'],['Policy','policy_version'],['Run time',r=>esc(date(r.created_at))]])}</section>${row?`<section class="panel stack"><h2>Evaluation results</h2>${selectRows('Run',rows,selected)}${['current','baseline'].map(label=>{const r=row.results[label];return `<h3>${label==='current'?'Active policy':'Baseline policy'}</h3>${metrics([['True positives',r.true_positives,'Expected threat flagged'],['False positives',r.false_positives,'Benign scenario flagged'],['Missed threats',r.false_negatives,'Expected threat below threshold'],['Unknown',r.unknown_outcomes,'Unassessable outcome']])}<p class="meta">Precision: ${r.precision??'unavailable'} · Recall: ${r.recall??'unavailable'} · Coverage: ${Math.round(r.coverage*100)}%</p>${table(r.scenarios,[['Scenario','name'],['Expected','expected'],['Result',r=>tag(r.severity)],['Prediction','prediction']])}`;}).join('')}${(row.results.recommendations??[]).map(r=>notice(r.action)).join('')}${btn('Download evaluation evidence','download-evaluation')}</section>`:''}`;}

async function usability(){const rows=await api('usability');pageData={rows};const row=rows.find(r=>r.id===selected)??rows[0];selected=row?.id??'';return `<section class="panel stack">${notice('Record actual walkthroughs and observations. A code check alone does not establish accessibility conformance.')}${details('Record a usability or accessibility check',form('usability-create',field('Task tested','task','text','','required minlength="8" maxlength="200"')+select('Category','category',[['keyboard','Keyboard navigation'],['contrast','Colour contrast'],['screen_reader','Screen reader'],['comprehension','Understanding risk'],['workflow','Task workflow']])+select('Observed outcome','outcome',['passed','failed','blocked'])+textarea('Observation','observation','','required minlength="8" maxlength="2000"'),'Record test'))}${table(rows,[['Task','task'],['Category','category'],['Outcome',r=>tag(r.outcome)],['Status',r=>tag(r.status)],['Observation','observation']])}${row?details('Record a fix or verified retest',selectRows('Test record',rows,selected)+form('usability-status',select('Issue status','status',['open','fixed','verified'],row.status)+textarea('Fix or retest evidence','verification',row.verification??'','required minlength="8" maxlength="2000"'),'Update record')):''}</section>`;}

async function guidance(){const p=await api('risk-policy');return `<div class="grid-even"><section class="panel body-copy"><h2>A useful first workflow</h2><ol><li>Open the toolbar popup and review the current site.</li><li>Choose Check destination to submit a cleaned URL, or select a downloaded file for local hashing.</li><li>Read the severity, assessment completeness and confirmed findings together.</li><li>Escalate High or Critical evidence to an administrator; keep Unknown outcomes visible.</li></ol><p>New website visits require approval. A one-visit grant opens once; a whitelisted URL can be revisited until expiry or revocation. Reputation checks still run only when you choose them, and downloaded files are never read automatically.</p></section><section class="panel body-copy"><h2>Understand the result</h2><p><strong>Low:</strong> Few confirmed signals in the checks performed. It does not guarantee safety.</p><p><strong>Medium:</strong> Review findings and avoid unnecessary exposure.</p><p><strong>High / Critical:</strong> Avoid opening the destination or file; investigate evidence and affected devices.</p><p><strong>Unknown:</strong> The required information was unavailable. Retry later or use another approved investigation method.</p>${table(p.severity_bands,[['Risk',r=>tag(r.severity)],['Minimum score','min_score']])}</section></div><section class="panel body-copy"><h2>Keep decisions accountable</h2><p>Administrators can acknowledge threats, link evidence to a case and record a resolution. Exceptions affect notifications while retaining the original risk result. Scoring changes need an independent administrator’s approval.</p><p>Monthly AI summaries are drafts that need review. Machine learning highlights unusual activity; it does not prove that malware is present.</p><div class="row">${btn('Review my account','go-account')}${can('scan')?btn('Check a file','go-files','primary'):''}</div></section>`;}

async function account(){return deviceConnection()+`<div class="grid-even"><section class="panel stack"><h2>Your account</h2><div class="profile-logo-row">${avatar(state.profile,true)}<div><h3>Profile logo</h3><p class="meta">Your logo is saved for this account in this Chrome profile only.</p></div></div>${form('account-logo',field('Choose profile logo','logo','file','','accept="image/png,image/jpeg,image/webp" required aria-describedby="logo-help"')+'<p id="logo-help" class="meta">PNG, JPG or WebP · up to 2 MiB. The image is cropped to a square and resized before saving.</p>','Save logo','small')}${state.profile.logo?btn('Remove logo','remove-account-logo','small'):''}${table([{label:'Account',value:state.profile.display_name},{label:'Username',value:state.profile.username},{label:'Role',value:state.profile.role_label},{label:'Session expires',value:date(state.expires_at)}],[['Detail','label'],['Value','value']])}${notice('Password and authenticator verification completed for this session.','success')}${btn('Sign out on this browser','logout')}</section><section class="panel stack"><h2>Your approved access</h2><p class="muted">Your role is assigned by the Head of Administrator. Contact that account owner when your responsibilities change.</p><div class="row">${state.profile.views.map(v=>`<span class="tag">${esc(v)}</span>`).join('')}</div><p class="meta">Sessions are stored in Chrome’s memory-only extension storage. Passwords and authenticator secrets are not saved by the extension.</p></section></div>`;}



function preferencesForm(){const prefs=getPreferences();return form('preferences',`<div class="fields appearance-fields">${select('Appearance','theme',THEMES,prefs.theme)}${select('Table size','tableSize',TABLE_SIZES,prefs.tableSize)}${select('Language','language',LANGUAGES,prefs.language)}${select('Time zone','timeZone',TIME_ZONES,prefs.timeZone)}</div>`,'Save preferences','small');}

async function settings(){return `<section class="panel stack"><h2>Appearance, language and time</h2><p class="muted">Arabic and English are supported. Times follow your selected zone; monthly report boundaries stay in UTC.</p>${preferencesForm()}${notice('These settings apply to the popup, console and blocked-page screen.')}${notice('Recorded evidence and administrator notes keep their original language.')}</section>`+connectionPanel(connectionStatus);}

async function access(){

 const [rows,whitelist]=await Promise.all([api('access/requests'),api('access/whitelist')]);pageData={rows,whitelist};

 const pending=reviewableAccessRequests(rows);

 const request=`<section class="panel"><h2>Request access</h2>${form('access-request',field('Destination','target','url','','required maxlength="2048" placeholder="https://example.com/approved-path"')+textarea('Request reason','reason','','required minlength="8" maxlength="1000"'),'Request access')}</section>`;

 const review=`<section class="panel"><div class="section-head"><h2>Review request</h2><span class="meta"><bdi>${number(pending.length)}</bdi> <span>Awaiting review</span></span></div>${pending.length?form('access-review',select('Select request','request_id',pending.map(r=>[r.id,r.target+' · '+r.requester]))+select('Decision','decision',[['approve','Approve request'],['reject','Reject request']])+select('Approval duration','duration',[['24','24 hours'],['168','7 days'],['forever','Forever (whitelist)']],'','required')+reason()+check('Confirm you have reviewed the destination and the business need.','confirmed',false,true),'Submit decision'):empty('No pending requests','Users need a manager, managers need an administrator, and administrators need the head. The head may review their own requests.')}</section>`;

 const help=`<section class="panel help-copy"><h2>How access works</h2><p><strong>Website stays blocked until approval.</strong></p><p>Temporary approval allows repeat visits for 24 hours or 7 days. After expiry, request access again. Forever adds the URL to the shared whitelist until revoked.</p><p>The exact scheme, host, port and path are approved. Query strings and fragments are not stored in approval requests.</p><p>Managing website approval does not change risk scores or suppress threat alerts.</p></section>`;

 return `<div class="task-grid">${can('access')?review:request}<div class="task-aside">${can('access')?request:''}${help}</div></div><section class="panel"><h2>Access requests</h2>${table(rows,[['Destination',r=>`<bdi class="code">${esc(r.target)}</bdi>`],['Requester',r=>`${evidence(r.requester)}<div class="meta">${esc(translate(({normal_user:'Normal user',manager:'Manager',administrator:'Administrator',head_administrator:'Head of Administrator'})[r.requester_role]??r.requester_role))}</div>`],['Status',r=>tag(r.status)+(r.decision?`<div class="meta">${esc(translate(r.decision))}</div>`:'')],['Reason','reason'],['Requested',r=>esc(date(r.created_at))],['Expires',r=>r.permanent?esc(translate('Forever')):esc(date(r.expires_at))]])}</section>${websiteWhitelistPanel(whitelist)}`;

}



const renderers={access,settings,overview,scan,files,alerts,history:()=>scanHistory(false),myhistory:()=>scanHistory(true),risks,overrides,reports,accounts,cases,policies,privacy,evaluation,usability,guidance,account,

 findings:()=>listPage('findings',[['Finding','title'],['Risk',r=>tag(r.severity)],['Points','points'],['Evidence','detail'],['Detected',r=>esc(date(r.created_at))],['Scan',r=>btn('Inspect','inspect-scan','small',`data-id="${esc(r.scan_id)}"`)]]),

 devices:devicesPage,

 extensions:extensionsPage,

 events:()=>listPage('events',[['Event','message'],['Risk',r=>tag(r.severity)],['Device',r=>`<span data-no-translate>${esc(r.device_name??'Not recorded')}</span>${r.device_id?`<div class="meta" data-no-translate>${esc(r.device_id)}</div>`:''}`],['User',r=>evidence(r.username??'Not recorded')],['Website / file',r=>evidence(r.target_display??'-')],['Actor','actor'],['Decision / reason','reason'],['Channel','channel'],['Time',r=>esc(date(r.created_at))]])};

async function renderView(){const sequence=++requestSequence;if(!state.profile){await renderAuth();return;}if(popup){await renderPopup();return;}if(!allowedViews().some(r=>r[0]===view))view=allowedViews()[0]?.[0]??'account';loading=true;shell('<div class="pending"><div class="stack"><div class="spinner" aria-hidden="true"></div><p role="status">Loading recorded evidence…</p></div></div>');try{const html=await renderers[view]();if(sequence===requestSequence){shell(html);document.querySelector('#main')?.focus({preventScroll:true});}}catch(error){if(sequence===requestSequence&&!await handleExpiredSession(error))shell(notice(error.message,'error')+btn('Try again','refresh'));}finally{loading=false;if(queuedView&&!busy){const next=queuedView;queuedView='';navigate(next);}}}

async function renderPopup(){

  if(inventoryRecovery()){app.innerHTML=previewNotice+`<main id="main" class="popup-main stack">${brand()}${notice(state.profile.inventory.pending?'Device added. Waiting for administrator approval.':state.profile.inventory.blocked?'This device is blocked. Contact an administrator.':'Click Add this device in My account to continue.','warning')}${btn('Open My account','open-account','primary')}${can('inventory')?btn('Open device inventory','open-devices'):''}${btn('Sign out','logout')}</main>`;return;}

  let active={};try{active=await send({type:'ACTIVE_TAB'});}catch{}

  pageData.active=active;

  const page=can('scan')?`<section class="popup-destination"><p class="popup-label">Current page</p><h1 data-no-translate>${esc(active.host||translate('Choose a web page'))}</h1><p class="meta">Only the site origin is checked.</p>${btn('Check current destination','scan-active','primary full',active.url?'':'disabled')}</section><div class="popup-actions">${btn('File check','toggle-file')}${btn('Dashboard','open-console')}</div><div id="popup-file" hidden><section class="panel">${fileForm()}</section></div><div id="popup-result" aria-live="polite">${scanResult?resultCard(scanResult,true):''}</div>`:`<section class="popup-destination"><h1>Security workspace</h1><p class="meta">Review findings, access requests and reports.</p>${btn('Dashboard','open-console','primary full')}</section>`;

  app.innerHTML=previewNotice+`<header class="popup-header"><div class="row between">${brand()}${tag('2FA verified')}</div></header><main id="main" class="popup-main">${page}</main><div class="popup-preferences"><div data-connection-badge>${connectionBadge(connectionStatus)}</div>${btn('Website access','open-access','ghost small')}</div><div class="popup-account">${details('Account & settings',`<div class="row">${avatar(state.profile)}<p class="meta"><bdi data-no-translate>${esc(state.profile.username)}</bdi> · <span>${esc(state.profile.role_label)}</span></p></div><div class="row">${btn('My account','open-account','small')}${btn('Settings','open-settings','small')}${btn('Sign out','logout','ghost small')}</div><p class="meta mt14">ExtSecure ${VERSION} · <bdi data-no-translate>${esc(getPreferences().timeZone)}</bdi></p>`)}</div>`;

}

function navigate(key){if(loading||busy){queuedView=key;return;}if(!allowedViews().some(r=>r[0]===key)){toast('This view is not available for your assigned role.',true);return;}view=key;selected='';pageData={};window.history.replaceState(null,'','#'+key);renderView();}

async function handleExpiredSession(error){if(error.status!==401||!state.profile)return false;state={};pageData={};devicePairing=null;scanResult=null;selected='';manualSecret='';qr='';authMode='login';queuedView='';connectionStatus='unchecked';requestSequence++;await renderAuth();toast(translate('Your session ended. Sign in again with your password and authenticator.'),true);return true;}

async function commit(path,body){await api(path,'POST',body);await renderView();toast('Saved. The backend recorded the decision.');}

async function mutation(task,element){if(busy)return;busy=true;const previousLabel=element?.innerHTML;if(element){element.disabled=true;element.setAttribute('aria-busy','true');element.textContent=translate('Working…');}try{await task();}catch(error){if(!await handleExpiredSession(error)){const alert=element?.closest('form')?.querySelector('.form-error');if(alert){alert.textContent=error.message;alert.hidden=false;alert.focus({preventScroll:true});}else toast(error.message,true);}}finally{busy=false;if(element){element.disabled=false;element.removeAttribute('aria-busy');if(element.isConnected)element.innerHTML=previousLabel;}if(queuedView&&!loading){const next=queuedView;queuedView='';navigate(next);}}}

app.addEventListener('click',async event=>{

  const button=event.target.closest('button');if(!button)return;

  if(button.dataset.view)return navigate(button.dataset.view);

  if(button.dataset.authMode){if(busy||loading)return;authMode=button.dataset.authMode;return renderAuth();}

  const action=button.dataset.action;if(!action)return;

  if(action==='toggle-navigation')return toggleConsoleNavigation(app.querySelector('.sidebar'),button);

  if(action.startsWith('go-'))return navigate(action.slice(3));

  if(busy)return;

  await mutation(async()=>{

    if(action==='remove-account-logo'){await send({type:'SAVE_ACCOUNT_LOGO',logo:null});state=await send({type:'STATE'});await renderView();toast('Profile logo removed.');return;}

    if(action==='toggle-theme'){const prefs=getPreferences();setPreferences(await send({type:'SAVE_PREFERENCES',preferences:{...prefs,theme:resolvedTheme()==='dark'?'light':'dark'}}));await renderView();return;}

    if(action==='restart-extension'){toast('Restarting ExtSecure. Reopen it from the Chrome extension icon and sign in.');restartExtension();return;}

    if(action==='sync-inventory'){

      if(!isExtension)throw new Error('Chrome inventory requires loading the extension.');

      // Start within the click gesture, inside the error handler. Registration

      // is independent of the permission prompt, including a declined prompt.

      if(typeof chrome.permissions?.request!=='function')throw new Error('Chrome inventory permission is unavailable. Reload ExtSecure and reopen its console.');

      if(!await chrome.permissions.request({permissions:['management']}))throw new Error('Chrome inventory permission was not granted. Your device remains connected. Click Connect enabled Chrome extensions to try again.');

      const result=await send({type:'SYNC_INVENTORY'});state=await send({type:'STATE'});await renderView();toast(result.enabled_count+' enabled Chrome extensions synced.');

    }

    if(action==='pair-created'){await send({type:'PAIR_DEVICE',code:devicePairing.pairing_code});devicePairing=null;state=await send({type:'STATE'});await renderView();toast('Chrome profile linked. Open Extensions to connect the enabled inventory.');}

    if(action==='open-account')await send({type:'OPEN_CONSOLE',view:'account'});

    if(action==='refresh'){state=await send({type:'STATE'});await renderView();}

    if(action==='open-devices')await send({type:'OPEN_CONSOLE',view:'devices'});

    if(action==='open-settings')await send({type:'OPEN_CONSOLE',view:'settings'});

    if(action==='open-access')await send({type:'OPEN_CONSOLE',view:'access'});

    if(action==='check-connection')await checkConnection();

    if(action==='open-history')await send({type:'OPEN_CONSOLE',view:state.profile.role==='normal_user'?'myhistory':'history'});

    if(action==='download-scan'){if(!pageData.inspectedScan)throw new Error('Open a scan result before exporting evidence.');download(pageData.inspectedScan,'extsecure-scan-'+pageData.inspectedScan.id+'.json');}

    if(action==='open-console')await send({type:'OPEN_CONSOLE'});

    if(action==='toggle-file')document.querySelector('#popup-file').hidden=!document.querySelector('#popup-file').hidden;

    if(action==='reset-auth'){await send({type:'RESET_AUTH'});state={};manualSecret='';qr='';await renderAuth();}

    if(action==='logout'){devicePairing=null;try{await send({type:'LOGOUT'});}finally{state={};scanResult=null;manualSecret='';qr='';pageData={};await renderAuth();}}

    if(action==='scan-active'){scanResult=await send({type:'SCAN_URL',target:pageData.active.url,includePath:false});await renderPopup();}

    if(action==='inspect-scan'){const r=await api((pageData.personal?'my/scans/':'scans/')+button.dataset.id);shell(resultCard(r)+btn('Back to results','refresh'));}

    if(action==='run-ml'){const p=reportPeriod(period),r=await api(`reports/monthly/ml?year=${p.year}&month=${p.month}`);pageData.ml=r;document.querySelector('#ml-result').innerHTML=r.status==='ready'?notice(`${r.unusual_days.length} unusual days. ${r.active_training_days} active historical days. These results support review, not a threat verdict.`)+table(r.daily_results,[['Day','date'],['Scans','scans'],['Unusual','unusual']])+notice(r.limitation,'',true)+btn('Download ML evidence','download-ml','small'):notice(r.reason??'Insufficient historical observations.','warning')+btn('Download ML evidence','download-ml','small');}

    if(action==='generate-report'){await api('reports/monthly/generate','POST',reportPeriod(period));await renderView();toast('The AI draft was saved. Review the report before sending.');}

    if(action==='send-report'){await api('reports/monthly/'+period+'/send','POST');await renderView();toast('Report delivery completed. Review the recorded delivery outcomes.');}

    if(action==='download-ai-report')await downloadPeriodReport(button.dataset.id);

    if(action==='download-ml')download(pageData.ml,'extsecure-ml-'+period+'.json');

    if(action==='download-evaluation')download(pageData.rows.find(r=>r.id===selected),'extsecure-evaluation.json');

  },button);

});

app.addEventListener('submit',async event=>{

  event.preventDefault();const f=event.target,action=f.dataset.form;if(!action)return;const submit=f.querySelector('[type="submit"]'),data=Object.fromEntries(new FormData(f));const error=f.querySelector('.form-error');if(error)error.hidden=true;if(busy)return;

  await mutation(async()=>{

    if(action==='account-logo'){const file=f.querySelector('[name="logo"]').files[0];const logo=await prepareLogo(file);await send({type:'SAVE_ACCOUNT_LOGO',logo});state=await send({type:'STATE'});await renderView();toast('Profile logo saved.');}

    else if(action==='device-connect'){

      if(!isExtension)throw new Error('Load ExtSecure in Chrome to add this device.');

      if(!state.profile?.inventory?.linked&&!['trusted','blocked'].includes(data.initial_access))throw new Error('Choose Trusted device or Blocked device before adding this device.');

      const message={type:'CONNECT_DEVICE',name:data.name,ip_address:data.ip_address};

      if(data.initial_access)message.initial_access=data.initial_access;

      const result=await send(message);f.reset();state=await send({type:'STATE'});await renderView();

      toast(result.pending?'Device added. Waiting for administrator approval.':result.blocked?'Device added as blocked. An administrator must allow it before scans or website access.':result.inventory_status==='ready'?result.enabled_count+' enabled Chrome extensions connected.':result.inventory_status==='retry_required'?'Device connected. Click Refresh devices & extensions to retry inventory sync.':'Device connected. Click Connect enabled Chrome extensions to include the other extensions.',result.inventory_status==='retry_required');

    }

    else if(action==='device-add'){devicePairing=await api('inventory/devices','POST',{name:data.name,ip_address:data.ip_address,operating_system:data.operating_system,reason:data.reason});f.reset();state=await send({type:'STATE'});await renderView();}

    else if(action==='device-pair'){await send({type:'PAIR_DEVICE',code:data.code});f.reset();devicePairing=null;state=await send({type:'STATE'});await renderView();toast('Chrome profile linked.');}

    else if(action==='device-status'||action==='device-code'){const row=pageData.rows.find(r=>r.id===data.device_id);if(!row)throw new Error('Refresh device inventory first.');const path='inventory/devices/'+row.id+'/'+(action==='device-status'?'status':'pairing-code'),body={expected_revision:row.revision,reason:data.reason};if(action==='device-status')body.blocked=data.blocked==='true';const result=await api(path,'POST',body);if(action==='device-code')devicePairing=result;state=await send({type:'STATE'});await renderView();toast('Device inventory updated.');}

    else if(action==='ai-explain')await runExplanation(f);

    else if(action==='ai-report')await runPeriodReport(f);

    else if(action==='login'){await send({type:'LOGIN',username:data.username,password:data.password});f.reset();state=await send({type:'STATE'});await renderAuth();}

    else if(action==='verify'){await send({type:'VERIFY',code:data.code});f.reset();state=await send({type:'STATE'});view=location.hash.slice(1)||'';await renderView();}

    else if(action==='register'){if(data.password!==data.confirm)throw new Error('Passwords must match.');const r=await send({type:'REGISTER',username:data.username,password:data.password});f.reset();manualSecret=r.secret;qr=r.image;state=await send({type:'STATE'});await renderAuth();}

    else if(action==='register-verify'){await send({type:'REGISTER_VERIFY',code:data.code,role:data.role});manualSecret='';qr='';state={};authMode='login';await renderAuth();toast('Account verified. A higher role must approve access before you can sign in.');}

    else if(action==='preferences'){setPreferences(await send({type:'SAVE_PREFERENCES',preferences:{...getPreferences(),language:data.language,timeZone:data.timeZone,theme:data.theme,tableSize:data.tableSize}}));await renderView();toast(translate('Preferences saved.'));}

    else if(action==='access-request'){const target=privateTarget(data.target,true);const permission=await api('access/check','POST',{target});if(permission.allowed){await renderView();toast(translate('This URL is already approved. No new request is needed.'));}else{await commit('access/requests',{target,reason:data.reason});toast(translate('Access request sent. The website remains blocked until approval.'));}}

    else if(action==='access-review'){if(!data.confirmed)throw new Error('Confirm you have reviewed the destination and the business need.');const row=pageData.rows.find(r=>r.id===data.request_id);if(!row)throw new Error('Refresh the request list first.');await commit('access/requests/'+row.id+'/review',accessReviewBody(row,data));}

    else if(action==='access-revoke')await commit('access/whitelist/'+data.entry_id+'/revoke',{reason:data.reason});

    else if(action==='url-scan'){scanResult=await send({type:'SCAN_URL',target:data.target,includePath:!!data.includePath});await renderView();}

    else if(action==='file-scan'){const file=f.querySelector('[name="file"]').files[0];if(file&&data.sha256.trim())throw new Error('Choose either a file or a pasted hash for this check.');const digest=file?await hashFile(file):validDigest(data.sha256);const actorHash=await hashFile(new Blob([state.profile.username]));scanResult=await api('admin/downloads/scan','POST',{device_id:'user-'+actorHash.slice(0,32),device_name:'ExtSecure browser checks',extension_key:'extsecure-browser',extension_name:'ExtSecure',extension_version:VERSION,sha256:digest});f.reset();await renderView();}

    else if(action==='alert-status'){const row=pageData.rows.find(r=>r.id===selected);await commit('alerts/'+selected+'/status',{status:data.status,expected_status:row.status,reason:data.reason});}

    else if(action==='override-create'){if(!data.expires_at)throw new Error('Set an expiry for the exception.');const expires_at=data.expires_at+':00Z';if(Date.parse(expires_at)<=Date.now())throw new Error('Choose a future expiry in UTC.');await commit('overrides',{kind:data.kind,target:data.target,reason:data.reason,expires_at});}

    else if(action==='override-deactivate'){if(!data.confirmed)throw new Error('Confirm deactivation first.');await commit('overrides/'+selected+'/deactivate');}

    else if(action==='account-review'){if(data.decision==='approve'&&!data.confirmed)throw new Error('Confirm identity and access authorization before approving.');await commit('admin/registrations/'+encodeURIComponent(data.username)+'/'+data.decision,{role:data.role,reason:data.reason});}

    else if(action==='account-role'){if(!data.confirmed)throw new Error('Confirm session revocation before applying access changes.');await commit('admin/accounts/'+encodeURIComponent(data.username)+'/'+data.operation,data.operation==='role'?{role:data.role,reason:data.reason}:undefined);}

    else if(action==='case-create')await commit('cases',{scan_id:data.scan_id,title:data.title,assignee:data.assignee});

    else if(action==='case-note')await commit('cases/'+selected+'/notes',{body:data.body});

    else if(action==='case-status')await commit('cases/'+selected+'/status',{status:data.status,assignee:data.assignee,reason:data.reason,expected_revision:pageData.row.revision});

    else if(action==='policy-create'){const weights=Object.fromEntries(pageData.active.signals.map(s=>[s.code,Number(data['weight_'+s.code])]));await commit('policies',{base_version:pageData.active.version,weights,medium:Number(data.medium),high:Number(data.high),critical:Number(data.critical),reason:data.reason});}

    else if(action==='policy-review')await commit('policies/'+selected+'/review',{decision:data.decision,reason:data.reason});

    else if(action==='policy-activate')await commit('policies/'+selected+'/activate',{reason:data.reason});

    else if(action==='privacy-save')await commit('privacy',{expected_revision:pageData.rules.revision,collection_purpose:data.collection_purpose,retention_days:Number(data.retention_days),show_hostnames:!!data.show_hostnames,reason:data.reason});

    else if(action==='retention-apply'){if(!data.confirmed)throw new Error('Review the preview and confirm permanent deletion first.');await commit('privacy/retention-apply',{expected_revision:pageData.preview.revision,confirm:true});}

    else if(action==='evaluation-run'){let scenarios;try{scenarios=JSON.parse(data.scenarios);}catch{throw new Error('Enter valid JSON for the labelled scenarios.');}await commit('evaluations',{dataset_version:data.dataset_version,scenarios});}

    else if(action==='usability-create')await commit('usability',{task:data.task,category:data.category,outcome:data.outcome,observation:data.observation});

    else if(action==='usability-status'){const row=pageData.rows.find(r=>r.id===selected);await commit('usability/'+selected+'/status',{status:data.status,verification:data.verification,expected_revision:row.revision});}

    else throw new Error('This action is not supported.');

  },submit);

  data.password='';data.confirm='';data.code='';

});

app.addEventListener('toggle',event=>{if(event.target.classList.contains('monthly-workspace'))monthlyOpen=event.target.open;},true);

app.addEventListener('change',event=>{
 if(event.target.hasAttribute('data-table-size')){
  if(busy||loading){event.target.value=getPreferences().tableSize;toast(translate('Wait for the current action to finish.'),true);return;}
  const size=event.target.value;
  void mutation(async()=>{try{setPreferences(await send({type:'SAVE_PREFERENCES',preferences:{...getPreferences(),tableSize:size}}));toast(translate('Table size saved.'));}finally{for(const input of app.querySelectorAll('[data-table-size]'))input.value=getPreferences().tableSize;}});
  return;
 }
 if(event.target.hasAttribute('data-account-request'))updateAccountReview(event.target.form,state.profile,pageData.requests??[]);if(event.target.name==='request_id')resetDestinationReview(event.target.form);if(event.target.name==='decision'&&event.target.form?.dataset.form==='access-review')updateAccessDecision(event.target.form);if(event.target.name==='device_filter'){if(busy||loading)return;deviceFilter=event.target.value;renderView();return;}changePeriodInput(event);if((busy||loading)&&(event.target.hasAttribute('data-select-record')||event.target.id==='report-period')){event.target.value=event.target.id==='report-period'?period:selected;toast(translate('Wait for the current action to finish.'),true);return;}if(event.target.hasAttribute('data-select-record')){selected=event.target.value;renderView();}if(event.target.id==='report-period'){try{reportPeriod(event.target.value);period=event.target.value;renderView();}catch(error){toast(error.message,true);event.target.value=period;}}});

app.addEventListener('input',event=>{if(event.target.id==='nav-filter')filterConsoleNavigation(app.querySelector('#console-nav'),event.target.value,translate);if(event.target.id==='filter'){const result=filterRecords(document.querySelector('#records-table'),event.target.value),count=document.querySelector('#filter-count'),empty=document.querySelector('#filter-empty');if(count)count.textContent=number(result.visible)+' / '+number(result.total)+' '+translate('matching records');if(empty)empty.hidden=result.visible>0;}if(event.target.name==='target'||event.target.name==='includePath'){const f=event.target.closest('form'),label=f?.querySelector('#clean-target');if(label)try{label.textContent='Will check: '+privateTarget(f.elements.target.value,f.elements.includePath.checked);}catch{label.textContent='';}}});

function download(data,name){const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}

window.addEventListener('hashchange',()=>{const key=location.hash.slice(1);if(state.profile&&!popup)navigate(key);});

observeLocalization();

try{setPreferences(await send({type:'PREFERENCES'}));state=await send({type:'STATE'});view=location.hash.slice(1);await renderView();}catch(error){app.innerHTML=previewNotice+`<main id="main" class="page stack recovery-page">${brand()}<h1>Reconnect to your workspace</h1>${notice(error.message,'error')}${connectionPanel(connectionStatus)}${btn('Try again','refresh','primary')}</main>`;}



function workflowActions(){const actions=[...(can('scan')?[['File check','go-files','file']]:[]),['Website access','go-access','lock'],['Reports','go-reports','chart']];return `<section class="workflow-actions" aria-label="Quick actions">${actions.map(([title,action,symbol])=>`<button class="workflow-card" data-action="${action}"><span class="workflow-icon">${icon(symbol)}</span><span><strong>${esc(title)}</strong></span></button>`).join('')}</section>`;}
