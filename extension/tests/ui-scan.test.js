import test from 'node:test';
import assert from 'node:assert/strict';
import {VERSION} from '../core.js';
import fs from 'node:fs/promises';
import path from 'node:path';

// Run the shipped UI handlers with DOM/Chrome doubles, without real account writes.
const handlers={},app={innerHTML:'',addEventListener:(name,handler)=>handlers[name]=handler};
globalThis.location={protocol:'chrome-extension:',hash:'#files'};
globalThis.window={history:{replaceState(){}},addEventListener(){}};
globalThis.document={body:{classList:{contains:()=>false},querySelectorAll:()=>[]},documentElement:{},
 querySelector:selector=>({'#app':app,'#main':{focus(){}},'#toast':{}}[selector]),createTreeWalker:()=>({nextNode:()=>null})};
globalThis.NodeFilter={SHOW_TEXT:4};globalThis.MutationObserver=class{observe(){}};
globalThis.setTimeout=()=>0;
const profile={username:'test-head',display_name:'Test Head',role_label:'Head of Administrator',role:'head_administrator',approvable_roles:['normal_user','manager','administrator'],can_manage_accounts:true,views:['Overview','Downloaded-file checks','Website access','Accounts','Reports'],inventory:{linked:true}};
let result={id:'test-scan',target_kind:'download',target_display:'SHA-256 test',severity:'Unknown',score:null,completeness:'unknown',findings:[],file_lookup:{verdict:'unknown',reason:'not_found',cache_hit:true}};
const calls=[];
globalThis.chrome={runtime:{id:'a'.repeat(32),sendMessage:async message=>{
 calls.push(message);
 if(message.type==='PREFERENCES')return {ok:true,data:{language:'en',timeZone:'UTC'}};
 if(message.type==='STATE')return {ok:true,data:{profile,version:VERSION,capabilities:['device-enrollment','chrome-inventory','device-access-choice']}};
 if(message.type==='API'&&message.method==='POST')return {ok:true,data:result};
 if(message.type==='API')return {ok:true,data:[]};
 if(message.type==='SCAN_URL')return {ok:true,data:result};
 throw new Error('Unexpected message '+message.type);
}}};
globalThis.FormData=class{constructor(form){this.form=form;}*[Symbol.iterator](){yield* Object.entries(this.form.values);}};
await import('../ui.js');
async function submit(kind,values){
 const error={hidden:true,focus(){}},button={innerHTML:'Check',isConnected:true,setAttribute(){},removeAttribute(){},closest:()=>form};
 const form={dataset:{form:kind},values,reset(){},querySelector:selector=>selector==='.form-error'?error:selector==='[name="file"]'?{files:[]}:button};
 await handlers.submit({target:form,preventDefault(){}});assert.equal(error.hidden,true,error.textContent);
}
async function navigate(view){await handlers.click({target:{closest:()=>({dataset:{view}})}});await new Promise(resolve=>setImmediate(resolve));}
async function snapshot(name){if(process.env.EXTSECURE_UI_QA_OUTPUT){await fs.mkdir(process.env.EXTSECURE_UI_QA_OUTPUT,{recursive:true});await fs.writeFile(path.join(process.env.EXTSECURE_UI_QA_OUTPUT,name+'.html'),app.innerHTML);}}

test('A submitted file check renders the real not-found explanation and cache status',async()=>{
 await submit('file-scan',{sha256:'a'.repeat(64)});
 assert(calls.some(call=>call.path==='/api/admin/downloads/scan'));
 assert.match(app.innerHTML,/hash lookup ran, but VirusTotal has no report/);
 assert.match(app.innerHTML,/Cached reputation result/);assert.match(app.innerHTML,/tag unknown/);
 await snapshot('unknown-file');
});
test('The same result card displays a completed known file assessment',async()=>{
 result={...result,severity:'Low',score:0,completeness:'complete',file_lookup:{verdict:'clear'}};
 await submit('file-scan',{sha256:'b'.repeat(64)});
 assert.match(app.innerHTML,/file hash reputation lookup completed/);assert.match(app.innerHTML,/tag low/);
 assert.doesNotMatch(app.innerHTML,/VirusTotal has no report/);
 await snapshot('known-file');
});
test('Website failure explanations are escaped and cannot inject active HTML',async()=>{
 await navigate('scan');
 result={...result,target_kind:'url',severity:'Unknown',score:null,file_lookup:undefined,lookup:{status:'unavailable',reason:'<img src=x onerror=alert(1)>'}};
 await submit('url-scan',{target:'https://example.com/'});
 assert.match(app.innerHTML,/&lt;img src=x onerror=alert\(1\)&gt;/);
 assert.doesNotMatch(app.innerHTML,/<img src=x/);
});
test('Pending access requests render an initially visible required approval duration',async()=>{
 const original=chrome.runtime.sendMessage;
 chrome.runtime.sendMessage=async message=>message.path==='/api/access/requests'?{ok:true,data:[{id:'request1',target:'https://example.com/',requester:'test-head',requester_role:'head_administrator',status:'pending',can_review:true,expires_at:new Date(Date.now()+86400000).toISOString()}]}:original(message);
 try{await navigate('access');assert.match(app.innerHTML,/<select name="duration" required>/);await snapshot('website-access');}
 finally{chrome.runtime.sendMessage=original;}
});

test('Account review renders the requested role as the initial assignment',async()=>{
 const original=chrome.runtime.sendMessage;
 chrome.runtime.sendMessage=async message=>message.path==='/api/admin/registrations'?{ok:true,data:[{username:'test-manager',role:'manager',status:'pending_review'}]}:original(message);
 try{await navigate('accounts');assert.match(app.innerHTML,/<option value="manager" selected>Manager/);assert.match(app.innerHTML,/data-account-request/);await snapshot('accounts');}
 finally{chrome.runtime.sendMessage=original;}
});

test('The monitoring overview has role-appropriate quick actions and connection recovery',async()=>{
 const original=chrome.runtime.sendMessage;
 const data={pending_alerts:2,total_scans:142,high_risk:7,devices:3,extensions:6,severity_counts:{Low:103,Medium:25,High:5,Critical:2,Unknown:7},recent_events:[{event_type:'threat_detected',message:'Synthetic test evidence: high-risk URL detected.',severity:'High',created_at:'2026-10-07T08:00:00Z'}],daily_activity:Array.from({length:14},(_,i)=>({date:'2026-09-'+String(17+i).padStart(2,'0'),scans:6+i%5,high_risk:i%4===0?2:0}))};
 chrome.runtime.sendMessage=async message=>message.path==='/api/overview'?{ok:true,data}:original(message);
 try{await navigate('overview');assert.match(app.innerHTML,/workflow-actions/);assert.match(app.innerHTML,/data-action="check-connection"/);await snapshot('overview');
  profile.role='manager';profile.role_label='Manager';data.pending_alerts=0;
  await handlers.click({target:{closest:()=>({dataset:{action:'refresh'},setAttribute(){},removeAttribute(){},isConnected:true})}});
  assert.doesNotMatch(app.innerHTML,/data-action="go-files"/);assert.match(app.innerHTML,/data-action="go-reports"/);
 }finally{profile.role='head_administrator';profile.role_label='Head of Administrator';chrome.runtime.sendMessage=original;}
});

test('Refreshing Reports preserves the opened monthly review and delivery workspace',async()=>{
 await navigate('reports');assert.match(app.innerHTML,/<details class="monthly-workspace" >/);
 handlers.toggle({target:{classList:{contains:name=>name==='monthly-workspace'},open:true}});
 await handlers.click({target:{closest:()=>({dataset:{action:'refresh'},setAttribute(){},removeAttribute(){},isConnected:true})}});
 assert.match(app.innerHTML,/<details class="monthly-workspace" open>/);
 handlers.toggle({target:{classList:{contains:name=>name==='monthly-workspace'},open:false}});
});

test('The console theme toggle saves appearance through the worker and preserves language and time',async()=>{
 const original=chrome.runtime.sendMessage,saved=[];
 chrome.runtime.sendMessage=async message=>{if(message.type==='SAVE_PREFERENCES'){saved.push(message.preferences);return {ok:true,data:message.preferences};}return original(message);};
 const button={dataset:{action:'toggle-theme'},setAttribute(){},removeAttribute(){},isConnected:true};
 try{
  await handlers.click({target:{closest:()=>button}});await handlers.click({target:{closest:()=>button}});
  assert.deepEqual(saved,[{language:'en',timeZone:'UTC',theme:'dark',tableSize:'standard'},{language:'en',timeZone:'UTC',theme:'light',tableSize:'standard'}]);
 }finally{chrome.runtime.sendMessage=original;}
});


test('Security events display device, scanner and target with escaped evidence',async()=>{
 const original=chrome.runtime.sendMessage;
 profile.views.push('Security events');
 chrome.runtime.sendMessage=async message=>{
  if(message.type==='API'&&message.path==='/api/events')return {ok:true,data:[{id:'test-event',message:'High risk detected in URL scan',severity:'High',device_name:'Hasan laptop <script>',device_id:'device-test',username:'normal_user',actor:'normal_user',target_display:'URL redacted123',created_at:'2026-10-08T08:00:00Z'}]};
  return original(message);
 };
 try{
  await navigate('events');
  assert.match(app.innerHTML,/<th scope="col">Device<\/th>/);
  assert.match(app.innerHTML,/<th scope="col">User<\/th>/);
  assert.match(app.innerHTML,/Hasan laptop &lt;script&gt;/);
  assert.match(app.innerHTML,/device-test/);assert.match(app.innerHTML,/normal_user/);
  assert.match(app.innerHTML,/URL redacted123/);assert.doesNotMatch(app.innerHTML,/<script>/);
 }finally{chrome.runtime.sendMessage=original;profile.views.pop();}
});
