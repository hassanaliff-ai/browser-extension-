import test from 'node:test';
import assert from 'node:assert/strict';
import {VERSION} from '../core.js';

// Execute the actual UI module and its registered DOM handlers. Chrome and the
// DOM are test doubles; this is not a claim of a live Chrome permission test.
const handlers={},calls=[],toast={hidden:true};
const app={innerHTML:'',addEventListener:(name,handler)=>handlers[name]=handler};
const main={focus(){}};
globalThis.location={protocol:'chrome-extension:',hash:'#devices'};
globalThis.window={history:{replaceState(){}},addEventListener(){}};
globalThis.document={body:{classList:{contains:()=>false},querySelectorAll:()=>[]},
 documentElement:{},querySelector:selector=>({'#app':app,'#toast':toast,'#main':main}[selector]),
 createTreeWalker:()=>({nextNode:()=>null})};
globalThis.NodeFilter={SHOW_TEXT:4};
globalThis.MutationObserver=class {observe(){}};
// Don't leave toast timers running or alter the standard test scheduler.
globalThis.setTimeout=()=>0;
const profile={username:'test-head',display_name:'Test Head',role:'head_administrator',role_label:'Head',
 can_write:['inventory'],views:['Devices','Extensions','My account'],
 inventory:{linked:false,pending:false,blocked:false,enrollment_required:false}};
let failConnect=false,permissionCalls=0,workerVersion=VERSION,workerCapabilities=['device-enrollment','chrome-inventory','device-access-choice'],reloads=0;
globalThis.chrome={runtime:{id:'a'.repeat(32),sendMessage:async message=>{
 calls.push(message);
 if(message.type==='PREFERENCES')return {ok:true,data:{language:'en',timeZone:'UTC'}};
 if(message.type==='STATE')return {ok:true,data:{profile:structuredClone(profile),version:workerVersion,capabilities:workerCapabilities}};
 if(message.type==='API')return {ok:true,data:[]};
 if(message.type==='CONNECT_DEVICE'){
  if(failConnect)return {ok:false,error:'The API is unavailable.'};
  profile.inventory.linked=true;profile.inventory.device_name='Windows Chrome';
  return {ok:true,data:{linked:true,pending:false,blocked:false,inventory_status:'permission_required'}};
 }
 if(message.type==='SYNC_INVENTORY')return {ok:true,data:{enabled_count:3}};
 throw new Error('Unexpected message '+message.type);
},reload:()=>reloads++},permissions:{request:()=>{permissionCalls++;return Promise.resolve(true);}}};
globalThis.FormData=class {constructor(form){this.form=form;}*[Symbol.iterator](){yield* Object.entries(this.form.values??{});}};
await import('../ui.js');

function submission(values={initial_access:'trusted'}) {
 const error={hidden:true,focus(){}},button={innerHTML:'Add this device',disabled:false,isConnected:true,
  setAttribute(){},removeAttribute(){},closest:()=>form};
 const form={dataset:{form:'device-connect'},values,reset(){},querySelector:selector=>selector==='.form-error'?error:button};
 return {form,error,button,event:{target:form,preventDefault(){}}};
}
async function clickSync() {
 const button={dataset:{action:'sync-inventory'},innerHTML:'Connect enabled Chrome extensions',isConnected:true,
 setAttribute(){},removeAttribute(){},closest:()=>null};
 await handlers.click({target:{closest:()=>button}});return button;
}

test('Devices renders the primary device form in the real UI module',()=>{
 assert.match(app.innerHTML,/data-form="device-connect"/);assert.match(app.innerHTML,/Add this device/);
 assert.doesNotMatch(app.innerHTML,/data-action="sync-inventory"/);
 assert.match(app.innerHTML,/<select name="initial_access" required>/);
 assert.match(app.innerHTML,/Trusted device/);assert.match(app.innerHTML,/Blocked device/);
 assert(app.innerHTML.indexOf('name="initial_access"')<app.innerHTML.indexOf('type="submit"'));
});
test('The initial access choice is required before any worker connection message',async()=>{
 calls.length=0;const {event,error}=submission({});await handlers.submit(event);
 assert.equal(error.hidden,false);assert.match(error.textContent,/Choose Trusted device or Blocked device/);
 assert.equal(calls.some(call=>call.type==='CONNECT_DEVICE'),false);
});
test('Device submission reaches the worker without invoking any Chrome permission prompt',async()=>{
 calls.length=0;permissionCalls=0;
 chrome.permissions.request=()=>{permissionCalls++;throw new Error('Permission prompt failed');};
 const {event,button,error}=submission();await handlers.submit(event);
 assert(calls.some(call=>call.type==='CONNECT_DEVICE'));assert.equal(permissionCalls,0);
 assert.equal(error.hidden,true);assert.equal(button.disabled,false);
 assert.match(app.innerHTML,/data-action="sync-inventory"/);
 assert.match(toast.textContent,/Device connected/);
});
test('Optional device details and access choice are forwarded by the submit handler',async()=>{
 calls.length=0;await handlers.submit(submission({name:'Hasan Chrome',ip_address:'192.168.1.20',initial_access:'trusted'}).event);
 assert.deepEqual(calls.find(call=>call.type==='CONNECT_DEVICE'),{type:'CONNECT_DEVICE',name:'Hasan Chrome',ip_address:'192.168.1.20',initial_access:'trusted'});
});
test('Device-add API errors appear in the form and release the button',async()=>{
 failConnect=true;
 try {const {event,button,error}=submission();await handlers.submit(event);
  assert.equal(error.hidden,false);assert.equal(error.textContent,'The API is unavailable.');assert.equal(button.disabled,false);
 } finally {failConnect=false;}
});
test('Synchronous Chrome permission errors are visible and do not disable retry',async()=>{
 calls.length=0;chrome.permissions.request=()=>{throw new Error('Permission API failed');};
 const button=await clickSync();assert.equal(toast.textContent,'Permission API failed');assert.equal(button.disabled,false);
 assert.equal(calls.some(call=>call.type==='SYNC_INVENTORY'),false);
});
test('Declined permission keeps the connected device and explains retry',async()=>{
 calls.length=0;chrome.permissions.request=async()=>false;await clickSync();
 assert.match(toast.textContent,/device remains connected/);assert.equal(profile.inventory.linked,true);
 assert.equal(calls.some(call=>call.type==='SYNC_INVENTORY'),false);
});
test('Granted permission connects inventory through the dedicated worker message',async()=>{
 calls.length=0;let requested=false;
 chrome.permissions.request=()=>{requested=true;return Promise.resolve(true);};
 const pending=clickSync();assert.equal(requested,true);await pending;
 assert(calls.some(call=>call.type==='SYNC_INVENTORY'));assert.match(toast.textContent,/3 enabled Chrome extensions synced/);
});
test('Missing permission API is reported with recovery instructions',async()=>{
 calls.length=0;chrome.permissions.request=undefined;await clickSync();
 assert.match(toast.textContent,/Reload ExtSecure and reopen/);assert.equal(calls.some(call=>call.type==='SYNC_INVENTORY'),false);
});
test('Stale extension tabs report how to reopen the live console',async()=>{
 const {send}=await import('../transport.js'),original=chrome.runtime.sendMessage;
 chrome.runtime.sendMessage=async()=>{throw new Error('Extension context invalidated.');};
 try {await assert.rejects(send({type:'STATE'}),/close this tab.*reopen the console/);}
 finally {chrome.runtime.sendMessage=original;}
});

test('An old worker hides unsupported device actions and offers direct restart',async()=>{
 workerVersion='0.6.0';workerCapabilities=[];calls.length=0;
 const button={dataset:{action:'refresh'},setAttribute(){},removeAttribute(){},closest:()=>null};
 await handlers.click({target:{closest:()=>button}});
 assert.match(app.innerHTML,/Console .*Worker 0\.6\.0/);
 assert.match(app.innerHTML,/data-action="restart-extension"/);
 assert.doesNotMatch(app.innerHTML,/data-form="device-connect"/);
 assert.doesNotMatch(app.innerHTML,/data-action="sync-inventory"/);
 assert.equal(calls.some(call=>call.type==='CONNECT_DEVICE'||call.type==='SYNC_INVENTORY'),false);
});
test('Restart uses Chrome runtime directly without another unsupported worker message',async()=>{
 calls.length=0;
 const button={dataset:{action:'restart-extension'},setAttribute(){},removeAttribute(){},closest:()=>null};
 await handlers.click({target:{closest:()=>button}});
 assert.equal(reloads,1);assert.equal(calls.length,0);assert.match(toast.textContent,/Reopen it from the Chrome extension icon/);
});
test('An unknown action becomes an actionable worker-update error',async()=>{
 const {send}=await import('../transport.js'),original=chrome.runtime.sendMessage;
 chrome.runtime.sendMessage=async()=>({ok:false,error:'Unknown extension action.'});
 try {await assert.rejects(send({type:'CONNECT_DEVICE'}),error=>error.code==='EXTENSION_UPDATE_REQUIRED'&&/Restart ExtSecure/.test(error.message));}
 finally {chrome.runtime.sendMessage=original;}
});
test('After worker update the device and inventory actions are restored',async()=>{
 workerVersion=VERSION;workerCapabilities=['device-enrollment','chrome-inventory','device-access-choice'];
 const button={dataset:{action:'refresh'},setAttribute(){},removeAttribute(){},closest:()=>null};
 await handlers.click({target:{closest:()=>button}});
 assert.match(app.innerHTML,/data-form="device-connect"/);assert.match(app.innerHTML,/data-action="sync-inventory"/);
 assert.doesNotMatch(app.innerHTML,/data-action="restart-extension"/);
});
test('A matching version without inventory capabilities is also detected as incompatible',async()=>{
 const {inventoryCompatibility}=await import('../transport.js');
 assert.equal(inventoryCompatibility({version:VERSION}).ready,false);
 assert.equal(inventoryCompatibility({version:VERSION,capabilities:['device-enrollment']}).ready,false);
 assert.equal(inventoryCompatibility({version:VERSION,capabilities:['device-enrollment','chrome-inventory']}).ready,false);
 assert.equal(inventoryCompatibility({version:VERSION,capabilities:['device-enrollment','chrome-inventory','device-access-choice']}).ready,true);
});

test('Blocked selection is forwarded before registration and shown as the chosen result',async()=>{
 const original=chrome.runtime.sendMessage;profile.inventory={linked:false,pending:false,blocked:false};calls.length=0;
 chrome.runtime.sendMessage=async message=>{
  if(message.type==='CONNECT_DEVICE'){
   calls.push(message);profile.inventory={linked:true,pending:false,blocked:true};
   return {ok:true,data:{blocked:true,pending:false,inventory_status:'blocked'}};
  }
  return original(message);
 };
 try {await handlers.submit(submission({initial_access:'blocked'}).event);
  assert.equal(calls.find(call=>call.type==='CONNECT_DEVICE').initial_access,'blocked');
  assert.match(toast.textContent,/Device added as blocked/);assert.doesNotMatch(app.innerHTML,/data-action="sync-inventory"/);
 } finally {chrome.runtime.sendMessage=original;profile.inventory={linked:true,pending:false,blocked:false};}
});

test('Reject hides and disables duration; approve restores it and preserves the selected duration',()=>{
 const field={hidden:false},duration={value:'168',disabled:false,required:true,closest:()=>field};
 const decision={value:'reject'};
 const form={dataset:{form:'access-review'},querySelector:selector=>selector==='[name="duration"]'?duration:decision};
 const event={target:{name:'decision',form,hasAttribute:()=>false,matches:()=>false}};
 handlers.change(event);
 assert.equal(field.hidden,true);assert.equal(duration.disabled,true);assert.equal(duration.required,false);
 decision.value='approve';handlers.change(event);
 assert.equal(field.hidden,false);assert.equal(duration.disabled,false);assert.equal(duration.required,true);
 assert.equal(duration.value,'168');
 decision.value='reject';handlers.change(event);
 assert.equal(field.hidden,true);assert.equal(duration.disabled,true);
});

test('Unrelated decision controls do not change the website duration',()=>{
 let queried=false;
 const form={dataset:{form:'policy-review'},querySelector(){queried=true;}};
 handlers.change({target:{name:'decision',form,hasAttribute:()=>false,matches:()=>false}});
 assert.equal(queried,false);
});
