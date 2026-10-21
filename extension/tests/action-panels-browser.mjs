// Native dialogs and Chrome storage; synthetic inventory, no production writes.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const output=process.env.EXTSECURE_TEST_OUTPUT||path.join(root,'../.private/action-panels-browser');
const pw=await import(process.env.EXTSECURE_PLAYWRIGHT_MODULE||'playwright');const {chromium}=pw.default??pw;
const version=JSON.parse(await fs.readFile(path.join(root,'manifest.json'),'utf8')).version;
const checks=[];let context,page;const record=name=>{checks.push({name,passed:true});console.log(JSON.stringify(checks.at(-1)));};
try{
 await fs.mkdir(output,{recursive:true});
 context=await chromium.launchPersistentContext(path.join(output,'profile'),{channel:'chromium',headless:true,viewport:{width:1440,height:1000},reducedMotion:'no-preference',args:['--disable-extensions-except='+root,'--load-extension='+root,'--no-first-run']});
 const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');const id=new URL(worker.url()).hostname;
 await worker.evaluate(()=>chrome.storage.local.set({preferences:{theme:'light',animations:true,language:'en',timeZone:'UTC',tableSize:'standard'}}));
 await context.addInitScript(version=>{
  const original=chrome.runtime.sendMessage.bind(chrome.runtime);
  const profile={username:'interface-review',display_name:'Interface review',role:'head_administrator',role_label:'Head administrator',views:['Overview','Devices','Extensions','My account','Website access'],inventory:{linked:false},approvable_roles:['normal_user','manager','administrator']};
  const devices=[{id:'device-one',name:'Example workstation',registered:true,online:true,status:'Active',access_status:'Trusted',blocked:false,pending:false,operating_system:'Windows',requested_by:'example-user',inventory_revision:3,revision:2,last_sync:new Date().toISOString(),last_heartbeat:new Date().toISOString(),highest_severity:'Low',scan_count:12}];
  window.reviewTest={calls:[],failNext:false,delay:false,profile,devices};
  chrome.runtime.sendMessage=async message=>{
   if(message.type==='STATE')return {ok:true,data:{profile,version,capabilities:['device-enrollment','chrome-inventory','device-access-choice']}};
   if(message.type==='HEALTH')return {ok:true,data:{status:'ready',service:'TestAPI'}};
   if(message.type==='CONNECT_DEVICE'){window.reviewTest.calls.push(message);profile.inventory={linked:true,device_id:'added-device',device_name:message.name||'Added Chrome device',last_sync:new Date().toISOString()};return {ok:true,data:{inventory_status:'ready',enabled_count:2,installed_count:2}};}
   if(message.type==='API'){
    if(message.method==='POST'){
     window.reviewTest.calls.push(message);
     if(window.reviewTest.delay)await new Promise(resolve=>setTimeout(resolve,650));
     if(window.reviewTest.failNext){window.reviewTest.failNext=false;return {ok:false,status:409,error:'This record changed. Refresh it before applying another decision.'};}
     if(message.path.endsWith('/remove'))devices[0].inventory_removed=true;
     if(message.path.endsWith('/restore'))devices[0].inventory_removed=false;
     return {ok:true,data:{status:'saved'}};
    }
    if(message.path==='/api/devices')return {ok:true,data:devices};
    if(message.path==='/api/extensions')return {ok:true,data:[{id:'extension-one',name:'Example PDF reader',device_id:'device-one',extension_key:'a'.repeat(32),version:'1.0',installed:true,status:'Enabled',may_enable:true,may_disable:true,inventory_revision:2,control:{revision:0}}]};
    return {ok:true,data:[]};
   }
   return original(message);
  };
 },version);
 page=await context.newPage();const errors=[];page.on('pageerror',error=>errors.push(error.message));
 await page.goto('chrome-extension://'+id+'/console.html#devices');await page.getByRole('heading',{name:'Device inventory',exact:true}).waitFor();
 await page.locator('[data-action-title="Add this device"]>summary').click();
 let dialog=page.getByRole('dialog');await dialog.waitFor();
 assert.equal(await dialog.locator('input[name=initial_access]').count(),2);
 assert.equal(await dialog.locator('input[name=initial_access]:checked').count(),0);
 await dialog.getByRole('button',{name:'Add this device',exact:true}).click();
 assert.equal(await page.evaluate(()=>reviewTest.calls.length),0);
 assert(await dialog.getByRole('alert').filter({hasText:'Choose a device access option'}).isVisible());
 record('Add device opens a focused dialog with explicit required trust choice cards');
 await dialog.locator('[name=initial_access][value=trusted]').check();
 await page.screenshot({path:path.join(output,'add-device-light.png'),fullPage:false,animations:'disabled'});
 await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
 assert.equal(await page.getByRole('dialog').count(),0);assert.equal(await page.evaluate(()=>reviewTest.calls.length),0);
 await page.locator('[data-action-title="Add this device"]>summary').click();dialog=page.getByRole('dialog');
 assert.equal(await dialog.locator('[name=initial_access]:checked').count(),0);
 record('Cancel never adds a device and clears the prior access decision');
 await dialog.locator('[name=initial_access][value=trusted]').check();
 await dialog.getByText('Optional device details',{exact:true}).click();await dialog.locator('[name=name]').fill('My Chrome workstation');
 await dialog.getByRole('button',{name:'Add this device',exact:true}).click();
 await page.waitForFunction(()=>!document.querySelector('dialog[open]'));
 assert.equal(await page.evaluate(()=>reviewTest.calls[0].initial_access),'trusted');
 record('Add device submits the chosen access level through the existing connection action');
 const row=page.locator('tr').filter({has:page.getByText('Example workstation',{exact:true})});
 const remove=row.locator('[data-action-title="Remove"]>summary');await remove.focus();await page.keyboard.press('Enter');
 dialog=page.getByRole('dialog',{name:'Remove device',exact:true});await dialog.waitFor();
 assert(await dialog.getByText('Selected device',{exact:true}).isVisible());assert(await dialog.getByText('Example workstation',{exact:true}).isVisible());
 record('Keyboard activation opens removal review with the exact selected device');
 for(let i=0;i<8;i++){await page.keyboard.press('Tab');assert(await page.evaluate(()=>!!document.activeElement.closest('dialog')));}
 record('Native dialog keeps keyboard focus inside the active review');
 await dialog.locator('[name=reason]').fill('Retire this duplicate inventory record after review.');await dialog.locator('[name=confirmed]').check();
 await page.screenshot({path:path.join(output,'remove-device-light.png'),fullPage:false,animations:'disabled'});
 await page.keyboard.press('Escape');assert.equal(await page.getByRole('dialog').count(),0);
 assert(await remove.evaluate(el=>document.activeElement===el));
 record('Escape cancels safely and returns focus to the originating row action');
 await remove.click();dialog=page.getByRole('dialog',{name:'Remove device',exact:true});
 assert.equal(await dialog.locator('[name=confirmed]').isChecked(),false);
 const before=await page.evaluate(()=>reviewTest.calls.length);
 await dialog.getByRole('button',{name:'Remove',exact:true}).click();assert.equal(await page.evaluate(()=>reviewTest.calls.length),before);
 record('A cancelled confirmation cannot carry into another removal attempt');
 await worker.evaluate(()=>chrome.storage.local.set({preferences:{theme:'dark',animations:false,language:'en',timeZone:'UTC',tableSize:'standard'}}));
 await page.waitForFunction(()=>document.documentElement.dataset.motion==='off'&&document.documentElement.dataset.theme==='dark');
 assert.equal(await dialog.evaluate(el=>getComputedStyle(el).animationName),'none');
 assert.equal(await dialog.locator('[name=reason]').inputValue(),'Retire this duplicate inventory record after review.');
 record('Motion and theme settings update an open review without discarding its draft');
 await page.setViewportSize({width:390,height:844});
 const box=await dialog.boundingBox();assert(box.width<=390&&box.height<=844);
 await page.screenshot({path:path.join(output,'remove-device-mobile-dark.png'),fullPage:false,animations:'disabled'});
 record('Review dialogs fit narrow viewports and retain visible actions');
 await page.evaluate(()=>{reviewTest.failNext=true;reviewTest.delay=true;});await dialog.locator('[name=confirmed]').check();
 await dialog.getByRole('button',{name:'Remove',exact:true}).click();await page.keyboard.press('Escape');assert(await dialog.isVisible());
 assert(await dialog.getByRole('button',{name:'Cancel',exact:true}).isDisabled());
 await dialog.getByRole('alert').filter({hasText:'This record changed'}).waitFor();
 assert.equal(await page.evaluate(()=>reviewTest.devices[0].inventory_removed===true),false);
 record('Pending operations cannot be dismissed; a server conflict leaves a visible review error');
 await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
 await worker.evaluate(()=>chrome.storage.local.set({preferences:{theme:'dark',animations:false,language:'ar',timeZone:'Asia/Riyadh',tableSize:'standard'}}));
 await page.waitForFunction(()=>document.documentElement.dir==='rtl');await remove.click();
 dialog=page.getByRole('dialog',{name:'إزالة الجهاز',exact:true});await dialog.waitFor();
 await page.screenshot({path:path.join(output,'remove-device-arabic.png'),fullPage:false,animations:'disabled'});
 record('Arabic review headings, target cards and RTL layouts remain usable');
 await page.keyboard.press('Escape');
 await worker.evaluate(()=>chrome.storage.local.set({preferences:{theme:'light',animations:false,language:'en',timeZone:'UTC',tableSize:'standard'}}));
 await page.waitForFunction(()=>document.documentElement.lang==='en');await page.setViewportSize({width:1440,height:1000});
 await remove.click();dialog=page.getByRole('dialog',{name:'Remove device',exact:true});await dialog.locator('[name=confirmed]').check();
 await dialog.getByRole('button',{name:'Remove',exact:true}).click();await page.waitForFunction(()=>!document.querySelector('dialog[open]'));
 const removed=await page.evaluate(()=>reviewTest.calls.filter(call=>call.path?.endsWith('/remove')).at(-1));
 assert.equal(removed.body.expected_revision,3);assert.equal(removed.body.confirmed,true);
 record('Confirmed removal preserves the exact record, revision and required confirmation payload');
 await page.locator('[name=device_filter]').selectOption('removed');await row.waitFor();
 await page.locator('[data-action-title="Restore to inventory"]>summary').click();
 dialog=page.getByRole('dialog',{name:'Restore device',exact:true});await dialog.waitFor();
 assert.equal(await dialog.getAttribute('data-action-tone'),'restore');
 assert(await dialog.getByText('Restore this record to active inventory. Security history is retained.',{exact:true}).isVisible());
 await page.screenshot({path:path.join(output,'restore-device.png'),fullPage:false,animations:'disabled'});
 record('Removed device history offers a distinct restore review with accurate consequences');
 assert.deepEqual(errors,[]);record('No uncaught JavaScript errors in the add/cancel/remove/restore flows');
 await fs.writeFile(path.join(output,'results.json'),JSON.stringify({passed:true,real_chrome:true,synthetic_backend:true,checks},null,2));console.log(JSON.stringify({passed:true,checks:checks.length,output}));
}catch(error){if(page)await page.screenshot({path:path.join(output,'failure.png'),fullPage:true}).catch(()=>{});console.error(JSON.stringify({passed:false,error:error.message}));process.exitCode=1;}finally{await context?.close();}
