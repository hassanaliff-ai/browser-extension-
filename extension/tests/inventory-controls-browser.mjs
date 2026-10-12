// Real Chrome management operations on a disposable harmless extension.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const output=path.resolve(process.env.EXTSECURE_TEST_OUTPUT||path.join(root,'../.private/inventory-controls-browser'));
const pw=await import(process.env.EXTSECURE_PLAYWRIGHT_MODULE||'playwright');const {chromium}=pw.default??pw;
const checks=[];let context;
const record=name=>checks.push({name,passed:true});
try{
 await fs.mkdir(output,{recursive:true});const loaded=path.join(output,'extsecure'),fixture=path.join(output,'harmless-extension');
 await fs.cp(root,loaded,{recursive:true,filter:source=>!source.split(path.sep).some(p=>['tests','_metadata','node_modules'].includes(p))});
 // Pregrant the existing optional management permission in this QA-only copy.
 const manifest=JSON.parse(await fs.readFile(path.join(loaded,'manifest.json'),'utf8'));manifest.permissions.push('management');manifest.optional_permissions=manifest.optional_permissions.filter(p=>p!=='management');
 await fs.writeFile(path.join(loaded,'manifest.json'),JSON.stringify(manifest));
 await fs.mkdir(fixture,{recursive:true});await fs.writeFile(path.join(fixture,'manifest.json'),JSON.stringify({manifest_version:3,name:'Harmless Inventory QA Fixture',version:'1.0',background:{service_worker:'worker.js'}}));await fs.writeFile(path.join(fixture,'worker.js'),'chrome.runtime.onInstalled.addListener(()=>{});');
 context=await chromium.launchPersistentContext(path.join(output,'profile'),{channel:'chromium',headless:true,viewport:{width:1440,height:1100},args:['--disable-extensions-except='+loaded+','+fixture,'--load-extension='+loaded+','+fixture,'--no-first-run']});
 let worker=context.serviceWorkers().find(w=>w.url().endsWith('/background.js'));
 if(!worker)worker=await context.waitForEvent('serviceworker',{predicate:w=>w.url().endsWith('/background.js')});
 const id=new URL(worker.url()).hostname;const target=await worker.evaluate(async()=>(await chrome.management.getAll()).find(e=>e.name==='Harmless Inventory QA Fixture').id);
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto('chrome-extension://'+id+'/console.html');await page.locator('[data-form="login"]').waitFor();
 await worker.evaluate(async({target,self})=>{
  const deviceId='device-qa';const rowId='11111111-1111-4111-8111-111111111111';
  const profile={username:'inventory-qa',display_name:'Inventory QA',role:'head_administrator',role_label:'Head of Administrator',views:['Overview','Extensions','Devices','My account'],inventory:{linked:true,device_id:deviceId,device_name:'QA workstation'}};
  globalThis.inventoryQa={control:null,enabled:true,present:true,snapshots:[],requests:[],remote:false,removed:[]};
  globalThis.fetch=async(url,options={})=>{
   const body=options.body?JSON.parse(options.body):null;let data=[];
   if(url.endsWith('/api/admin/me'))data=profile;
   else if(url.endsWith('/remove')){inventoryQa.removed.push(url.split('/').at(-2));data={removed:true,history_preserved:true};}
   else if(url.endsWith('/api/devices'))data=[{id:deviceId,name:'QA workstation',registered:true,operating_system:'Windows'},{id:'device-remote',name:'Second QA device',registered:true,operating_system:'Linux'}];
   else if(url.endsWith('/api/extensions'))data=[{id:rowId,name:'Harmless Inventory QA Fixture',extension_key:target,version:'1.0',device_id:deviceId,device_name:'QA workstation',installed:inventoryQa.present,enabled:inventoryQa.enabled,may_enable:true,may_disable:true,protected:false,status:inventoryQa.present?(inventoryQa.enabled?'Enabled':'Disabled'):'Not installed',control:inventoryQa.control??{revision:0}},{id:'22222222-2222-4222-8222-222222222222',name:'Second-device extension',extension_key:'b'.repeat(32),device_id:'device-remote',device_name:'Second QA device',installed:true,status:'Enabled',may_disable:true,may_enable:true,control:{revision:0}},{id:'33333333-3333-4333-8333-333333333333',name:'ExtSecure',extension_key:self,device_id:deviceId,device_name:'QA workstation',installed:true,status:'Enabled',protected:true}];
   else if(url.endsWith('/control')){inventoryQa.control={...body,revision:(inventoryQa.control?.revision??0)+1,status:'pending',error:null};inventoryQa.requests.push(body);data=inventoryQa.control;}
   else if(url.endsWith('/api/inventory/extension-controls'))data=inventoryQa.control&&(inventoryQa.control.status!=='applied'||inventoryQa.control.desired==='blocked')?[{...inventoryQa.control,chrome_id:target,extension_id:rowId}]:[];
   else if(url.endsWith('/receipt')){if(body.revision!==inventoryQa.control.revision)return new Response(JSON.stringify({detail:'A newer extension action is pending.'}),{status:409,headers:{'Content-Type':'application/json'}});inventoryQa.control={...inventoryQa.control,...body};data=inventoryQa.control;}
   else if(url.endsWith('/api/inventory/sync')){inventoryQa.snapshots.push(body);const item=body.extensions.find(e=>e.id===target);inventoryQa.present=!!item;inventoryQa.enabled=item?.enabled??false;data={device_id:deviceId,enabled_count:body.extensions.filter(e=>e.enabled).length,installed_count:body.extensions.length};}
   if(url.endsWith('/api/devices')||url.endsWith('/api/extensions'))data=data.map(row=>({...row,inventory_removed:inventoryQa.removed.includes(row.id),inventory_revision:1}));
   return new Response(JSON.stringify(data),{status:200,headers:{'Content-Type':'application/json'}});
  };
  await chrome.storage.local.set({deviceCredential:{token:'synthetic-inventory-qa-only',device_id:deviceId},inventoryConnected:true});
  await chrome.storage.session.set({session:{token:'synthetic-inventory-qa-only',expires_at:new Date(Date.now()+3600000).toISOString(),profile}});
 },{target,self:id});
 await page.goto('chrome-extension://'+id+'/console.html#extensions');await page.reload();await page.getByRole('heading',{name:'Chrome extension inventory',exact:true}).waitFor();
 await page.getByRole('button',{name:'QA workstation',exact:true}).waitFor();assert.equal(await page.locator('table').count(),1);assert.equal(await page.getByText('Harmless Inventory QA Fixture',{exact:true}).count(),0);record('Initial table lists devices without showing their extensions');
 await page.locator('[name="extension_removed"]').check();await page.getByRole('button',{name:'QA workstation',exact:true}).waitFor();assert.equal(await page.getByText('Second-device extension',{exact:true}).count(),0);record('History filter does not reveal extensions before clicking a device');await page.locator('[name="extension_removed"]').uncheck();await page.getByRole('button',{name:'QA workstation',exact:true}).waitFor();
 await page.screenshot({path:path.join(output,'device-table.png'),fullPage:true});
 async function chooseDevice(id){if(await page.getByRole('button',{name:'Back to devices',exact:true}).count()){await page.getByRole('button',{name:'Back to devices',exact:true}).click();}await page.locator(`[data-action="open-device-extensions"][data-device-id="${id}"]`).click();await page.getByRole('button',{name:'Back to devices',exact:true}).waitFor();}
 await chooseDevice('device-qa');
 assert.equal(await page.getByText('Second-device extension',{exact:true}).count(),0);record('Selecting an added device filters its extensions');
 assert.match(await page.locator('body').innerText(),/ExtSecure protected/);record('ExtSecure has no destructive controls');
 async function action(desired){await page.getByText('Manage extension',{exact:true}).click();const form=page.locator('[data-form="extension-control"]');await form.locator('[name="desired"]').selectOption(desired);assert(!await form.locator('[name="confirmed"]').isChecked());await form.locator('[name="reason"]').fill('Synthetic QA approved extension state change');await form.locator('[name="confirmed"]').check();await form.getByRole('button',{name:'Apply',exact:true}).click();await page.waitForFunction(()=>!document.querySelector('#app [aria-busy="true"]')&&!document.querySelector('#app')?.innerText.includes('Working…')&&!!document.querySelector('[data-action="back-extension-devices"]'));}
 await action('disabled');assert.equal(await worker.evaluate(async id=>(await chrome.management.get(id)).enabled,target),false);record('Turn off disables the real harmless Chrome extension');
 assert.match(await page.locator('body').innerText(),/Disabled/);record('Disabled extension remains visible in inventory');
 await action('enabled');assert.equal(await worker.evaluate(async id=>(await chrome.management.get(id)).enabled,target),true);record('Turn on enables the real Chrome extension');
 await action('blocked');assert.equal(await worker.evaluate(async id=>(await chrome.management.get(id)).enabled,target),false);record('Block disables the real Chrome extension');
 await page.evaluate(async id=>chrome.management.setEnabled(id,true),target);
 await page.waitForFunction(async id=>!(await chrome.management.get(id)).enabled,target);record('Blocked extension is disabled again after a manual re-enable event');
 await worker.evaluate(()=>{inventoryQa.control={...inventoryQa.control,desired:'enabled',status:'pending',revision:inventoryQa.control.revision+1};});
 await page.getByRole('button',{name:'Apply pending extension controls',exact:true}).click();await page.waitForFunction(()=>!document.querySelector('#app [aria-busy="true"]'));
 await page.waitForFunction(async id=>(await chrome.management.get(id)).enabled,target);record('Pending turn-on directive applies through the target profile button');
 const snapshots=await worker.evaluate(()=>inventoryQa.snapshots);assert(snapshots.some(s=>s.extensions.some(e=>e.id===target&&!e.enabled)));record('Chrome sends actual disabled-state snapshots');
 await page.screenshot({path:path.join(output,'extensions-by-device.png'),fullPage:true});
 await chooseDevice('device-remote');await page.waitForFunction(()=>!document.querySelector('#app [aria-busy="true"]'));assert.equal(await page.getByText('Harmless Inventory QA Fixture',{exact:true}).count(),0);record('Switching device does not mix another device inventory');
 await chooseDevice('device-qa');await page.waitForFunction(()=>!document.querySelector('#app [aria-busy="true"]'));
 const selfRow=page.locator('tr').filter({has:page.getByText('ExtSecure',{exact:true})});assert.equal(await selfRow.locator('[data-form="inventory-remove"]').count(),1);record('Protected ExtSecure row has a Remove from inventory option');
 await selfRow.getByText('Remove',{exact:true}).first().click();const remove=selfRow.locator('[data-form="inventory-remove"]');assert(!await remove.locator('[name="confirmed"]').isChecked());await remove.locator('[name="reason"]').fill('Remove QA inventory entry without uninstalling');await remove.locator('[name="confirmed"]').check();await remove.getByRole('button',{name:'Remove',exact:true}).click();
 await page.waitForFunction(()=>!document.querySelector('#app [aria-busy="true"]'));assert.equal(await page.locator('tr').filter({has:page.getByText('ExtSecure',{exact:true})}).count(),0);assert.equal(await worker.evaluate(async()=> (await chrome.management.getSelf()).enabled),true);record('Inventory removal hides ExtSecure without uninstalling protection');
 await page.locator('[name="extension_removed"]').check();await page.waitForFunction(()=>!document.querySelector('#app [aria-busy="true"]'));await page.getByText('Restore to inventory',{exact:true}).waitFor();record('Removed extension history can be displayed and restored');
 await page.goto('chrome-extension://'+id+'/console.html#devices');await page.reload();await page.getByRole('heading',{name:'Device inventory',exact:true}).waitFor();const remoteRow=page.locator('tr').filter({has:page.getByText('Second QA device',{exact:true})});await remoteRow.getByText('Remove',{exact:true}).first().click();const removeDevice=remoteRow.locator('[data-form="inventory-remove"]');await removeDevice.locator('[name="reason"]').fill('Remove retired QA device from inventory');await removeDevice.locator('[name="confirmed"]').check();await removeDevice.getByRole('button',{name:'Remove',exact:true}).click();await page.waitForFunction(()=>!document.querySelector('#app [aria-busy="true"]'));assert.equal(await page.locator('tr').filter({has:page.getByText('Second QA device',{exact:true})}).count(),0);record('Device Remove hides the selected device from active inventory');
 await page.locator('[name="device_filter"]').selectOption('removed');await page.getByText('Second QA device',{exact:true}).waitFor();record('Removed device remains available in the history filter');
 await page.screenshot({path:path.join(output,'inventory-removal.png'),fullPage:true});
 assert.deepEqual(errors,[]);record('No uncaught console JavaScript errors');
 await fs.writeFile(path.join(output,'results.json'),JSON.stringify({passed:true,checks,note:'QA-only management pregrant; synthetic backend; real Chrome enable/disable/block operations. Uninstall confirmation tested with unit doubles.'},null,2));console.log(JSON.stringify({passed:true,checks:checks.length}));
}finally{await context?.close();}
