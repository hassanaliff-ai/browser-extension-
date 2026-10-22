// Actual Chrome metadata and signed-out device synchronization in an isolated DB.
import path from 'node:path';
import fs from 'node:fs/promises';
import {createHmac} from 'node:crypto';
import assert from 'node:assert/strict';
const {chromium}=await import(process.env.EXTSECURE_PLAYWRIGHT_MODULE||'playwright');
const root=process.env.EXTSECURE_FEEDBACK_EXTENSION,output=process.env.EXTSECURE_FEEDBACK_OUTPUT;
const checks=[];const record=name=>{checks.push(name);console.log('PASS: '+name);};
function otp(secret){let bits='';for(const c of secret)bits+='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c).toString(2).padStart(5,'0');const key=Buffer.from(bits.match(/.{8}/g).map(s=>parseInt(s,2))),counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));const hash=createHmac('sha1',key).update(counter).digest(),offset=hash.at(-1)&15;return String((hash.readUInt32BE(offset)&0x7fffffff)%1000000).padStart(6,'0');}
const fixtures=[];
for(const name of ['Inventory enabled fixture','Inventory disabled fixture']){
 const folder=path.join(output,name.replaceAll(' ','-'));await fs.mkdir(folder);
 await fs.writeFile(path.join(folder,'manifest.json'),JSON.stringify({manifest_version:3,name,version:'1.0'}));fixtures.push(folder);
}
const paths=[root,...fixtures].join(',');
const context=await chromium.launchPersistentContext(path.join(output,'profile'),{channel:'chromium',headless:true,timeout:20000,viewport:{width:1440,height:1000},args:['--disable-extensions-except='+paths,'--load-extension='+paths,'--no-first-run']});
let page;
try{
 const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');const id=new URL(worker.url()).hostname;
 page=await context.newPage();page.setDefaultTimeout(15000);const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('chrome-extension://'+id+'/console.html');
 const message=async body=>{const r=await page.evaluate(input=>chrome.runtime.sendMessage(input),body);assert(r.ok,r.error);return r.data;};
 const origin=await page.evaluate(async()=> (await import(chrome.runtime.getURL('core.js'))).API_ORIGIN);
 const chromeItems=await page.evaluate(()=>chrome.management.getAll());
 const disabled=chromeItems.find(x=>x.name==='Inventory disabled fixture');assert(disabled);
 await page.evaluate(id=>chrome.management.setEnabled(id,false),disabled.id);
 const form=page.locator('[data-form="login"]');await form.locator('[name="username"]').fill('feedback-head');await form.locator('[name="password"]').fill(process.env.EXTSECURE_TEST_PASSWORD);await form.locator('[type="submit"]').click();
 const verify=page.locator('[data-form="verify"]');await verify.waitFor();await verify.locator('[name="code"]').fill(otp(process.env.EXTSECURE_TEST_HEAD_SECRET));await verify.locator('[type="submit"]').click();await page.locator('.page-title').waitFor();
 const connected=await message({type:'CONNECT_DEVICE',name:'Isolated Chrome inventory',initial_access:'trusted'});
 await page.goto('chrome-extension://'+id+'/console.html#account');
 await page.reload();
 await page.getByRole('button',{name:'Sync Chrome extensions',exact:true}).waitFor();
 assert.equal((await message({type:'STATE'})).profile.inventory.management_permission,true);
 await page.getByRole('button',{name:'Sync Chrome extensions',exact:true}).click();
 await page.getByText(/installed extensions synced:/).waitFor();
 record('Actual inventory UI recognizes granted access and syncs from its dedicated button');
 const expected=await page.evaluate(async()=> (await chrome.management.getAll()).filter(x=>x.type==='extension').map(x=>x.id).sort());
 let result=await message({type:'SYNC_INVENTORY'});assert.equal(result.installed_count,expected.length);record('First sync includes every extension reported by the actual Chrome profile');
 let rows=await message({type:'API',path:'/api/extensions'});let own=rows.filter(x=>x.device_id===connected.device_id&&x.installed);
 assert.deepEqual(own.map(x=>x.extension_key).sort(),expected);assert.equal(own.find(x=>x.extension_key===disabled.id).status,'Disabled');record('Backend inventory contains enabled and disabled fixtures without truncation');
 await page.goto('chrome-extension://'+id+'/console.html#extensions');await page.getByRole('button',{name:'Isolated Chrome inventory',exact:true}).click();
 await page.locator('strong[data-no-translate]').filter({hasText:'Inventory disabled fixture'}).first().waitFor();record('Device-first inventory UI displays the selected profile and its disabled extension');
 await page.screenshot({path:path.join(output,'complete-inventory.png'),fullPage:true});
 await message({type:'API',path:'/api/admin/accounts/feedback-user/role',method:'POST',body:{role:'administrator',reason:'Create an isolated observer for signed-out inventory verification'}});
 async function call(route,body,token){const r=await fetch(origin+'/monitor'+route,{method:body?'POST':'GET',headers:{...(body?{'Content-Type':'application/json'}:{}),...(token?{Authorization:'Bearer '+token}:{})},body:body?JSON.stringify(body):undefined});assert(r.ok,`Observer request ${route}: ${r.status}`);return r.json();}
 const challenge=await call('/api/admin/login',{username:'feedback-user',password:process.env.EXTSECURE_TEST_PASSWORD});
 const observer=await call('/api/admin/verify',{challenge_token:challenge.challenge_token,totp_code:otp(process.env.EXTSECURE_TEST_USER_SECRET)});
 await message({type:'LOGOUT'});assert(!(await message({type:'STATE'})).profile);record('Target Chrome profile is signed out while its device pairing remains');
 const enabled=chromeItems.find(x=>x.name==='Inventory enabled fixture');assert(enabled);
 await page.evaluate(id=>chrome.management.setEnabled(id,false),enabled.id);
 let changed=false;
 for(let i=0;i<40;i++){
  rows=await call('/api/extensions',undefined,observer.access_token);
  if(rows.some(x=>x.device_id===connected.device_id&&x.extension_key===enabled.id&&x.status==='Disabled')){changed=true;break;}
  await new Promise(r=>setTimeout(r,250));
 }
 assert(changed,'Signed-out change did not reach the backend');record('Actual Chrome enable/disable event refreshes inventory without an account session');
 assert(!(await message({type:'STATE'})).profile);record('Background inventory sync does not grant or restore an account session');
 assert.deepEqual(errors,[]);record('No page JavaScript errors');
 await fs.writeFile(path.join(output,'results.json'),JSON.stringify({passed:checks.length,checks},null,2));
}catch(error){if(page)await page.screenshot({path:path.join(output,'inventory-failure.png'),fullPage:true});throw error;}
finally{await context.close();}
