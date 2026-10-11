// Real bundled QR decoding and shipped UI in an isolated Chrome profile.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const output=path.resolve(process.env.EXTSECURE_TEST_OUTPUT||path.join(root,'../.private/qr-file-browser'));
const pw=await import(process.env.EXTSECURE_PLAYWRIGHT_MODULE||'playwright');
const {chromium}=pw.default??pw;
const checks=[];let context;
const record=name=>checks.push({name,passed:true});
try {
 await fs.mkdir(output,{recursive:true});
 context=await chromium.launchPersistentContext(path.join(output,'profile'),{channel:'chromium',headless:true,viewport:{width:1440,height:1000},args:['--disable-extensions-except='+root,'--load-extension='+root,'--no-first-run']});
 const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');
 const id=new URL(worker.url()).hostname;
 const page=await context.newPage(),errors=[],initialPages=context.pages().length;page.on('pageerror',e=>errors.push(e.message));
 await page.goto('chrome-extension://'+id+'/console.html');await page.locator('[data-form="login"]').waitFor();
 await worker.evaluate(async()=>{
  const profile={username:'synthetic-reviewer',display_name:'QR Safety Tester',role:'head_administrator',views:['Overview','Downloaded-file checks','My account'],inventory:{linked:true}};
  globalThis.qrRequests=[];
  globalThis.fetch=async(url,options={})=>{
   let data=[];
   if(url.endsWith('/api/admin/me'))data=profile;
   if(options.body)qrRequests.push({url,body:JSON.parse(options.body)});
   if(url.endsWith('/extension/scan'))data={id:'qr-test',target_kind:'url',target_display:'example.com',severity:'Low',score:0,findings:[],completeness:'complete'};
   if(url.endsWith('/downloads/scan'))data={id:'file-test',target_kind:'download',target_display:'Synthetic hash lookup',severity:'Low',score:0,findings:[],completeness:'complete',file_lookup:{verdict:'clear'}};
   return new Response(JSON.stringify(data),{status:200,headers:{'Content-Type':'application/json'}});
  };
  await chrome.storage.session.set({session:{token:'synthetic-qr-test-only',expires_at:new Date(Date.now()+3600000).toISOString(),profile}});
 });
 await page.goto('chrome-extension://'+id+'/console.html#scan');await page.reload();
 await page.getByRole('heading',{name:'QR link safety check',exact:true}).waitFor();
 const fixture=path.join(root,'tests/fixtures/qr-example.png');
 await page.locator('[name="qrImage"]').setInputFiles(fixture);
 await page.getByRole('button',{name:'Read QR destination',exact:true}).click();
 await page.getByRole('heading',{name:'Review decoded destination',exact:true}).waitFor();
 assert.match(await page.locator('body').innerText(),/https:\/\/example.com\/invoice/);
 assert.doesNotMatch(await page.locator('body').innerText(),/private-token/);
 assert.equal((await worker.evaluate(()=>qrRequests)).length,0);record('Real PNG QR decoded locally with private URL parameters removed and no API call');
 await page.getByRole('button',{name:'Check QR destination',exact:true}).click();
 await page.getByRole('heading',{name:'Risk result',exact:true}).waitFor();
 let requests=await worker.evaluate(()=>qrRequests);assert.equal(requests.length,1);assert.equal(requests[0].body.target,'https://example.com/');record('Explicit QR check uses real worker and existing URL scanner with origin privacy');
 assert.equal(context.pages().length,initialPages);assert(context.pages().every(p=>!p.url().startsWith('https://example.com')));record('QR reading and checking never open the destination');
 await page.screenshot({path:path.join(output,'qr-check.png'),fullPage:true});
 await page.locator('[data-form="qr-scan"] [name="includePath"]').check();await page.getByRole('button',{name:'Check QR destination',exact:true}).click();
 await page.waitForFunction(()=>!document.querySelector('#app [aria-busy="true"]'));
 requests=await worker.evaluate(()=>qrRequests);assert.equal(requests.at(-1).body.target,'https://example.com/invoice');record('Explicit path lookup sends only the reviewed path without private parameters');
 await page.locator('[name="qrImage"]').setInputFiles(path.join(root,'tests/fixtures/qr-javascript.png'));
 assert.equal(await page.locator('[data-form="qr-scan"]').count(),0);
 await page.getByRole('button',{name:'Read QR destination',exact:true}).click();
 await page.locator('[data-form="qr-decode"] .form-error:not([hidden])').waitFor();
 assert.equal(await page.locator('[data-form="qr-scan"]').count(),0);record('Unsafe QR payload rejected and old reviewed destination cleared');
 const blank=await page.evaluate(async()=>{
  const module=await import('./qr-safety.js');const canvas=new OffscreenCanvas(200,200),context=canvas.getContext('2d');context.fillStyle='#fff';context.fillRect(0,0,200,200);const image=await canvas.convertToBlob({type:'image/png'});
  try{await module.decodeQrImage(image);return '';}catch(error){return error.message;}
 });assert.match(blank,/No readable QR code/);record('Valid image without a QR code receives a clear error');
 await page.goto('chrome-extension://'+id+'/console.html#files');await page.reload();await page.locator('[data-form="file-scan"]').waitFor();
 await page.locator('[name="file"]').setInputFiles({name:'invoice.pdf.exe',mimeType:'application/octet-stream',buffer:Buffer.from('Harmless synthetic filename test')});
 await page.locator('[data-filename-warning]:not([hidden])').waitFor();assert.match(await page.locator('[data-filename-warning]').innerText(),/final extension is .exe/);record('Filename warning appears immediately on file selection');
 await page.getByRole('button',{name:'Check file hash',exact:true}).click();await page.getByRole('heading',{name:'Risk result',exact:true}).waitFor();
 assert.match(await page.locator('body').innerText(),/hash result does not cancel/);record('Filename warning survives a Low hash reputation result');
 requests=await worker.evaluate(()=>qrRequests);const fileRequest=requests.find(r=>r.url.endsWith('/downloads/scan'));
 assert.match(fileRequest.body.sha256,/^[a-f0-9]{64}$/);assert(!JSON.stringify(fileRequest.body).includes('invoice.pdf.exe'));record('Filename and file bytes are never sent to backend');
 await page.screenshot({path:path.join(output,'filename-warning.png'),fullPage:true});
 await page.locator('[name="file"]').setInputFiles({name:'quarterly.final.pdf',mimeType:'application/pdf',buffer:Buffer.from('Synthetic ordinary file')});
 assert(await page.locator('[data-filename-warning]').isHidden());record('Ordinary multi-dot filename does not receive a double-extension warning');
 await page.goto('chrome-extension://'+id+'/popup.html');await page.getByRole('button',{name:'QR check',exact:true}).waitFor();await page.getByRole('button',{name:'QR check',exact:true}).click();
 await page.locator('[name="qrImage"]').setInputFiles(fixture);await page.getByRole('button',{name:'Read QR destination',exact:true}).click();await page.getByRole('heading',{name:'Review decoded destination',exact:true}).waitFor();record('Toolbar popup also supports QR upload and destination review');
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1),false);record('QR interface fits the available viewport');
 assert.deepEqual(errors,[]);record('No uncaught JavaScript errors or decoder CSP failures');
 await fs.writeFile(path.join(output,'results.json'),JSON.stringify({passed:true,checks},null,2));console.log(JSON.stringify({passed:true,checks:checks.length}));
} finally {await context?.close();}
