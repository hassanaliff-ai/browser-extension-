// Real MV3 UI/worker regression for the reported AMTSO home-page mismatch.
// API replies are a fixture of the public report; the target is never visited.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium}=await import(process.env.EXTSECURE_PLAYWRIGHT_MODULE||'playwright');
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const output=process.env.EXTSECURE_TEST_OUTPUT||path.join(root,'../.private/page-path-browser');
const target='https://www.amtso.org/check-desktop-phishing-page/';
await fs.mkdir(output,{recursive:true});
const context=await chromium.launchPersistentContext(path.join(output,'profile'),{channel:'chromium',headless:true,viewport:{width:1350,height:1000},args:['--disable-extensions-except='+root,'--load-extension='+root,'--no-first-run']});
let worker,page;
const checks=[];const record=name=>{checks.push(name);console.log(JSON.stringify({passed:true,name}));};
try{
 worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');
 await worker.evaluate(async target=>{
  globalThis.pageChecks=[];
  const profile={username:'page-path-fixture',role:'head_administrator',inventory:{linked:true},views:['Scan a page']};
  const realQuery=chrome.tabs.query.bind(chrome.tabs);
  chrome.tabs.query=async options=>options.active?[{url:target+'?secret=not-sent#local'}]:realQuery(options);
  globalThis.fetch=async(url,options={})=>{
   let data={};
   if(url.endsWith('/api/admin/me'))data=profile;
   if(url.endsWith('/api/v1/check')){
    const submitted=JSON.parse(options.body).url;pageChecks.push(submitted);
    const page=submitted===target;
    data={id:'page-fixture',target_kind:'url',target_display:'www.amtso.org',severity:page?'Critical':'Low',score:page?80:0,completeness:'partial',findings:[],containment:page?{id:'host:fixture',kind:'host',active:true,severity:'Critical',scan_id:'page-fixture'}:null,provider_evidence:{provider:'VirusTotal',status:'available',engine_total:93,counts:page?{malicious:12,suspicious:0,harmless:48,undetected:33}:{malicious:0,suspicious:0,harmless:58,undetected:35},analysis_at:'2026-11-11T05:24:43+00:00',report_id:'f19761934518c3993f38ec9968a19b8d4d48f3ae7b1d9d3c4c6eb2b6e578607f'}};
   }
   return new Response(JSON.stringify(data),{status:200,headers:{'Content-Type':'application/json'}});
  };
  await chrome.storage.session.set({session:{token:'synthetic-page-path-session',expires_at:new Date(Date.now()+3600000).toISOString(),profile}});
  await chrome.storage.local.set({preferences:{theme:'dark',language:'en',timeZone:'UTC'}});
 },target);
 const id=new URL(worker.url()).hostname;page=await context.newPage();
 await page.goto('chrome-extension://'+id+'/console.html#scan');
 const form=page.locator('[data-form="url-scan"]');await form.waitFor();
 assert(await form.locator('[name="includePath"]').isChecked());
 await form.locator('[name="target"]').fill(target+'?secret=not-sent#local');await form.locator('[type="submit"]').click();
 await page.locator('.provider-ratio strong').waitFor();
 assert.equal(await page.locator('.provider-ratio strong').innerText(),'12 / 93');
 assert.equal(await page.locator('[aria-label="ExtSecure risk classification"]').innerText(),'Critical');
 assert.equal(await page.locator('.results > p.code').innerText(),target);
 assert.equal(await worker.evaluate(()=>pageChecks.at(-1)),target);
 record('Manual detector checks the actual page and shows 12 / 93 with its full checked address');
 await page.screenshot({path:path.join(output,'matching-page-report.png'),fullPage:true});
 await form.locator('[name="target"]').fill(target);await form.locator('[name="includePath"]').uncheck();await form.locator('[type="submit"]').click();
 await page.waitForFunction(()=>document.querySelector('.provider-ratio strong')?.textContent==='0 / 93');
 assert.equal(await worker.evaluate(()=>pageChecks.at(-1)),'https://www.amtso.org/');
 record('Home-page-only checking occurs only when explicitly selected');
 await page.setViewportSize({width:560,height:900});await page.goto('chrome-extension://'+id+'/popup.html');
 await page.locator('[data-action="scan-active"]').click();await page.locator('.provider-ratio strong').waitFor();
 assert.equal(await page.locator('.provider-ratio strong').innerText(),'12 / 93');
 assert.equal(await page.locator('[aria-label="ExtSecure risk classification"]').innerText(),'Critical');
 assert.equal(await worker.evaluate(()=>pageChecks.at(-1)),target);
 record('Popup current-page checks preserve the page path');
 await page.goto('chrome-extension://'+id+'/console.html#scan');
 await page.locator('[name="qrImage"]').setInputFiles(process.env.EXTSECURE_PAGE_QR||path.join(root,'tests/fixtures/qr-amtso-page.png'));
 await page.getByRole('button',{name:'Read QR destination',exact:true}).click();
 const qr=page.locator('[data-form="qr-scan"]');await qr.waitFor();assert(await qr.locator('[name="includePath"]').isChecked());
 await qr.locator('[type="submit"]').click();await page.locator('.provider-ratio strong').waitFor();
 assert.equal(await worker.evaluate(()=>pageChecks.at(-1)),target);
 record('QR checks preserve the decoded page path by default');
 const submitted=await worker.evaluate(()=>pageChecks);assert(submitted.every(url=>!url.includes('secret')&&!url.includes('#')));
 record('Private query parameters and fragments never reach the backend');
 await fs.writeFile(path.join(output,'results.json'),JSON.stringify({passed:true,checks,scope:'Actual Chrome UI and worker, fixed report fixture, no target visits or shared database writes'},null,2));
}catch(error){
 if(page){await page.screenshot({path:path.join(output,'failure.png'),fullPage:true});console.error((await page.locator('body').innerText()).slice(-2000));}
 if(worker)console.error(JSON.stringify(await worker.evaluate(()=>pageChecks)));
 throw error;
}finally{await context.close();}
