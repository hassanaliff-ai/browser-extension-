// UI fixtures only: no personal credentials, provider requests or shared writes.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium}=await import(process.env.EXTSECURE_PLAYWRIGHT_MODULE||'playwright');
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const output=process.env.EXTSECURE_TEST_OUTPUT||path.join(root,'../.private/provider-browser');
await fs.mkdir(output,{recursive:true});
const context=await chromium.launchPersistentContext(path.join(output,'profile'),{channel:'chromium',headless:true,viewport:{width:1400,height:1000},args:['--disable-extensions-except='+root,'--load-extension='+root,'--no-first-run']});
const checks=[];
try {
 const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');
 const id=new URL(worker.url()).hostname,page=await context.newPage(),errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.addInitScript(()=>{
  const evidence={provider:'VirusTotal',status:'available',counts:{malicious:3,suspicious:1,harmless:60,undetected:4},cached:false,analysis_at:'2026-11-14T00:00:00+00:00'};
  const scan={id:'fixture-scan',target_kind:'url',target_display:'https://reserved.example',score:100,severity:'Critical',completeness:'partial',findings:[{title:'Malicious URL',code:'malicious_url',points:80,detail:'Provider reported malicious detections.'}],unknown_codes:['new_domain'],provider_evidence:evidence};
  const incident={id:'fixture-case',scan_id:scan.id,title:'Phishing investigation',severity:'Critical',status:'open',revision:1,assignee:'fixture-head',category_label:'Phishing finding',guidance:'Review the provider evidence.',provider_evidence:evidence,notes:[],timeline:[],safety_plan:{actions:[]}};
  chrome.runtime.sendMessage=async m=>{
   let data={};
   if(m.type==='PREFERENCES')data={language:'en',timeZone:'UTC',animations:false};
   if(m.type==='STATE')data={version:'0.8.56',capabilities:['device-enrollment','chrome-inventory','device-access-choice'],profile:{username:'fixture-head',role:'head_administrator',role_label:'Head administrator',inventory:{linked:true},views:['Overview','Scan a page','Incident cases']}};
   if(m.type==='HEALTH')data={status:'ready',api_origin:'https://api.example'};
   if(m.type==='ACTIVE_TAB')data={url:'https://reserved.example/',host:'reserved.example'};
   if(m.type==='SCAN_URL')data=scan;
   if(m.type==='API'){
    if(m.path==='/api/cases')data=[incident];
    else if(m.path==='/api/cases/fixture-case')data=incident;
    else if(m.path==='/api/scans')data=[scan];
    else if(m.path==='/api/case-assignees')data=[{username:'fixture-head'}];
    else data=[];
   }
   return {ok:true,data};
  };
 });
 await page.goto('chrome-extension://'+id+'/console.html#scan');
 const form=page.locator('[data-form="url-scan"]');await form.waitFor();
 await form.locator('[name="target"]').fill('https://reserved.example/');await form.locator('[type="submit"]').click();
 await page.getByRole('heading',{name:'VirusTotal report'}).waitFor();
 assert.equal(await page.locator('.score').count(),0);
 assert.equal(await page.locator('.provider-evidence strong').first().innerText(),'3');
 checks.push('Scan UI shows the VirusTotal report directly, without a separate numerical score');
 await page.screenshot({path:path.join(output,'scan-provider-evidence.png'),fullPage:true});
 await page.goto('chrome-extension://'+id+'/console.html#cases');
 await page.getByRole('heading',{name:'Investigation workspace'}).waitFor();
 await page.getByText('Incident categories and creation rules',{exact:true}).click();
 assert.match(await page.locator('#main').innerText(),/Phishing finding/);
 assert.equal(await page.locator('.provider-evidence strong').first().innerText(),'3');
 checks.push('Incidents show evidence, categories and investigation rules in the existing workspace');
 await page.screenshot({path:path.join(output,'incident-provider-evidence.png'),fullPage:true});
 await page.setViewportSize({width:390,height:844});
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1),false);
 checks.push('Incident workspace fits a narrow viewport');
 await page.setViewportSize({width:560,height:844});
 await page.goto('chrome-extension://'+id+'/popup.html');
 await page.locator('[data-action="scan-active"]').click();
 await page.getByRole('heading',{name:'VirusTotal report'}).waitFor();
 assert.equal(await page.locator('.provider-evidence strong').first().innerText(),'3');
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1),false);
 await page.screenshot({path:path.join(output,'popup-provider-evidence.png'),fullPage:true});
 checks.push('Wide popup keeps exact provider evidence and result visible without overflow');
 assert.deepEqual(errors,[]);checks.push('No page JavaScript errors');
 await fs.writeFile(path.join(output,'results.json'),JSON.stringify({passed:true,checks,scope:'Real Chrome UI with fixture transport; not a live provider or authentication test'},null,2));
 console.log(JSON.stringify({passed:true,checks}));
}finally{await context.close();}
