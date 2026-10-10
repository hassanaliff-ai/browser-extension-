// Real Chrome DNR verification using synthetic evidence in an isolated profile.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const output=path.resolve(process.env.EXTSECURE_TEST_OUTPUT||path.join(root,'../.private/containment-browser'));
const pw=await import(process.env.EXTSECURE_PLAYWRIGHT_MODULE||'playwright');
const {chromium}=pw.default??pw;
let context;const checks=[];
const record=name=>checks.push({name,passed:true});
try{
 await fs.mkdir(output,{recursive:true});
 context=await chromium.launchPersistentContext(path.join(output,'profile'),{channel:'chromium',headless:true,viewport:{width:1440,height:1000},args:['--disable-extensions-except='+root,'--load-extension='+root,'--no-first-run']});
 const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');
 const id=new URL(worker.url()).hostname;
 const page=await context.newPage();await page.goto('chrome-extension://'+id+'/console.html');
 await worker.evaluate(async()=>{
  const profile={username:'synthetic-reviewer',role:'head_administrator',views:['Threat blocklist','Incident cases','Website access','My account'],inventory:{linked:true,blocked:false,pending:false}};
  await chrome.storage.session.set({session:{token:'synthetic-browser-test-only',expires_at:new Date(Date.now()+3600000).toISOString(),profile}});
  globalThis.testThreatActive=false;
  globalThis.testBlock={id:'host:'+'a'.repeat(64),kind:'host',fingerprint:'a'.repeat(64),active:true,severity:'High',scan_id:'12345678-1234-4234-8234-123456789abc',case_id:'22345678-1234-4234-8234-123456789abc',case_status:'open',revision:1,target_display:'danger.example',updated_at:new Date().toISOString()};
  globalThis.fetch=async(url)=>{
   let data={};if(url.endsWith('/api/admin/me'))data=profile;
   else if(url.endsWith('/extension/scan')){globalThis.testThreatActive=true;data={id:testBlock.scan_id,severity:'High',target_kind:'url',containment:{...testBlock,host:'danger.example'}};}
   else if(url.endsWith('/api/threat-blocks'))data=[testBlock];
   else if(url.endsWith('/api/cases'))data=[{id:testBlock.case_id,scan_id:testBlock.scan_id,title:'Synthetic containment investigation',assignee:profile.username,status:'open',severity:'High',revision:1}];
   else if(url.endsWith('/api/cases/'+testBlock.case_id))data={id:testBlock.case_id,scan_id:testBlock.scan_id,title:'Synthetic containment investigation',assignee:profile.username,status:'open',severity:'High',revision:1,device_name:'Synthetic Chrome test device',containment:testBlock,notes:[],timeline:[{action:'created',actor:'system'}]};
   else if(url.endsWith('/api/scans'))data=[{id:testBlock.scan_id,severity:'High',target_display:'danger.example'}];
   else if(url.endsWith('/api/case-assignees'))data=[{username:profile.username}];
   else if(url.endsWith('/api/access/check'))data={containment_checked:true,allowed:!testThreatActive,threat_blocked:testThreatActive,kind:testThreatActive?'threat_block':'temporary'};
   else if(url.endsWith('/api/access/consume'))data={allowed:!testThreatActive,kind:'temporary'};
   else if(url.endsWith('/api/controls/navigation'))data={recorded:true};
   return new Response(JSON.stringify(data),{status:200,headers:{'Content-Type':'application/json'}});
  };
 });
 const sent=await page.evaluate(()=>chrome.runtime.sendMessage({type:'SCAN_URL',target:'https://danger.example/private?token=secret'}));
 assert(sent.ok&&sent.data.protection.blocked);record('Real worker contains synthetic High evidence');
 const rules=await worker.evaluate(()=>chrome.declarativeNetRequest.getDynamicRules());assert.equal(rules.length,2);assert(rules.every(r=>r.priority===10000));record('Chrome installs persistent rules above visit approvals');
 assert(rules.some(r=>r.action.type==='block'&&r.condition.resourceTypes.includes('script')));record('Threat resources are blocked as well as navigation');
 const destination=await context.newPage();await destination.goto('https://danger.example/another-path').catch(()=>{});await destination.waitForURL(u=>u.pathname==='/blocked.html');await destination.getByText('High-risk threat contained',{exact:true}).waitFor();record('Real navigation redirects to the high-risk blocked screen');
 assert.equal(await destination.locator('form[data-form="request"]').count(),0);record('Threat screen does not offer an approval bypass');
 const denied=await destination.evaluate(()=>chrome.runtime.sendMessage({type:'OPEN_APPROVED'}));assert.equal(denied.ok,false);assert.match(denied.error,/High-risk threat is blocked/);record('An approved-visit action cannot override a threat block');
 await page.goto('chrome-extension://'+id+'/console.html#blocks');await page.getByRole('heading',{name:'Threat blocklist',exact:true,level:1}).waitFor();assert.equal(await page.getByRole('button',{name:'Investigate',exact:true}).count(),1);record('Blocklist shows the linked investigation');
 assert.equal(await page.locator('form[data-form="block-release"]').count(),0);record('Unresolved investigation has no release control');
 await page.screenshot({path:path.join(output,'threat-blocklist.png'),fullPage:true});await destination.screenshot({path:path.join(output,'threat-blocked.png'),fullPage:true});
 await page.getByRole('button',{name:'Investigate',exact:true}).click();await page.getByRole('heading',{name:'Investigation workspace',exact:true}).waitFor();await page.getByText('Synthetic Chrome test device',{exact:false}).waitFor();assert.equal(new URL(page.url()).hash,'#cases');record('Investigate opens the linked case with affected-device evidence');
 await page.screenshot({path:path.join(output,'incident-workspace.png'),fullPage:true});
 await fs.writeFile(path.join(output,'results.json'),JSON.stringify({synthetic_evidence:true,real_chrome:true,passed:true,checks},null,2));console.log(JSON.stringify({passed:true,checks:checks.length,output}));
}catch(error){console.error(JSON.stringify({passed:false,error:error.message}));process.exitCode=1;}finally{await context?.close();}
