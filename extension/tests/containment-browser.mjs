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
 const page=await context.newPage();await page.goto('chrome-extension://'+id+'/console.html');await page.getByRole('button',{name:'Continue securely',exact:true}).waitFor();
 await worker.evaluate(async()=>{
  const profile={username:'synthetic-reviewer',role:'head_administrator',views:['Threat blocklist','Incident cases','Website access','My account'],inventory:{linked:true,blocked:false,pending:false}};

  globalThis.testThreatActive=false;globalThis.testIncidentDeleted=false;globalThis.testSafetyRecorded=false;globalThis.testDeviceBlocked=false;globalThis.testIncidentRequests=[];
  globalThis.testBlock={id:'host:'+'a'.repeat(64),kind:'host',fingerprint:'a'.repeat(64),active:true,severity:'High',scan_id:'12345678-1234-4234-8234-123456789abc',case_id:'22345678-1234-4234-8234-123456789abc',case_status:'open',revision:1,target_display:'danger.example',updated_at:new Date().toISOString()};
  globalThis.fetch=async(url,options={})=>{
   if(options.method==='POST'&&/\/api\/cases\//.test(url)){testIncidentRequests.push({url,body:JSON.parse(options.body)});if(url.endsWith('/remove'))testIncidentDeleted=true;if(url.endsWith('/safety'))testSafetyRecorded=true;if(url.endsWith('/block-device'))testDeviceBlocked=true;}
   let data={};if(url.endsWith('/api/admin/me'))data=profile;
   else if(url.endsWith('/extension/scan')){globalThis.testThreatActive=true;data={id:testBlock.scan_id,severity:'High',target_kind:'url',containment:{...testBlock,host:'danger.example'}};}
   else if(url.endsWith('/api/threat-blocks'))data=[{...testBlock,case_id:testIncidentDeleted?null:testBlock.case_id}];
   else if(url.endsWith('/api/cases'))data=testIncidentDeleted?[]:[{id:testBlock.case_id,scan_id:testBlock.scan_id,title:'Synthetic containment investigation',assignee:profile.username,status:'open',severity:'High',revision:1}];
   else if(url.endsWith('/api/cases/'+testBlock.case_id))data={id:testBlock.case_id,scan_id:testBlock.scan_id,title:'Synthetic containment investigation',assignee:profile.username,status:'open',severity:'High',revision:1,device_name:'Synthetic Chrome test device',containment:testBlock,device_protection:{registered:true,blocked:testDeviceBlocked,revision:1},safety_plan:{recorded_by:testSafetyRecorded?'synthetic-reviewer':null,actions:[{code:'user_notified',description:'Notify the affected user through an approved channel.',completed:testSafetyRecorded}]},notes:[],timeline:[{action:'created',actor:'system'}]};
   else if(url.endsWith('/api/scans'))data=[{id:testBlock.scan_id,severity:'High',target_display:'danger.example'}];
   else if(url.endsWith('/api/case-assignees'))data=[{username:profile.username}];
   else if(url.endsWith('/api/access/check'))data={containment_checked:true,allowed:!testThreatActive,threat_blocked:testThreatActive,kind:testThreatActive?'threat_block':'temporary'};
   else if(url.endsWith('/api/access/consume'))data={allowed:!testThreatActive,kind:'temporary'};
   return new Response(JSON.stringify(data),{status:200,headers:{'Content-Type':'application/json'}});
  };
  await chrome.storage.session.set({session:{token:'synthetic-browser-test-only',expires_at:new Date(Date.now()+3600000).toISOString(),profile}});
 });
 const sent=await page.evaluate(()=>chrome.runtime.sendMessage({type:'SCAN_URL',target:'https://danger.example/private?token=secret'}));
 assert(sent.ok&&sent.data.protection.blocked);record('Real worker contains synthetic High evidence');
 const rules=await worker.evaluate(()=>chrome.declarativeNetRequest.getDynamicRules());assert.equal(rules.length,2);assert(rules.every(r=>r.priority===10000));record('Chrome installs persistent rules above visit approvals');
 assert(rules.some(r=>r.action.type==='block'&&r.condition.resourceTypes.includes('script')));record('Threat resources are blocked as well as navigation');
 const destination=await context.newPage();await destination.goto('https://danger.example/another-path').catch(()=>{});await destination.waitForURL(u=>u.pathname==='/blocked.html');await destination.getByText('High-risk threat contained',{exact:true}).waitFor();record('Real navigation redirects to the high-risk blocked screen');
 assert.equal(await destination.locator('form[data-form="request"]').count(),0);record('Threat screen does not offer an approval bypass');
 const denied=await destination.evaluate(()=>chrome.runtime.sendMessage({type:'OPEN_APPROVED'}));assert.equal(denied.ok,false);assert.match(denied.error,/High-risk threat is blocked/);record('An approved-visit action cannot override a threat block');
 assert.equal(await worker.evaluate(async()=>typeof testThreatActive!=='undefined'&&!!(await chrome.storage.session.get('session')).session?.token),true,'Isolated fixture session is ready');
 const verifiedState=await page.evaluate(()=>chrome.runtime.sendMessage({type:'STATE'}));assert(verifiedState.ok&&verifiedState.data.profile?.username==='synthetic-reviewer',JSON.stringify(verifiedState));await page.goto('chrome-extension://'+id+'/console.html#blocks');await page.reload();await page.getByRole('heading',{name:'Threat blocklist',exact:true,level:1}).waitFor();assert.equal(await page.getByRole('button',{name:'Investigate',exact:true}).count(),1);record('Blocklist shows the linked investigation');
 assert.equal(await page.locator('form[data-form="block-release"]').count(),0);record('Unresolved investigation has no release control');
 await page.screenshot({path:path.join(output,'threat-blocklist.png'),fullPage:true});await destination.screenshot({path:path.join(output,'threat-blocked.png'),fullPage:true});
 await page.getByRole('button',{name:'Investigate',exact:true}).click();await page.getByRole('heading',{name:'Investigation workspace',exact:true}).waitFor();await page.getByText('Synthetic Chrome test device',{exact:false}).waitFor();assert.equal(new URL(page.url()).hash,'#cases');record('Investigate opens the linked case with affected-device evidence');
 await page.screenshot({path:path.join(output,'incident-workspace.png'),fullPage:true});
 const safety=page.locator('form[data-form="case-safety"]');await safety.locator('input[name="safety_user_notified"]').check();await safety.locator('textarea[name="reason"]').fill('Synthetic operator confirms the affected user was informed.');await safety.getByRole('button',{name:'Save safety review',exact:true}).click();await page.getByText('Last recorded by',{exact:false}).waitFor();assert.equal(await worker.evaluate(()=>testIncidentRequests.some(r=>r.url.endsWith('/safety')&&r.body.checks.includes('user_notified'))),true);record('The shipped UI submits a reviewed safety action');
 await page.getByText('Block affected device',{exact:true}).click();const protect=page.locator('form[data-form="case-block-device"]');await protect.locator('input[name="confirmed"]').check();await protect.locator('textarea[name="reason"]').fill('Synthetic administrator confirms device protection.');await protect.getByRole('button',{name:'Block device access',exact:true}).click();await page.getByText('The affected device is blocked in ExtSecure. Review any unblock separately in device inventory.',{exact:false}).waitFor();assert.equal(await worker.evaluate(()=>testIncidentRequests.some(r=>r.url.endsWith('/block-device')&&r.body.confirmed===true&&r.body.expected_device_revision===1)),true);record('The shipped UI submits confirmed registered-device protection');
 await page.screenshot({path:path.join(output,'incident-safety.png'),fullPage:true});await page.getByText('Remove this incident permanently',{exact:true}).click();const remove=page.locator('form[data-form="case-remove"]');await remove.locator('textarea[name="reason"]').fill('Synthetic duplicate incident removal; preserve its threat block.');await remove.getByRole('button',{name:'Remove incident',exact:true}).click();assert.equal(await worker.evaluate(()=>testIncidentDeleted),false);record('Removal without confirmation sends no delete action');await remove.locator('input[name="confirmed"]').check();await remove.getByRole('button',{name:'Remove incident',exact:true}).click();await page.getByRole('heading',{name:'Investigation workspace',exact:true}).waitFor({state:'hidden'});assert.equal(await worker.evaluate(()=>testIncidentRequests.some(r=>r.url.endsWith('/remove')&&r.body.confirmed===true)),true);record('Confirmed removal clears the selected incident from the shipped UI');assert.equal(await worker.evaluate(async()=>(await chrome.declarativeNetRequest.getDynamicRules()).filter(r=>r.priority===10000).length),2);record('Removing an incident preserves real Chrome threat rules');

 await fs.writeFile(path.join(output,'results.json'),JSON.stringify({synthetic_evidence:true,real_chrome:true,passed:true,checks},null,2));console.log(JSON.stringify({passed:true,checks:checks.length,output}));
}catch(error){const debugPage=context?.pages().find(p=>p.url().includes('/console.html'));if(debugPage){await debugPage.screenshot({path:path.join(output,'failure.png')});console.error((await debugPage.locator('body').innerText()).slice(0,2000));}console.error(JSON.stringify({passed:false,error:error.message}));process.exitCode=1;}finally{await context?.close();}
