// Actual Chrome navigation + local HTTP server. Backend replies are isolated
// fixtures; this test never uses personal sessions or writes shared records.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import {fileURLToPath} from 'node:url';
const {chromium}=await import(process.env.EXTSECURE_PLAYWRIGHT_MODULE||'playwright');
const root=process.env.EXTSECURE_NAV_EXTENSION||path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const output=process.env.EXTSECURE_TEST_OUTPUT||path.join(root,'../.private/approved-navigation');
await fs.mkdir(output,{recursive:true});
const requests=[];
const server=http.createServer((req,res)=>{
 requests.push({url:req.url,method:req.method});
 if(req.url==='/redirect'){res.writeHead(302,{Location:'/landing'});return res.end();}
 if(req.url==='/cycle-a'||req.url==='/cycle-b'){res.writeHead(302,{Location:req.url==='/cycle-a'?'/cycle-b':'/cycle-a'});return res.end();}
 res.writeHead(200,{'Content-Type':'text/html','Cache-Control':'no-store'});
 if(req.method==='POST')return res.end('<h1>Form received</h1>');
 res.end('<!doctype html><h1>Approved page ready</h1><form method="post" action="/approved"><input name="fixture" value="local-test"><button>Submit form</button></form>');
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin='http://127.0.0.1:'+server.address().port;
let context;const checks=[];
function record(name){checks.push(name);console.log(JSON.stringify({passed:true,name}));}
try{
 context=await chromium.launchPersistentContext(path.join(output,'profile'),{channel:'chromium',headless:true,viewport:{width:1100,height:800},args:['--disable-extensions-except='+root,'--load-extension='+root,'--no-first-run']});
 context.setDefaultTimeout(12000);
 const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');
 await worker.evaluate(async origin=>{
  globalThis.navAllowed=new Set([origin+'/approved',origin+'/redirect']);globalThis.navConsumes=0;globalThis.navRevoked=false;globalThis.navThreat=false;
  const profile={username:'navigation-fixture',role:'head_administrator',inventory:{linked:true},views:['Website access']};
  globalThis.fetch=async(url,options={})=>{
   let data={};
   if(url.endsWith('/api/admin/me'))data=profile;
   if(/\/api\/access\/(check|consume)$/.test(url)){
    const target=JSON.parse(options.body).target;
    data={allowed:navAllowed.has(target)&&!navRevoked&&!navThreat,threat_blocked:navThreat,kind:'temporary',expires_at:new Date(Date.now()+3600000).toISOString(),containment_checked:true};
    if(url.endsWith('/consume'))navConsumes++;
   }
   return new Response(JSON.stringify(data),{status:200,headers:{'Content-Type':'application/json'}});
  };
  await chrome.storage.session.set({session:{token:'synthetic-navigation-session',expires_at:new Date(Date.now()+3600000).toISOString(),profile}});
 },origin);
 const page=await context.newPage();
 await page.goto(origin+'/approved').catch(()=>{});
 await page.getByRole('heading',{name:'Approved page ready'}).waitFor();
 record('Approved page opens through the real navigation gate');
 const consumed=await worker.evaluate(()=>navConsumes);
 await page.reload();await page.getByRole('heading',{name:'Approved page ready'}).waitFor();
 assert.equal(await worker.evaluate(()=>navConsumes),consumed);
 record('Reload stays on the approved site without another blocked-page cycle');
 await page.getByRole('button',{name:'Submit form'}).click();
 await page.getByRole('heading',{name:'Form received'}).waitFor();
 assert(requests.some(r=>r.method==='POST'&&r.url==='/approved'));
 record('Approved same-address form POST reaches the server without being changed to GET');
 await page.goto(origin+'/redirect').catch(()=>{});
 await page.waitForURL(url=>url.protocol==='chrome-extension:'&&url.pathname==='/blocked.html');
 await page.locator('[data-form="request"]').waitFor();
 assert.match(await page.locator('.blocked-destination').innerText(),/\/landing/);
 assert.equal(requests.filter(r=>r.url==='/redirect').length,1);
 assert(!requests.some(r=>r.url==='/landing'));
 record('Redirect to an unapproved address stops at its actual destination without a reopen loop');
 await page.screenshot({path:path.join(output,'redirect-requires-approval.png'),fullPage:true});
 await worker.evaluate(origin=>navAllowed.add(origin+'/landing'),origin);
 await page.getByRole('button',{name:'Check approval',exact:true}).click();
 await page.getByRole('heading',{name:'Approved page ready'}).waitFor();
 record('Approving the redirected destination opens it successfully');
 await worker.evaluate(()=>{navRevoked=true;});
 const tabId=await worker.evaluate(async()=>{
  const all=await chrome.storage.session.get(null);return Number(Object.keys(all).find(k=>k.startsWith('visit:')).slice(6));
 });
 await worker.evaluate(tabId=>chrome.alarms.create('visit:'+tabId,{when:Date.now()+50}),tabId);
 await page.waitForTimeout(1000);
 const active=await worker.evaluate(async()=>chrome.declarativeNetRequest.getSessionRules());
 assert.equal(active.filter(r=>r.id>=100000).length,0);
 record('Revoked approval removes the reusable permission at revalidation');
 await worker.evaluate(origin=>{navRevoked=false;navAllowed.add(origin+'/cycle-a');navAllowed.add(origin+'/cycle-b');},origin);
 await page.goto(origin+'/cycle-a').catch(()=>{});
 await page.getByRole('alert').filter({hasText:'Automatic reopening stopped'}).waitFor();
 assert(requests.filter(r=>r.url.startsWith('/cycle-')).length<=9);
 record('A genuine server redirect cycle stops with an actionable error');
 await page.goto(origin+'/approved').catch(()=>{});await page.getByRole('heading',{name:'Approved page ready'}).waitFor();
 await worker.evaluate(async origin=>{
  navThreat=true;
  await chrome.declarativeNetRequest.updateDynamicRules({addRules:[{id:50000,priority:10000,action:{type:'redirect',redirect:{extensionPath:'/blocked.html'}},condition:{urlFilter:origin+'/approved',resourceTypes:['main_frame']}}]});
 },origin);
 await page.reload().catch(()=>{});
 await page.getByText('High-risk threat contained',{exact:true}).waitFor();
 assert.equal(await page.getByRole('button',{name:'Open approved website',exact:true}).count(),0);
 record('High-severity threat blocking still outranks an active reusable approval');
 await fs.writeFile(path.join(output,'results.json'),JSON.stringify({passed:true,checks,scope:'Real Chrome, local HTTP fixture, mocked backend authorization; no shared records'},null,2));
}catch(error){console.error(JSON.stringify({passed:false,error:error.message,requests}));throw error;}
finally{await context?.close();await new Promise(resolve=>server.close(resolve));}
