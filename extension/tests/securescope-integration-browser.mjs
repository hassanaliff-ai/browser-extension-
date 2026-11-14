// Real MV3/content-script integration using a fulfilled reserved-domain fixture.
// Synthetic session exists only in this disposable profile; it never authenticates
// to the API or reads/writes the shared database. No linked destination is visited.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium}=await import(process.env.EXTSECURE_PLAYWRIGHT_MODULE||'playwright');
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const output=path.resolve(process.env.EXTSECURE_TEST_OUTPUT||path.join(root,'../.private/securescope-integration'));
await fs.mkdir(output,{recursive:true});
const context=await chromium.launchPersistentContext(path.join(output,'profile'),{
  channel:'chromium',headless:true,viewport:{width:1100,height:700},
  args:['--disable-extensions-except='+root,'--load-extension='+root,'--no-first-run']
});
const checks=[],requests=[];
const record=name=>{checks.push(name);console.log(JSON.stringify({passed:true,name}));};
try {
  const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');
  await worker.evaluate(async()=>{
    await chrome.storage.session.clear();
    await chrome.storage.local.clear();
    await chrome.declarativeNetRequest.updateSessionRules({addRules:[{id:99999,priority:300,action:{type:'allow'},condition:{regexFilter:'^https://integration\\.example/',resourceTypes:['main_frame']}}]});
  });
  await context.route('https://integration.example/**',route=>route.fulfill({contentType:'text/html',body:
    '<!doctype html><title>ExtSecure integration fixture</title><h1>SecureScope integration fixture</h1><p>Reserved example links; destinations are never opened.</p><a id="risk" href="https://paypal.com.evil.example/login?secret=fixture">Suspicious example</a><p><a id="ordinary" href="https://www.paypal.com/private?secret=fixture">Ordinary example</a></p>'}));
  context.on('request',request=>requests.push(request.url()));
  const page=await context.newPage();
  await page.goto('https://integration.example/');
  await page.waitForTimeout(500);
  assert.equal(await page.locator('.securescope-inline-badge').count(),0);
  record('Signed-out profile does not display authenticated inline findings');
  await worker.evaluate(()=>chrome.storage.session.set({session:{token:'synthetic-local-inline-only',expires_at:new Date(Date.now()+60000).toISOString()}}));
  await page.reload();
  const badge=page.locator('#risk + .securescope-inline-badge');
  await badge.waitFor();
  assert.match(await badge.innerText(),/High local warning/);
  assert.match(await badge.getAttribute('title'),/Local URL indicators only; no backend lookup/);
  assert.equal(await page.locator('#ordinary + .securescope-inline-badge').count(),0);
  record('Actual content script receives High origin-only finding from ExtSecure worker');
  await page.evaluate(()=>{const link=document.createElement('a');link.id='added';link.href='https://paypal.com.evil.example/other?private=fixture';link.textContent='Dynamically added link';document.body.append(link);});
  await page.locator('#added + .securescope-inline-badge').waitFor();
  record('Dynamically added links receive cached origin findings');
  await page.evaluate(()=>{document.querySelector('#risk').href='https://example.com/';});
  await page.waitForFunction(()=>!document.querySelector('#risk + .securescope-inline-badge'));
  record('Changed ordinary destination removes the old warning');
  assert(requests.every(url=>url.startsWith('https://integration.example/')));
  record('Inline checks make no API requests and never visit linked destinations');
  await page.screenshot({path:path.join(output,'inline-integration.png'),fullPage:true});
  await worker.evaluate(()=>chrome.storage.session.clear());
  await fs.writeFile(path.join(output,'results.json'),JSON.stringify({passed:true,checks,scope:'Isolated Chrome integration; synthetic session, reserved-domain fixture, no provider or shared database access'},null,2));
}finally{await context.close();}
