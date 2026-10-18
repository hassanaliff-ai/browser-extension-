import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHmac} from 'node:crypto';
const {chromium}=await import(process.env.EXTSECURE_PLAYWRIGHT_MODULE||'playwright');
const root=process.env.EXTSECURE_FEEDBACK_EXTENSION, output=process.env.EXTSECURE_FEEDBACK_OUTPUT;
const checks=[];function record(name){checks.push(name);console.log('PASS: '+name);}
function totp(secret){
 const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';
 for(const c of secret)bits+=alphabet.indexOf(c).toString(2).padStart(5,'0');
 const key=Buffer.from(bits.match(/.{8}/g).map(b=>parseInt(b,2)));
 const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));
 const hash=createHmac('sha1',key).update(counter).digest(),offset=hash.at(-1)&15;
 return String((hash.readUInt32BE(offset)&0x7fffffff)%1000000).padStart(6,'0');
}
console.log('Starting isolated MV3 browser verification.');
const context=await chromium.launchPersistentContext(path.join(output,'profile'),{channel:'chromium',headless:true,timeout:20000,viewport:{width:1440,height:1000},args:['--disable-extensions-except='+root,'--load-extension='+root,'--no-first-run']});
context.setDefaultTimeout(12000);
let page;const errors=[];
try{
 const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');
 const id=new URL(worker.url()).hostname;page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
 async function open(view){const url=`chrome-extension://${id}/console.html#${view}`;if(page.url()===url)await page.reload();else await page.goto(url);}
 const usedCounters=new Map();
 async function login(username,secret){
  const form=page.locator('[data-form="login"]');await form.waitFor();
  await form.locator('[name="username"]').fill(username);await form.locator('[name="password"]').fill(process.env.EXTSECURE_TEST_PASSWORD);await form.locator('[type="submit"]').click();
  const verify=page.locator('[data-form="verify"]');await verify.waitFor();
  if(usedCounters.get(username)===Math.floor(Date.now()/30000))await new Promise(resolve=>setTimeout(resolve,30200-Date.now()%30000));
  usedCounters.set(username,Math.floor(Date.now()/30000));
  await verify.locator('[name="code"]').fill(totp(secret));await verify.locator('[type="submit"]').click();
  await page.locator('.page-title').waitFor();
 }
 await open('myhistory');await login('feedback-user',process.env.EXTSECURE_TEST_USER_SECRET);
 await open('myhistory');await page.locator('[data-action="inspect-scan"]').click();
 await page.getByText('Report a concern or challenge this warning',{exact:true}).click();
 const form=page.locator('[data-form="feedback-submit"]');await form.locator('[name="category"]').selectOption('challenge_warning');
 await form.locator('[name="message"]').fill('The warning needs review. <img src=x onerror=alert(1)> This is test evidence.');
 await form.locator('[type="submit"]').click();await page.getByRole('heading',{name:'My security feedback'}).waitFor();
 assert.equal(await page.locator('[data-form="feedback-review"]').count(),0);
 assert((await page.locator('#main').innerText()).includes('Waiting for administrator review'));
 record('Normal user submits scan-linked feedback and sees pending review without review controls');
 assert.equal(await page.locator('#main img[src="x"]').count(),0);record('User feedback is rendered as text; HTML does not execute');
 await page.screenshot({path:path.join(output,'user-feedback.png'),fullPage:true});
 await page.locator('[data-action="logout"]').first().click();await login('feedback-head',process.env.EXTSECURE_TEST_HEAD_SECRET);
 await open('feedback');const review=page.locator('[data-form="feedback-review"]');await review.waitFor();
 await page.locator('[data-action="inspect-scan"]').click();await page.getByRole('heading',{name:'Risk result'}).waitFor();
 assert((await page.locator('#main').innerText()).includes('Critical'));record('Administrator opens original scan evidence from the feedback workspace');
 await open('feedback');await review.waitFor();await review.locator('[name="outcome"]').selectOption('false_positive');
 await review.locator('[name="review_note"]').fill('Evidence reviewed. Perform a follow-up check before considering block release.');
 await review.locator('[type="submit"]').click();await page.getByRole('heading',{name:'Administrator decision'}).waitFor();
 record('Administrator records a review outcome and explanation');
 const result=await page.evaluate(async scan=>chrome.runtime.sendMessage({type:'API',path:'/api/scans/'+scan}),process.env.EXTSECURE_TEST_SCAN);
 const blocks=await page.evaluate(()=>chrome.runtime.sendMessage({type:'API',path:'/api/threat-blocks'}));
 assert(result.ok&&result.data.severity==='Critical');
 assert(blocks.ok&&blocks.data.some(b=>b.scan_id===process.env.EXTSECURE_TEST_SCAN&&b.active));record('Review does not downgrade the scan or release critical containment');
 await page.screenshot({path:path.join(output,'administrator-review.png'),fullPage:true});
 await page.setViewportSize({width:390,height:844});await page.screenshot({path:path.join(output,'feedback-mobile.png'),fullPage:true});
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1),false);record('Feedback workspace fits a narrow viewport');
 // Logout may be hidden by collapsed mobile navigation, so use the real worker action.
 await page.evaluate(()=>chrome.runtime.sendMessage({type:'LOGOUT'}));await page.setViewportSize({width:1440,height:1000});
 await open('feedback');await login('feedback-user',process.env.EXTSECURE_TEST_USER_SECRET);await open('feedback');
 await page.getByRole('heading',{name:'Administrator decision'}).waitFor();assert((await page.locator('#main').innerText()).includes('Perform a follow-up check'));
 record('Submitting user sees the saved administrator decision after signing in again');
 assert.deepEqual(errors,[]);record('No browser JavaScript errors');
 await fs.writeFile(path.join(output,'results.json'),JSON.stringify({passed:checks.length,checks},null,2));
}catch(error){if(page)await page.screenshot({path:path.join(output,'failure.png'),fullPage:true});throw error;}
finally{await context.close();}
