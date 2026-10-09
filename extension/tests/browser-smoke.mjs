// Real MV3 smoke tests in a fresh test profile. Never attaches to personal Chrome.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHmac} from 'node:crypto';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const live=process.argv.includes('--live');
const output=path.resolve(process.env.EXTSECURE_TEST_OUTPUT||path.join(root,'../.private/extension-smoke'));
const playwright=process.env.EXTSECURE_PLAYWRIGHT_MODULE
  ? await import(process.env.EXTSECURE_PLAYWRIGHT_MODULE) : await import('playwright');
const {chromium}=playwright.default??playwright;
const checks=[];let phase='startup',context,page,signedIn=false;
const record=(name,details={})=>{checks.push({name,passed:true,...details});console.log(JSON.stringify(checks.at(-1)));};
const manifest=JSON.parse(await fs.readFile(path.join(root,'manifest.json'),'utf8'));
function totp(secret){
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';
  for(const character of secret.toUpperCase().replace(/=+$/,'')){
    const value=alphabet.indexOf(character);assert(value>=0,'Invalid authenticator input');bits+=value.toString(2).padStart(5,'0');
  }
  const bytes=[];for(let i=0;i+8<=bits.length;i+=8)bytes.push(parseInt(bits.slice(i,i+8),2));
  const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));
  const hash=createHmac('sha1',Buffer.from(bytes)).update(counter).digest();
  const offset=hash.at(-1)&15;return String((hash.readUInt32BE(offset)&0x7fffffff)%1000000).padStart(6,'0');
}
async function message(body){
  const result=await page.evaluate(input=>chrome.runtime.sendMessage(input),body);
  if(!result?.ok)throw new Error('Extension action failed: '+body.type);
  return result.data;
}
async function go(view){
  await page.goto('chrome-extension://'+extensionId+'/console.html#'+view);
  await page.locator('.page-title').waitFor({timeout:15000});
  await page.waitForFunction(()=>!document.querySelector('#app [aria-busy="true"]'));
}
let extensionId;
try{
  await fs.mkdir(output,{recursive:true});
  phase='load MV3 extension';
  context=await chromium.launchPersistentContext(path.join(output,'profile'),{
    channel:'chromium',headless:true,viewport:{width:1440,height:1000},
    args:['--disable-extensions-except='+root,'--load-extension='+root,'--no-first-run']
  });
  const errors=[];
  let worker=context.serviceWorkers()[0];if(!worker)worker=await context.waitForEvent('serviceworker',{timeout:15000});
  assert(worker.url().endsWith('/background.js'));
  extensionId=new URL(worker.url()).hostname;
  page=await context.newPage();page.on('pageerror',error=>errors.push(error.message));
  await page.goto('chrome-extension://'+extensionId+'/console.html');
  await page.locator('form[data-form="login"]').waitFor();
  record('Actual MV3 service worker and console loaded',{version:manifest.version});
  const initial=await message({type:'STATE'});assert.equal(initial.version,manifest.version);assert(!initial.profile);
  record('Test profile starts signed out without borrowed credentials');
  const health=await message({type:'HEALTH'});assert.equal(health.status,'ready');
  record('Running TestAPI is reachable through the real worker');
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1),false);
  record('Sign-in layout fits a desktop viewport');
  let credentials;
  if(live){
    phase='password and authenticator sign-in';
    console.log(JSON.stringify({credentials_required:true}));
    let body='';for await(const chunk of process.stdin)body+=chunk;
    credentials=JSON.parse(body);assert(credentials.username&&credentials.password&&(credentials.code||credentials.totp_secret));
    await page.locator('form[data-form="login"] [name="username"]').fill(credentials.username);
    await page.locator('form[data-form="login"] [name="password"]').fill(credentials.password);
    await page.locator('form[data-form="login"] button[type="submit"]').click();
    await page.locator('form[data-form="verify"]').waitFor({timeout:15000});
    record('Password alone requires the second authenticator step');
    await page.locator('form[data-form="verify"] [name="code"]').fill(credentials.code||totp(credentials.totp_secret));
    await page.locator('form[data-form="verify"] button[type="submit"]').click();
    await page.locator('.page-title').waitFor({timeout:15000});signedIn=true;
    const state=await message({type:'STATE'});assert.equal(state.profile.username,credentials.username);
    assert.equal(state.profile.role,'head_administrator','Live smoke tests require the approved head role');
    assert(Date.parse(state.expires_at)>Date.now()+23*60*60*1000&&Date.parse(state.expires_at)<Date.now()+25*60*60*1000);
    record('Backend 2FA grants the correct profile and a 24-hour session');
    credentials=null;
    phase='register the isolated test device';
    await go('account');
    if(!(await message({type:'STATE'})).profile.inventory.linked){
    await page.locator('form[data-form="device-connect"] [name="initial_access"]').selectOption('trusted');
    await page.locator('form[data-form="device-connect"] details summary').click();
    await page.locator('form[data-form="device-connect"] [name="name"]').fill('ExtSecure QA browser '+new Date().toISOString().slice(0,10));
    await page.locator('form[data-form="device-connect"] button[type="submit"]').click();
    await page.getByText('This Chrome profile is connected.',{exact:true}).waitFor({timeout:15000}).catch(async()=>{
      await page.getByText('Connected',{exact:true}).first().waitFor({timeout:15000});
    });
    }
    const linked=await message({type:'STATE'});assert(linked.profile.inventory.linked&&!linked.profile.inventory.blocked&&!linked.profile.inventory.pending);
    record('Device and ExtSecure metadata persist from the real test profile');
    phase='URL reputation scan';await go('scan');
    await page.locator('form[data-form="url-scan"] [name="target"]').fill('https://example.com/?extsecure-private-test=must-not-be-stored#local');
    await page.locator('form[data-form="url-scan"] button[type="submit"]').click();
    await page.locator('[aria-label="Risk assessment"]').waitFor({timeout:30000});
    const urlText=await page.locator('[aria-label="Risk assessment"]').innerText();
    assert(!urlText.includes('must-not-be-stored'));assert(/Low|Medium|High|Critical|Unknown/.test(urlText));
    record('Public URL check stores a result and removes private parameters');
    phase='local file hashing';await go('files');
    await page.locator('input[name="file"]').setInputFiles({name:'extsecure-benign-smoke.txt',mimeType:'text/plain',buffer:Buffer.from('ExtSecure benign smoke test 2026-10-09')});
    await page.locator('form[data-form="file-scan"] button[type="submit"]').click();
    await page.locator('[aria-label="Risk assessment"]').waitFor({timeout:30000});
    const fileText=await page.locator('[aria-label="Risk assessment"]').innerText();
    assert(fileText.includes('SHA-256'));assert(/Low|Medium|High|Critical|Unknown/.test(fileText));
    record('Harmless local file is hashed and its risk result is displayed');
    await page.screenshot({path:path.join(output,'file-result.png'),fullPage:true});
    phase='console workflows';
    for(const view of ['history','events','devices','extensions','workflow','controls','reports']){
      await go(view);await page.waitForTimeout(300);
      const text=await page.locator('body').innerText();
      assert(!text.includes('This API action is not supported.')&&!text.includes('Unknown extension action.')&&!text.includes('Cannot reach the ExtSecure backend.'));
      record('Console view loads: '+view);
    }
    phase='navigation gate';
    const blockedEvent=context.waitForEvent('response',response=>response.url().endsWith('/monitor/api/controls/navigation')
      && response.request().method()==='POST',{timeout:15000});
    const destination=await context.newPage();await destination.goto('https://example.com/').catch(()=>{});
    await destination.waitForURL(url=>url.protocol==='chrome-extension:'&&url.pathname==='/blocked.html',{timeout:15000});
    await destination.getByRole('heading',{name:'This website is blocked',exact:true}).waitFor({timeout:15000});
    record('Unapproved website navigation is blocked by real Chrome rules');
    const navigation=await blockedEvent;assert(navigation.status()>=200&&navigation.status()<300);
    record('Blocked navigation reaches backend control-effectiveness evidence');
    await destination.close();
    phase='local preferences';await go('events');
    const selector=page.locator('select[data-table-size]').first();
    await selector.selectOption('compact');
    await page.waitForFunction(()=>document.documentElement.dataset.tableSize==='compact');
    await page.reload();await page.locator('.page-title').waitFor();
    assert.equal(await page.locator('select[data-table-size]').first().inputValue(),'compact');
    record('Table size persists after a real extension-page reload');
    await go('overview');await page.screenshot({path:path.join(output,'dashboard.png'),fullPage:true});
    assert.deepEqual(errors,[]);record('No uncaught console-page JavaScript errors');
    phase='sign out test session';await message({type:'LOGOUT'});signedIn=false;
    assert(!(await message({type:'STATE'})).profile);record('Sign-out clears only this test profile session');
  }
  await fs.writeFile(path.join(output,'results.json'),JSON.stringify({live,checks,passed:true},null,2));
  console.log(JSON.stringify({passed:true,checks:checks.length,live}));
}catch(error){
  // Never print request bodies, authenticator input, tokens or account secrets.
  await fs.mkdir(output,{recursive:true});
  await fs.writeFile(path.join(output,'results.json'),JSON.stringify({live,checks,passed:false,failed_phase:phase,error_type:error.name},null,2));
  console.error(JSON.stringify({passed:false,failed_phase:phase,error_type:error.name}));process.exitCode=1;
}finally{
  if(live&&page)try{if((await message({type:'STATE'})).profile)await message({type:'LOGOUT'});}catch{/* Report failure without exposing private diagnostics. */}
  if(context)await context.close();
}
