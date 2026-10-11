// Authenticated real Chrome -> real TestAPI -> real PostgreSQL. No fetch mocks.
// A temporary session is issued using the existing approved account and TOTP.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const output=process.env.EXTSECURE_TEST_OUTPUT;
const sessionFile=process.env.EXTSECURE_LIVE_SESSION_FILE;
assert(output&&sessionFile,'Explicit private output and temporary session are required.');
const session=JSON.parse(await fs.readFile(sessionFile,'utf8'));
const pw=await import(process.env.EXTSECURE_PLAYWRIGHT_MODULE||'playwright');
const {chromium}=pw.default??pw;
let context;const checks=[],scans=[];
const record=name=>checks.push({name,passed:true});
try {
  await fs.mkdir(output,{recursive:true});
  context=await chromium.launchPersistentContext(path.join(output,'profile'),{channel:'chromium',headless:true,viewport:{width:1440,height:1000},args:['--disable-extensions-except='+root,'--load-extension='+root,'--no-first-run']});
  const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');
  const id=new URL(worker.url()).hostname;
  const page=await context.newPage();
  await page.goto('chrome-extension://'+id+'/console.html');
  await page.getByRole('button',{name:'Continue securely',exact:true}).waitFor();
  await worker.evaluate(async value=>chrome.storage.session.set({session:value}),session);
  async function send(message){
    const r=await page.evaluate(value=>chrome.runtime.sendMessage(value),message);
    assert(r.ok,r.error??'Extension action failed');return r.data;
  }
  const connection=await send({type:'CONNECT_DEVICE',initial_access:'trusted',name:'Chrome database integration verification'});
  assert(connection.device_id&&!connection.blocked&&!connection.pending);
  record('Real Chrome profile enrolls through the authenticated inventory API');
  await send({type:'STATE'});
  const before=await send({type:'API',path:'/api/database/status'});
  assert(before.healthy&&before.connection.engine==='PostgreSQL'&&before.connection.database==='extsecure');
  record('Extension verifies the actual runtime PostgreSQL database');
  const website=await send({type:'SCAN_URL',target:'https://example.org/'});
  assert(website.id&&['Unknown','Low','Medium','High','Critical'].includes(website.severity));
  scans.push({id:website.id,kind:'url',severity:website.severity,lookup_status:website.lookup?.status});
  record('Real website lookup saves a scan without inventing a safe verdict');
  const sha256=createHash('sha256').update('ExtSecure harmless database integration verification\n').digest('hex');
  const file=await send({type:'API',path:'/api/admin/downloads/scan',method:'POST',body:{device_id:connection.device_id,device_name:'Chrome database integration verification',sha256}});
  assert(file.id&&file.target_kind==='download');
  scans.push({id:file.id,kind:'download',severity:file.severity,lookup_status:file.file_lookup?.status});
  record('A harmless local file digest is checked and saved without uploading bytes');
  const history=await send({type:'API',path:'/api/my/scans'});
  for(const row of scans)assert(history.some(item=>item.id===row.id));
  record('Both persisted scans are visible in the account history');
  const events=await send({type:'API',path:'/api/events'});
  for(const row of scans)assert(events.some(item=>item.scan_id===row.id&&item.device_name==='Chrome database integration verification'&&item.username===session.profile.username));
  record('Stored events identify the real enrolled device and approved account');
  const after=await send({type:'API',path:'/api/database/status'});
  for(const table of ['scans','personal_scan_ownership','security_events'])assert(after.table_rows[table]>=before.table_rows[table]+2);
  record('PostgreSQL scan, ownership and event counts increase together');
  await page.goto('chrome-extension://'+id+'/console.html#settings');await page.reload();
  await page.getByRole('heading',{name:'Database connection',exact:true}).waitFor();
  await page.getByText('Saved records by table',{exact:true}).click();
  await page.getByText('Verified PostgreSQL storage',{exact:true}).waitFor();
  await page.screenshot({path:path.join(output,'database-connection.png'),fullPage:true});
  record('The shipped console displays the live database and table counts');
  await fs.writeFile(path.join(output,'results.json'),JSON.stringify({passed:true,real_chrome:true,real_backend:true,real_postgresql:true,checks,scans,before,after,device_id:connection.device_id},null,2));
  console.log(JSON.stringify({passed:true,checks:checks.length,scans,connection:after.connection,table_rows:after.table_rows}));
} catch(error) {
  await fs.writeFile(path.join(output,'failure.json'),JSON.stringify({passed:false,error:error.message,checks,scans},null,2));
  console.error(JSON.stringify({passed:false,error:error.message}));process.exitCode=1;
} finally {
  await context?.close();
  await fetch('http://127.0.0.1:8765/monitor/api/admin/logout',{method:'POST',headers:{Authorization:'Bearer '+session.token}}).catch(()=>{});
  await fs.unlink(sessionFile).catch(()=>{});
}
