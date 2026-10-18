// Real public package in a fresh Chrome profile; never uses account credentials.
import path from 'node:path';
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
const {chromium}=await import(process.env.EXTSECURE_PLAYWRIGHT_MODULE||'playwright');
const root=process.env.EXTSECURE_PUBLIC_EXTENSION,output=process.env.EXTSECURE_TEST_OUTPUT;
const context=await chromium.launchPersistentContext(path.join(output,'profile'),{channel:'chromium',headless:true,timeout:20000,args:['--disable-extensions-except='+root,'--load-extension='+root,'--no-first-run']});
try{
 const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');
 const id=new URL(worker.url()).hostname,page=await context.newPage();const errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.goto('chrome-extension://'+id+'/console.html');
 await page.locator('[data-form="login"]').waitFor();
 const result=await page.evaluate(()=>chrome.runtime.sendMessage({type:'HEALTH'}));
 assert(result.ok&&result.data.status==='ready',JSON.stringify(result));
 assert.equal(result.data.api_origin,process.env.EXTSECURE_PUBLIC_ORIGIN);
 await page.locator('[data-connection-badge] button').first().click();
 await page.getByText('The configured API is reachable: '+process.env.EXTSECURE_PUBLIC_ORIGIN,{exact:true}).waitFor();
 assert.deepEqual(errors,[]);
 await page.screenshot({path:path.join(output,'public-connection.png'),fullPage:true});
 const summary={passed:true,origin:result.data.api_origin,status:result.data.status,checks:['Real MV3 package loads','Health request succeeds through Chrome with packaged CSP','Configured public address matches current tunnel','Connection button reports the public address','No page JavaScript errors']};
 await fs.writeFile(path.join(output,'results.json'),JSON.stringify(summary,null,2));console.log(JSON.stringify(summary));
}finally{await context.close();}
