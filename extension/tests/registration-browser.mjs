import path from 'node:path';
import fs from 'node:fs/promises';
import {createHmac} from 'node:crypto';
import assert from 'node:assert/strict';
const {chromium}=await import(process.env.EXTSECURE_PLAYWRIGHT_MODULE||'playwright');
const root=process.env.EXTSECURE_FEEDBACK_EXTENSION,output=process.env.EXTSECURE_FEEDBACK_OUTPUT;
const checks=[];const record=name=>{checks.push(name);console.log('PASS: '+name);};
function otp(secret){
 let bits='';for(const c of secret)bits+='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c).toString(2).padStart(5,'0');
 const key=Buffer.from(bits.match(/.{8}/g).map(s=>parseInt(s,2))),counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));
 const hash=createHmac('sha1',key).update(counter).digest(),offset=hash.at(-1)&15;return String((hash.readUInt32BE(offset)&0x7fffffff)%1000000).padStart(6,'0');
}
const context=await chromium.launchPersistentContext(path.join(output,'profile'),{channel:'chromium',headless:true,timeout:20000,viewport:{width:1440,height:1000},args:['--disable-extensions-except='+root,'--load-extension='+root,'--no-first-run']});
let page;
try{
 const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');const id=new URL(worker.url()).hostname;
 page=await context.newPage();page.setDefaultTimeout(15000);const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('chrome-extension://'+id+'/console.html');
 let login=page.locator('[data-form="login"]');await login.locator('[name="username"]').fill('signup-example');
 await login.locator('[name="password"]').fill(process.env.EXTSECURE_TEST_PASSWORD);await login.locator('[type="submit"]').click();
 await page.getByText(/New users must create an account/).waitFor();record('Unknown login explains registration and approval without creating an account');
 await page.getByRole('button',{name:'Create a new account',exact:true}).click();
 const register=page.locator('[data-form="register"]');assert.equal(await register.locator('[name="username"]').inputValue(),'signup-example');
 assert.equal(await register.locator('[name="password"]').inputValue(),'');record('Registration is directly accessible and preserves only the username');
 await register.locator('[name="password"]').fill(process.env.EXTSECURE_TEST_PASSWORD);await register.locator('[name="confirm"]').fill(process.env.EXTSECURE_TEST_PASSWORD);await register.locator('[type="submit"]').click();
 await page.locator('[data-form="register-verify"]').waitFor();
 await page.getByText('Enter the setup key manually',{exact:true}).click();const secret=await page.getByLabel('Authenticator setup key').inputValue();
 const verify=page.locator('[data-form="register-verify"]');await verify.locator('[name="role"]').selectOption('normal_user');
 await verify.locator('[name="code"]').fill(otp(secret));const usedCounter=Math.floor(Date.now()/30000);await verify.locator('[type="submit"]').click();
 await page.getByRole('heading',{name:'Registration submitted'}).waitFor();record('Actual account registration and authenticator verification produce a pending confirmation');
 await page.reload();await page.getByRole('heading',{name:'Registration submitted'}).waitFor();
 assert((await page.locator('[data-registration-pending]').innerText()).includes('signup-example'));record('Submission confirmation survives closing and reopening the console page');
 await page.screenshot({path:path.join(output,'registration-submitted.png'),fullPage:true});
 await page.getByRole('button',{name:'Continue to log in',exact:true}).click();
 login=page.locator('[data-form="login"]');assert.equal(await login.locator('[name="username"]').inputValue(),'signup-example');
 await login.locator('[name="password"]').fill(process.env.EXTSECURE_TEST_PASSWORD);await login.locator('[type="submit"]').click();await page.getByText(/New users must create an account/).waitFor();
 assert.equal(await page.locator('[data-form="verify"]').count(),0);record('An unapproved account still cannot sign in');
 await login.locator('[name="username"]').fill('feedback-head');await login.locator('[name="password"]').fill(process.env.EXTSECURE_TEST_PASSWORD);await login.locator('[type="submit"]').click();
 let second=page.locator('[data-form="verify"]');await second.waitFor();await second.locator('[name="code"]').fill(otp(process.env.EXTSECURE_TEST_HEAD_SECRET));await second.locator('[type="submit"]').click();await page.locator('.page-title').waitFor();
 await page.goto('chrome-extension://'+id+'/console.html#accounts');await page.getByRole('heading',{name:'Pending registrations'}).waitFor();
 const row=page.locator('tr').filter({hasText:'signup-example'});assert.equal(await row.count(),1);record('Verified registration appears in the administrator approval dashboard');
 await page.screenshot({path:path.join(output,'pending-approval.png'),fullPage:true});
 await page.getByText('Review an access request',{exact:true}).click();const review=page.locator('[data-form="account-review"]');
 await review.locator('[name="username"]').selectOption('signup-example');await review.locator('[name="role"]').selectOption('normal_user');await review.locator('[name="confirmed"]').check();await review.locator('[name="reason"]').fill('Verified the isolated test account identity and requested access.');await review.locator('[type="submit"]').click();
 await page.waitForFunction(()=>!document.querySelector('[data-form="account-review"]'));record('Head administrator approves the verified account through the real review form');
 await page.locator('[data-action="logout"]').first().click();login=page.locator('[data-form="login"]');await login.locator('[name="username"]').fill('signup-example');await login.locator('[name="password"]').fill(process.env.EXTSECURE_TEST_PASSWORD);await login.locator('[type="submit"]').click();
 second=page.locator('[data-form="verify"]');await second.waitFor();
 if(Math.floor(Date.now()/30000)===usedCounter)await new Promise(r=>setTimeout(r,30200-Date.now()%30000));
 await second.locator('[name="code"]').fill(otp(secret));await second.locator('[type="submit"]').click();await page.locator('.page-title').waitFor();record('Approved new account completes password and authenticator sign-in');
 assert.deepEqual(errors,[]);record('No page JavaScript errors');
 await fs.writeFile(path.join(output,'results.json'),JSON.stringify({passed:checks.length,checks},null,2));
}catch(error){if(page)await page.screenshot({path:path.join(output,'registration-failure.png'),fullPage:true});throw error;}
finally{await context.close();}
