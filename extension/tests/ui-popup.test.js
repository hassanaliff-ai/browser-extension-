import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {VERSION} from '../core.js';

const handlers={},app={innerHTML:'',addEventListener:(name,handler)=>handlers[name]=handler};
globalThis.location={protocol:'chrome-extension:',hash:''};
globalThis.window={history:{replaceState(){}},addEventListener(){}};
globalThis.document={body:{classList:{contains:name=>name==='popup'},querySelectorAll:()=>[]},documentElement:{},
 querySelector:selector=>({'#app':app,'#main':{focus(){}},'#toast':{}}[selector]),createTreeWalker:()=>({nextNode:()=>null})};
globalThis.NodeFilter={SHOW_TEXT:4};globalThis.MutationObserver=class{observe(){}};globalThis.setTimeout=()=>0;
globalThis.chrome={runtime:{id:'a'.repeat(32),sendMessage:async message=>{
 if(message.type==='PREFERENCES')return {ok:true,data:{language:'en',timeZone:'Asia/Riyadh'}};
 if(message.type==='STATE')return {ok:true,data:{profile:{username:'test-head',role:'head_administrator',role_label:'Head of Administrator',inventory:{linked:true}},version:VERSION}};
 if(message.type==='ACTIVE_TAB')return {ok:true,data:{url:'https://example.com/',host:'example.com'}};
 if(message.type==='SCAN_URL')return {ok:true,data:{id:'test-url',severity:'Low',score:0,completeness:'complete',target_kind:'url',target_display:'example.com',findings:[],lookup:{status:'complete'}}};
 throw new Error('Unexpected message '+message.type);
}}};
await import('../ui.js');

test('Toolbar popup exposes scanning, website access, account verification and recovery',async()=>{
 assert.match(app.innerHTML,/Check current destination/);assert.match(app.innerHTML,/data-action="open-access"/);
 assert.match(app.innerHTML,/2FA verified/);assert.match(app.innerHTML,/data-action="check-connection"/);
 if(process.env.EXTSECURE_UI_QA_OUTPUT){await fs.mkdir(process.env.EXTSECURE_UI_QA_OUTPUT,{recursive:true});await fs.writeFile(path.join(process.env.EXTSECURE_UI_QA_OUTPUT,'popup-ready.html'),app.innerHTML);}
});
test('Popup results stay compact and offer the full evidence workspace',async()=>{
 const button={dataset:{action:'scan-active'},innerHTML:'Check current destination',isConnected:true,setAttribute(){},removeAttribute(){},closest:()=>null};
 await handlers.click({target:{closest:()=>button}});
 assert.match(app.innerHTML,/Risk result/);assert.match(app.innerHTML,/Download scan evidence/);assert.match(app.innerHTML,/Open evidence workspace/);
 assert.doesNotMatch(app.innerHTML,/data-form="ai-explain"/);
 if(process.env.EXTSECURE_UI_QA_OUTPUT){await fs.mkdir(process.env.EXTSECURE_UI_QA_OUTPUT,{recursive:true});await fs.writeFile(path.join(process.env.EXTSECURE_UI_QA_OUTPUT,'popup.html'),app.innerHTML);}
});

test('Compact popup keeps threat findings and the action visible outside optional details',async()=>{
 const original=chrome.runtime.sendMessage;
 chrome.runtime.sendMessage=async message=>message.type==='SCAN_URL'?{ok:true,data:{id:'test-high',severity:'High',score:80,completeness:'complete',target_kind:'url',target_display:'example.com',suggested_action:'Do not proceed. Ask an administrator to investigate.',findings:[{title:'Synthetic malicious verdict',points:80,detail:'Synthetic provider evidence for a UI test.'}],lookup:{status:'complete'}}}:original(message);
 try{
  await handlers.click({target:{closest:()=>({dataset:{action:'scan-active'},isConnected:true,setAttribute(){},removeAttribute(){},closest:()=>null})}});
  const visible=app.innerHTML.split('<summary>Scan details</summary>')[0];
  assert.match(visible,/Do not proceed/);assert.match(visible,/Synthetic malicious verdict/);assert.match(visible,/risk-high/);
  if(process.env.EXTSECURE_UI_QA_OUTPUT)await fs.writeFile(path.join(process.env.EXTSECURE_UI_QA_OUTPUT,'popup-threat.html'),app.innerHTML);
 }finally{chrome.runtime.sendMessage=original;}
});

test('Compact popup leaves Unknown and provider failure guidance visible',async()=>{
 const original=chrome.runtime.sendMessage;
 chrome.runtime.sendMessage=async message=>message.type==='SCAN_URL'?{ok:true,data:{id:'test-unknown',severity:'Unknown',score:null,completeness:'unknown',target_kind:'url',target_display:'example.com',findings:[],lookup:{status:'unavailable',reason:'rate_limited',retry_after_seconds:30}}}:original(message);
 try{
  await handlers.click({target:{closest:()=>({dataset:{action:'scan-active'},isConnected:true,setAttribute(){},removeAttribute(){},closest:()=>null})}});
  const visible=app.innerHTML.split('<summary>Scan details</summary>')[0];
  assert.match(visible,/Unknown is not a safe result/);assert.match(visible,/request limit/);assert.match(visible,/Retry after/);assert.match(visible,/>30<\/bdi>/);
  if(process.env.EXTSECURE_UI_QA_OUTPUT)await fs.writeFile(path.join(process.env.EXTSECURE_UI_QA_OUTPUT,'popup-unknown.html'),app.innerHTML);
 }finally{chrome.runtime.sendMessage=original;}
});

test('The signed-out screen keeps registration and connection diagnostics available',async()=>{
 const original=chrome.runtime.sendMessage;
 chrome.runtime.sendMessage=async message=>message.type==='STATE'?{ok:true,data:{version:VERSION}}:original(message);
 try{await handlers.click({target:{closest:()=>({dataset:{action:'refresh'},isConnected:true,setAttribute(){},removeAttribute(){},closest:()=>null})}});
  assert.match(app.innerHTML,/Register account/);assert.match(app.innerHTML,/data-action="check-connection"/);
  if(process.env.EXTSECURE_UI_QA_OUTPUT)await fs.writeFile(path.join(process.env.EXTSECURE_UI_QA_OUTPUT,'sign-in.html'),app.innerHTML);
 }finally{chrome.runtime.sendMessage=original;}
});

test('Authenticator verification remains a required separate screen',async()=>{
 const original=chrome.runtime.sendMessage;
 chrome.runtime.sendMessage=async message=>message.type==='STATE'?{ok:true,data:{challenge:true,version:VERSION}}:original(message);
 try{await handlers.click({target:{closest:()=>({dataset:{action:'refresh'},isConnected:true,setAttribute(){},removeAttribute(){},closest:()=>null})}});
  assert.match(app.innerHTML,/data-form="verify"/);assert.match(app.innerHTML,/pattern="\[0-9\]\{6\}"/);
  assert.match(app.innerHTML,/Password accepted/);assert.doesNotMatch(app.innerHTML,/Open console/);
  if(process.env.EXTSECURE_UI_QA_OUTPUT)await fs.writeFile(path.join(process.env.EXTSECURE_UI_QA_OUTPUT,'verification.html'),app.innerHTML);
 }finally{chrome.runtime.sendMessage=original;}
});
