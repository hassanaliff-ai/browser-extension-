import test from 'node:test';
import assert from 'node:assert/strict';
globalThis.location={protocol:'chrome-extension:',hostname:'test-extension',port:''};
let response={ok:false,error:'This API action is not supported.'},messages=[],reloads=0;
globalThis.chrome={runtime:{id:'test-extension',sendMessage:async message=>{messages.push(message);return response;},reload:()=>{reloads++;}}};
const {send,restartExtension}=await import('../transport.js');
const {VERSION,WORKER_CAPABILITIES}=await import('../core.js');
test('Recognized valid task routes turn a legacy rejection into actionable recovery without retrying',async()=>{
 for(const path of ['/api/cases','/api/threat-blocks']){
  messages=[];response={ok:false,error:'This API action is not supported.'};
  await assert.rejects(send({type:'API',path}),error=>error.code==='EXTENSION_UPDATE_REQUIRED');
  assert.equal(messages.length,1);assert.equal(reloads,0);
 }
});
test('Invalid paths and methods remain denied without being mislabeled as update errors',async()=>{
 for(const message of [{type:'API',path:'/api/arbitrary'},{type:'API',path:'/api/cases',method:'DELETE'},{type:'API',path:'/api/threat-blocks?secret=x'},{type:'API',path:'https://other.test/api/cases'}]){
  messages=[];response={ok:false,error:'This API action is not supported.'};
  await assert.rejects(send(message),error=>error.code===undefined&&error.message==='This API action is not supported.');
  assert.equal(messages.length,1);
 }
});
test('A backend permission error is not disguised as a worker compatibility error',async()=>{
 response={ok:false,error:'Your account does not have permission for this action.',status:403};
 await assert.rejects(send({type:'API',path:'/api/cases'}),error=>error.status===403&&error.code===undefined);
});
test('Worker disconnection provides the repair action',async()=>{
 const original=chrome.runtime.sendMessage;chrome.runtime.sendMessage=async()=>{throw new Error('Extension context invalidated.');};
 try{await assert.rejects(send({type:'STATE'}),error=>error.code==='EXTENSION_UPDATE_REQUIRED');}finally{chrome.runtime.sendMessage=original;}
});
test('Only explicit repair reloads the extension',()=>{assert.equal(reloads,0);restartExtension();assert.equal(reloads,1);});
