import test from 'node:test';
import assert from 'node:assert/strict';
globalThis.location={protocol:'chrome-extension:',hostname:'test-extension',port:''};
let response={ok:false,error:'This API action is not supported.'},messages=[],reloads=0;
globalThis.chrome={runtime:{id:'test-extension',sendMessage:async message=>{messages.push(message);return response;},reload:()=>{reloads++;}}};
const {send,operationsCompatibility,restartExtension}=await import('../transport.js');
const {VERSION,WORKER_CAPABILITIES,OPERATIONS_API_CONTRACT}=await import('../core.js');
const current=()=>({version:VERSION,operations_api_contract:OPERATIONS_API_CONTRACT,capabilities:[...WORKER_CAPABILITIES]});

test('Both task sections accept the current worker contract',()=>{
 for(const view of ['workflow','controls'])assert.equal(operationsCompatibility(current(),view).ready,true);
});
test('Both task sections detect a legacy worker and a same-version worker missing the contract',()=>{
 for(const view of ['workflow','controls'])for(const state of [undefined,{version:'0.8.7'}, {...current(),operations_api_contract:undefined},{...current(),capabilities:[]},{...current(),operations_api_contract:2}])
  assert.equal(operationsCompatibility(state,view).ready,false);
});
test('Worker capabilities are evaluated separately for each task',()=>{
 const state={...current(),capabilities:['workflow-automation']};
 assert.equal(operationsCompatibility(state,'workflow').ready,true);assert.equal(operationsCompatibility(state,'controls').ready,false);
 assert.equal(operationsCompatibility(undefined,'account').ready,true);
});
test('Recognized valid task routes turn a legacy rejection into actionable recovery without retrying',async()=>{
 for(const path of ['/api/workflow/rules','/api/controls/effectiveness?days=30']){
  messages=[];response={ok:false,error:'This API action is not supported.'};
  await assert.rejects(send({type:'API',path}),error=>error.code==='EXTENSION_UPDATE_REQUIRED');
  assert.equal(messages.length,1);assert.equal(reloads,0);
 }
});
test('Invalid paths and methods remain denied without being mislabeled as update errors',async()=>{
 for(const message of [{type:'API',path:'/api/arbitrary'},{type:'API',path:'/api/workflow/rules',method:'DELETE'},{type:'API',path:'/api/workflow/rules?secret=x'},{type:'API',path:'https://other.test/api/workflow/rules'}]){
  messages=[];response={ok:false,error:'This API action is not supported.'};
  await assert.rejects(send(message),error=>error.code===undefined&&error.message==='This API action is not supported.');
  assert.equal(messages.length,1);
 }
});
test('A backend permission error is not disguised as a worker compatibility error',async()=>{
 response={ok:false,error:'Your account does not have permission for this action.',status:403};
 await assert.rejects(send({type:'API',path:'/api/workflow/rules'}),error=>error.status===403&&error.code===undefined);
});
test('Worker disconnection provides the repair action',async()=>{
 const original=chrome.runtime.sendMessage;chrome.runtime.sendMessage=async()=>{throw new Error('Extension context invalidated.');};
 try{await assert.rejects(send({type:'STATE'}),error=>error.code==='EXTENSION_UPDATE_REQUIRED');}finally{chrome.runtime.sendMessage=original;}
});
test('Only explicit repair reloads the extension',()=>{assert.equal(reloads,0);restartExtension();assert.equal(reloads,1);});
