import test from 'node:test';
import assert from 'node:assert/strict';
import {deviceControlRequest,executeDeviceCommands} from '../device-controls.js';
test('Device control transport has scoped headers and no account credentials',async()=>{
 let options;const fetcher=async(url,o)=>{assert.equal(url,'https://api.example/monitor/api/device/extension-controls?cursor=-1');options=o;return {ok:true,json:async()=>({cursor:0,commands:[]})};};
 await deviceControlRequest('https://api.example','device-secret','/api/device/extension-controls?cursor=-1','GET',undefined,fetcher);
 assert.equal(options.headers['X-ExtSecure-Device'],'device-secret');assert.equal(options.headers.Authorization,undefined);assert.equal(options.credentials,'omit');assert.equal(options.redirect,'error');
});
test('Device credential cannot be sent to unrelated routes',async()=>{
 for(const path of ['/api/admin/me','/api/device/extension-controls?cursor=bad','https://evil.example'])await assert.rejects(deviceControlRequest('https://api.example','token',path));
 await assert.rejects(deviceControlRequest('https://api.example','','/api/device/extension-controls?cursor=-1'));
});
test('Signed-out device executes and verifies a block before its device-scoped receipt',async()=>{
 let enabled=true,receipt;const id='11111111-1111-4111-8111-111111111111';
 await executeDeviceCommands({cursor:1,commands:[{extension_id:id,chrome_id:'b'.repeat(32),revision:1,desired:'blocked',status:'pending'}]}, {
 origin:'https://api.example',token:'paired-device',selfId:'a'.repeat(32),management:{get:async()=>({type:'extension',enabled,mayDisable:true}),setEnabled:async(_,value)=>{enabled=value;}},
 fetcher:async(url,o)=>{assert(url.endsWith('/api/device/extensions/'+id+'/receipt'));assert.equal(enabled,false);receipt=JSON.parse(o.body);return {ok:true,json:async()=>receipt};}
 });assert.deepEqual(receipt,{revision:1,status:'applied',error:null});
});
test('Malformed delivery and rejected credentials fail visibly',async()=>{
 await assert.rejects(executeDeviceCommands({cursor:0,commands:null},{}));
 await assert.rejects(deviceControlRequest('https://api.example','bad','/api/device/extension-controls?cursor=-1','GET',undefined,async()=>({ok:false,status:403,json:async()=>({})})),{status:403});
});
