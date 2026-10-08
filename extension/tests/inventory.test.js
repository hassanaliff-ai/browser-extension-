import test from 'node:test';
import assert from 'node:assert/strict';
import {enabledExtensions,platformName} from '../inventory.js';
import {safeApiPath} from '../core.js';

test('Inventory contains only enabled extensions and the three required metadata fields',()=>{
 const result=enabledExtensions([
  {id:'a'.repeat(32),name:'Enabled',version:'1',enabled:true,type:'extension',permissions:['tabs'],description:'private'},
  {id:'b'.repeat(32),name:'Disabled',version:'1',enabled:false,type:'extension'},
  {id:'c'.repeat(32),name:'Theme',version:'1',enabled:true,type:'theme'},
  {id:'d'.repeat(32),name:'App',version:'1',enabled:true,type:'hosted_app'}
 ]);
 assert.deepEqual(result,[{id:'a'.repeat(32),name:'Enabled',version:'1'}]);
});
test('Malformed extension metadata fails rather than silently misidentifying extensions',()=>{
 assert.throws(()=>enabledExtensions([{id:'bad',name:'Invalid',version:'1',enabled:true,type:'extension'}]));
});
test('Chrome operating system names are normalized',()=>{
 assert.equal(platformName('win'),'Windows');assert.equal(platformName('mac'),'macOS');
 assert.equal(platformName('cros'),'ChromeOS');assert.equal(platformName('unknown'),'Other');
});
test('Inventory API routes are bounded and traversal is denied',()=>{
 assert(safeApiPath('/api/inventory/devices','POST'));
 assert(safeApiPath('/api/inventory/devices/device-a123/status','POST'));
 assert(!safeApiPath('/api/inventory/devices/../../admin/accounts','POST'));
 assert(!safeApiPath('/api/inventory/devices/device-a123/delete','POST'));
});
