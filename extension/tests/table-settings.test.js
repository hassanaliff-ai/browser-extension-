import test from 'node:test';
import assert from 'node:assert/strict';
import {loadTableSize,saveTableSize,observeTableSize} from '../table-settings.js';

test('Table density persists independently of a legacy worker and survives reopening',async()=>{
 const previous=globalThis.chrome,values={preferences:{theme:'dark',tableSize:'compact'}};
 globalThis.chrome={storage:{local:{get:async()=>values,set:async update=>Object.assign(values,update)}}};
 try{
  assert.equal(await loadTableSize(),'compact');
  await saveTableSize('spacious');
  values.preferences={theme:'dark'}; // Older worker does not recognize tableSize.
  assert.equal(await loadTableSize(),'spacious');
  assert.equal(values.preferences.theme,'dark');
  await assert.rejects(saveTableSize('invalid'),/supported table size/);
  assert.equal(await loadTableSize(),'spacious');
 }finally{globalThis.chrome=previous;}
});

test('Storage failures are reported instead of confirming an unsaved setting',async()=>{
 const previous=globalThis.chrome;
 globalThis.chrome={storage:{local:{set:async()=>{throw new Error('Storage unavailable');}}}};
 try{await assert.rejects(saveTableSize('compact'),/Storage unavailable/);}
 finally{globalThis.chrome=previous;}
});

test('Open console pages observe only local table setting changes',()=>{
 const previous=globalThis.chrome,seen=[];let listener;
 globalThis.chrome={storage:{onChanged:{addListener:callback=>listener=callback}}};
 try{
  observeTableSize(value=>seen.push(value));
  listener({extsecureTableSize:{newValue:'compact'}},'local');
  listener({preferences:{newValue:{theme:'dark'}}},'local');
  listener({extsecureTableSize:{newValue:'spacious'}},'sync');
  listener({extsecureTableSize:{newValue:'spacious'}},'local');
  listener({extsecureTableSize:{}},'local');
  assert.deepEqual(seen,['compact','spacious','standard']);
 }finally{globalThis.chrome=previous;}
});
