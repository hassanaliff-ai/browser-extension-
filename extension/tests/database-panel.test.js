import test from 'node:test';
import assert from 'node:assert/strict';
import {databasePanel} from '../database-panel.js';
import {safeApiPath} from '../core.js';
test('Database status is an allowed read but never a mutation',()=>{
  assert.equal(safeApiPath('/api/database/status','GET'),true);
  assert.equal(safeApiPath('/api/database/status','POST'),false);
});
test('Panel identifies the real target and distinguishes empty data from failure',()=>{
  const html=databasePanel({healthy:true,connection:{engine:'PostgreSQL',host:'127.0.0.1',port:5432,database:'extsecure',schema:'public'},table_count:37,view_count:8,total_rows:171,table_rows:{scans:7,alerts:0}});
  assert.match(html,/5432 \/ extsecure \/ public/);
  assert.match(html,/171 saved records/);assert.match(html,/Zero records can be correct/);
});
test('Database details cannot inject HTML and non-PostgreSQL storage is not verified',()=>{
  const html=databasePanel({healthy:false,connection:{engine:'sqlite'},reason:'<script>private</script>'});
  assert.doesNotMatch(html,/<script>/);assert.doesNotMatch(html,/Verified PostgreSQL storage/);
});
