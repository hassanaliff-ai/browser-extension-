import test from 'node:test';
import assert from 'node:assert/strict';
import {summarize,evaluate,validateRows} from '../../scripts/evaluate_inline.mjs';
test('Evaluation counts missed phishing and false warnings with Unknown separate',()=>{
 const result=summarize([
  {label:'phishing',warned:true,severity:'High'},
  {label:'phishing',warned:false,severity:'Unknown'},
  {label:'benign-assumed',warned:true,severity:'Medium'},
  {label:'benign-assumed',warned:false,severity:'Low'}]);
 assert.equal(result.detection_rate,.5);assert.equal(result.false_warning_rate,.5);
 assert.equal(result.unknown_rate,.25);assert.equal(result.false_negative,1);
 assert.equal(summarize([]).detection_rate,null);assert.equal(summarize([]).precision,null);
});
test('Evaluation rejects duplicates and invalid labels instead of inflating counts',()=>{
 const row={id:'one',url:'https://example.com/a',label:'phishing',source:'test'};
 assert.throws(()=>validateRows([row,{...row,id:'two',url:'https://example.com/b'}]),/Duplicate origin/);
 assert.throws(()=>validateRows([{...row,label:'safe'}]),/label/);
});
test('Evaluation uses shipped rules without connecting to sample URLs',()=>{
 const original=globalThis.fetch;globalThis.fetch=()=>{throw new Error('Network forbidden');};
 try{
  const rows=evaluate([{id:'p',url:'https://paypal.com.demo.invalid/path?q=private',label:'phishing',source:'synthetic'},
   {id:'b',url:'https://example.com',label:'benign-assumed',source:'synthetic'}],3);
  assert.equal(rows[0].warned,true);assert.equal(rows[1].warned,false);
  assert(!JSON.stringify(rows).includes('q=private'));assert(rows[0].local_classification_median_ms>=0);
 }finally{globalThis.fetch=original;}
});
