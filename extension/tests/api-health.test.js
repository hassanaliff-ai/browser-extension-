import test from 'node:test';
import assert from 'node:assert/strict';
import {probeApi} from '../api-health.js';
const origin='https://api.example',policy='administrator-self-review-v1';
const good=()=>Response.json({status:'ok',service:'TestAPI',website_access_policy:policy,secret:'never forwarded'});
test('Transient network failure recovers with an anonymous read-only health retry',async()=>{
 const calls=[];const r=await probeApi(origin,policy,{wait:async()=>{},fetcher:async(url,options)=>{calls.push({url,options});if(calls.length===1)throw new TypeError('network');return good();}});
 assert.equal(r.status,'ready');assert.equal(r.attempts,2);assert.equal(calls.length,2);
 for(const {url,options} of calls){assert.equal(url,origin+'/health');assert.equal(options.method,'GET');assert.equal(options.credentials,'omit');assert.equal(options.redirect,'error');assert.deepEqual(options.headers,{Accept:'application/json'});assert.equal(options.body,undefined);}
 assert(!JSON.stringify(r).includes('secret'));
});
test('A hung fetch is aborted, then the next attempt can recover',async()=>{
 let count=0;const r=await probeApi(origin,policy,{timeout:5,wait:async()=>{},fetcher:async(_,options)=>{if(++count===2)return good();return new Promise((_,reject)=>options.signal.addEventListener('abort',()=>reject(new DOMException('aborted','AbortError'))));}});
 assert.equal(r.status,'ready');assert.equal(count,2);
});
test('Persistent timeout stays offline after exactly two attempts',async()=>{
 let count=0;const r=await probeApi(origin,policy,{wait:async()=>{},fetcher:async()=>{count++;throw new DOMException('slow','TimeoutError');}});
 assert.equal(r.status,'offline');assert.equal(r.reason,'timeout');assert.equal(count,2);
});
test('Transient gateway status retries but authentication and other client errors do not',async()=>{
 for(const status of [502,503,504,401,403,429]){let count=0;const r=await probeApi(origin,policy,{wait:async()=>{},fetcher:async()=>++count===1?new Response('',{status}):good()});assert.equal(count,[502,503,504].includes(status)?2:1);assert.equal(r.status,count===2?'ready':'offline');}
});
test('Malformed, unrelated and outdated services are never retried or called ready',async()=>{
 for(const [response,status,reason] of [[()=>new Response('<html>'), 'offline','invalid_response'],[()=>Response.json({status:'ok',service:'other'}),'offline','unexpected_service'],[()=>Response.json({status:'ok',service:'TestAPI'}),'update_required','website_access_policy_outdated']]){let count=0;const r=await probeApi(origin,policy,{fetcher:async()=>{count++;return response();}});assert.equal(count,1);assert.equal(r.status,status);assert.equal(r.reason,reason);}
});

test('Render cold start can recover on the sixth anonymous health probe',async()=>{
 let count=0;const calls=[];
 const r=await probeApi('https://extsecure-api-htg7.onrender.com',policy,{wait:async()=>{},fetcher:async(url,options)=>{calls.push(options);return ++count<6?new Response('',{status:503}):good();}});
 assert.equal(r.status,'ready');assert.equal(r.attempts,6);
 assert(calls.every(options=>options.method==='GET'&&options.credentials==='omit'&&!options.headers.Authorization&&!options.body));
});

test('Render wake retries stay bounded and never replay rejected authentication',async()=>{
 for(const [status,expected] of [[503,6],[401,1],[403,1],[429,1]]){
  let count=0;const r=await probeApi('https://extsecure-api-htg7.onrender.com',policy,{wait:async()=>{},fetcher:async()=>{count++;return new Response('',{status});}});
  assert.equal(count,expected);assert.equal(r.status,'offline');
 }
});
