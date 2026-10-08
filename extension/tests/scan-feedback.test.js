import test from 'node:test';
import assert from 'node:assert/strict';
import {lookupFeedback} from '../scan-feedback.js';
import {setPreferences,translate} from '../locale.js';

test('An unlisted file hash explains the actual lookup rather than implying no scan ran',()=>{
 const result={severity:'Unknown',score:null,file_lookup:{verdict:'unknown',reason:'not_found',cache_hit:true}};
 const before=structuredClone(result),feedback=lookupFeedback(result);
 assert.match(feedback.message,/lookup ran.*no report/);assert.match(feedback.message,/not uploaded/);
 assert.equal(feedback.warning,true);assert.equal(feedback.cached,true);assert.deepEqual(result,before);
});
test('File feedback uses file_lookup even when no website lookup is present',()=>{
 const feedback=lookupFeedback({severity:'Low',file_lookup:{verdict:'clear',reason:null}});
 assert.equal(feedback.warning,false);assert.match(feedback.message,/lookup completed/);
});
test('Detected malicious and suspicious files retain their risk severity',()=>{
 for(const verdict of ['malicious','suspicious']){
  const result={severity:'High',score:70,file_lookup:{verdict}};
  assert.match(lookupFeedback(result).message,/recorded detections/);
  assert.equal(result.severity,'High');assert.equal(result.score,70);
 }
});
test('A successful website report displays completion and cache status',()=>{
 const feedback=lookupFeedback({severity:'Low',lookup:{status:'complete',cached:true}});
 assert.equal(feedback.warning,false);assert.equal(feedback.cached,true);
 assert.match(feedback.message,/website.*completed/);
});
test('Rate limit feedback includes the provider retry delay',()=>{
 const feedback=lookupFeedback({severity:'Unknown',file_lookup:{verdict:'unknown',reason:'rate_limited',retry_after_seconds:60}});
 assert.match(feedback.message,/request limit/);assert.equal(feedback.retry,60);
});
test('Invalid provider retry values do not become misleading countdowns',()=>{
 for(const retry of [-1,0,'60',Infinity]){
  assert.equal(lookupFeedback({file_lookup:{reason:'rate_limited',retry_after_seconds:retry}}).retry,null);
 }
});
test('Auth, configuration, network and invalid-response errors have useful explanations',()=>{
 for(const [reason,pattern] of [['provider_auth_failed',/rejected/],['not_configured',/not configured/],['lookup_failed',/Retry later/],['invalid_response',/invalid analysis/]]){
  const feedback=lookupFeedback({severity:'Unknown',file_lookup:{verdict:'unknown',reason}});
  assert.match(feedback.message,pattern);assert.equal(feedback.warning,true);
 }
});
test('Website-specific failure reason is retained for investigation',()=>{
 const feedback=lookupFeedback({severity:'Unknown',lookup:{status:'unavailable',reason:'The URL analysis is still pending.'}});
 assert.equal(feedback.message,'The URL analysis is still pending.');assert.equal(feedback.warning,true);
});
test('Older Unknown history records and incomplete lookup envelopes explain missing evidence',()=>{
 for(const result of [{severity:'Unknown'},{severity:'Unknown',file_lookup:{verdict:'unknown'}},{severity:'Unknown',lookup:{}}]){
  assert.match(lookupFeedback(result).message,/No usable reputation evidence/);
 }
 assert.equal(lookupFeedback({severity:'Low'}),null);
});
test('The new feedback is available in Arabic as well as English',()=>{
 const messages=[lookupFeedback({severity:'Unknown',file_lookup:{reason:'not_found'}}).message,lookupFeedback({severity:'Low',lookup:{status:'complete'}}).message,'Retry after','Cached reputation result'];
 try {setPreferences({language:'ar',timeZone:'Asia/Riyadh'});
  for(const message of messages){assert.notEqual(translate(message),message);assert.match(translate(message),/[\u0600-\u06ff]/);}
 }finally{setPreferences({language:'en',timeZone:'UTC'});}
});
