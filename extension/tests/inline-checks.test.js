import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {checkInlineOrigins,inlineSender} from '../inline-checks.js';
import {scoreUrlLocally} from '../inline-score.js';

test('Inline batches reject private URL components, malformed inputs and oversized work',()=>{
  for(const value of [[],Array(51).fill('https://example.com'),['https://example.com/'],['https://example.com/private?token=secret'],['https://user:pass@example.com'],['file:///private'],[null]])
    assert.throws(()=>checkInlineOrigins(value));
});
test('Local rules explain reserved impersonation example without certifying a genuine address',()=>{
  const result=checkInlineOrigins(['https://paypal.com.evil.example','https://www.paypal.com','http://127.0.0.1:8765','https://www.paypal.com']);
  assert.equal(result.lookupStatus,'local-only');
  assert.equal(result.results.length,3);
  assert.equal(result.results[0].severity,'High');
  assert(result.results[0].reasons.some(s=>s.includes('embeds')));
  assert.equal(result.results[1].severity,'Low');
  assert.equal(result.results[2].severity,'Unknown');
  assert.equal(scoreUrlLocally('not a URL').severity,'Unknown');
});
test('Only the extension top-level web content script can use local inline messages',()=>{
  const runtime={id:'extension-id'};
  const good={id:runtime.id,frameId:0,tab:{id:4},url:'https://example.com/private?secret=x'};
  assert(inlineSender(good,runtime));
  for(const changed of [{id:'other'},{frameId:1},{tab:undefined},{tab:{id:-1}},{url:'chrome-extension://extension-id/console.html'},{url:'file:///secret'}])
    assert.equal(inlineSender({...good,...changed},runtime),false);
});
test('Release manifest loads the real inline assets in top frames after page load',()=>{
  const manifest=JSON.parse(readFileSync(new URL('../manifest.json',import.meta.url)));
  const entry=manifest.content_scripts.find(x=>x.js.includes('inline-links.js'));
  assert.equal(entry.run_at,'document_idle');assert.equal(entry.all_frames,false);
  assert(entry.css.includes('inline-links.css'));
  for(const path of [...entry.js,...entry.css])assert(readFileSync(new URL('../'+path,import.meta.url)).length);
});
