import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {accessTarget,visitRule,navigationTarget} from '../access.js';
import {normalizePreferences,setPreferences,formatDate,translate} from '../locale.js';
import {safeApiPath,roleCanWrite,completedMonth} from '../core.js';
test('Approval URLs drop private parameters without expanding path scope',()=>{
 assert.equal(accessTarget('https://EXAMPLE.COM:443/a?secret=1#hidden'),'https://example.com/a');
 assert.equal(accessTarget('https://example.com./a'),'https://example.com/a');
 assert.throws(()=>accessTarget('https://name:password@example.com/'));
 assert.throws(()=>accessTarget('javascript:alert(1)'));
});
test('Opening uses the same canonical host as the approval rule while retaining private query and fragment locally',()=>{
 const opened=navigationTarget('https://EXAMPLE.COM.:443/approved?private=local#section');
 assert.equal(opened,'https://example.com/approved?private=local#section');
 const rule=visitRule(1,accessTarget(opened));
 assert.equal(new RegExp(rule.condition.regexFilter).test(opened.split('#')[0]),true);
 assert.throws(()=>navigationTarget('https://name:password@example.com/'));
});
test('One-visit allow matches one tab, method, scheme, host, port and case-sensitive path',()=>{
 const rule=visitRule(42,'https://example.com/A+b.c');
 assert.deepEqual(rule.condition.tabIds,[42]);
 assert.deepEqual(rule.condition.resourceTypes,['main_frame']);
 assert.deepEqual(rule.condition.requestMethods,['get']);
 assert.equal(rule.condition.isUrlFilterCaseSensitive,true);
 const regex=new RegExp(rule.condition.regexFilter);
 assert.equal(regex.test('https://example.com/A+b.c?private=1'),true);
 for(const value of ['http://example.com/A+b.c','https://example.com.evil/A+b.c','https://example.com/Axbxc','https://example.com/a+b.c','https://example.com/A+b.c/extra','https://example.com:8443/A+b.c'])assert.equal(regex.test(value),false,value);
 assert.throws(()=>visitRule(-1,'https://example.com/'));
});
test('Static navigation gate covers main-frame HTTP and HTTPS while worker sleeps',async()=>{
 const manifest=JSON.parse(await fs.readFile(new URL('../manifest.json',import.meta.url)));
 const rules=JSON.parse(await fs.readFile(new URL('../rules/navigation.json',import.meta.url)));
 assert.equal(manifest.declarative_net_request.rule_resources[0].enabled,true);
 const gate=rules.find(r=>r.action.type==='redirect');
 assert.equal(gate.action.redirect.extensionPath,'/blocked.html');
 assert.deepEqual(gate.condition.resourceTypes,['main_frame']);
 const regex=new RegExp(gate.condition.regexFilter);
 for(const url of ['http://example.com/','https://example.com/private'])assert.equal(regex.test(url),true);
 assert.equal(regex.test('chrome-extension://abc/console.html'),false);
 const exempt=new RegExp(rules.find(r=>r.action.type==='allow').condition.regexFilter);
 assert.equal(exempt.test('http://127.0.0.1:8765/docs'),true);
 for(const url of ['http://localhost:9999/','http://localhost.evil:8765/','http://127.0.0.1:8765.evil/'])assert.equal(exempt.test(url),false);
});
test('Preference validation keeps session and scoring data out of local settings',()=>{
 assert.deepEqual(normalizePreferences({language:'ar',timeZone:'Asia/Riyadh',token:'private'}),{language:'ar',timeZone:'Asia/Riyadh'});
 assert.deepEqual(normalizePreferences({language:'xx',timeZone:'bad'}),{language:'en',timeZone:'UTC'});
 assert.throws(()=>normalizePreferences({language:'xx'},true));
 assert.throws(()=>normalizePreferences({timeZone:'bad'},true));
});
test('KSA timestamps move three hours while UTC month accounting stays unchanged',()=>{
 setPreferences({language:'en',timeZone:'UTC'});assert.match(formatDate('2026-09-30T23:30:00Z'),/23:30/);
 setPreferences({language:'en',timeZone:'Asia/Riyadh'});const result=formatDate('2026-09-30T23:30:00Z');assert.match(result,/02:30/);assert.match(result,/1 Oct/);
 assert.equal(completedMonth(new Date('2026-10-01T00:01:00Z')),'2026-09');
 assert.equal(formatDate('invalid'),'—');
});
test('Arabic localization covers the approval journey and does not modify evidence',()=>{
 setPreferences({language:'ar',timeZone:'Asia/Riyadh'});
 assert.equal(translate('Request access'),'طلب الوصول');
 assert.equal(translate('Administrator'),'مسؤول النظام');
 assert.equal(translate('https://example.com/'),'https://example.com/');
 assert.match(formatDate('2026-10-05T00:00:00Z'),/Asia\/Riyadh/);
 setPreferences({language:'en',timeZone:'UTC'});assert.equal(translate('Request access'),'Request access');
});
test('Approval messages use narrow route grants and manager privileges',()=>{
 for(const path of ['/api/access/requests','/api/access/whitelist'])assert.equal(safeApiPath(path),true);
 for(const path of ['/api/access/check','/api/access/consume','/api/access/requests/test-id/review','/api/access/whitelist/test-id/revoke'])assert.equal(safeApiPath(path,'POST'),true);
 for(const path of ['/api/access/everything','/api/access/requests/../review','/api/access/requests?target=secret'])assert.equal(safeApiPath(path,'POST'),false);
 assert.equal(roleCanWrite({role:'manager'},'access'),true);
 assert.equal(roleCanWrite({role:'normal_user'},'access'),false);
 assert.equal(roleCanWrite({role:'manager'},'overrides'),false);
});
