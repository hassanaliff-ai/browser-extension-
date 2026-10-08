import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeTheme,applyTheme,resolvedTheme} from '../theme.js';
import {normalizePreferences} from '../locale.js';

test('Appearance accepts only supported choices and preserves old preference defaults',()=>{
 for(const theme of ['light','dark','system'])assert.equal(normalizePreferences({theme},true).theme,theme);
 assert.equal(normalizePreferences({language:'ar'}).theme,'light');
 assert.equal(normalizeTheme('invalid'),'light');assert.throws(()=>normalizeTheme('invalid',true),/supported appearance/);
 assert.deepEqual(normalizePreferences({theme:'dark',token:'private',password:'private'}),{theme:'dark',language:'en',timeZone:'UTC',tableSize:'standard'});
});
test('Device appearance follows OS changes while explicit light or dark choices override them',()=>{
 const oldDocument=globalThis.document,oldMatchMedia=globalThis.matchMedia;
 const attrs={},pressed={};let listener;
 const media={matches:true,addEventListener:(name,callback)=>listener=callback};
 globalThis.matchMedia=()=>media;
 globalThis.document={documentElement:{setAttribute:(name,value)=>attrs[name]=value},querySelectorAll:()=>[{setAttribute:(name,value)=>pressed[name]=value}]};
 try{
  applyTheme('system');assert.equal(attrs['data-theme'],'dark');assert.equal(pressed['aria-pressed'],'true');
  media.matches=false;listener({matches:false});assert.equal(attrs['data-theme'],'light');assert.equal(resolvedTheme(),'light');
  applyTheme('dark');listener({matches:false});assert.equal(attrs['data-theme'],'dark');
  applyTheme('light');media.matches=true;listener({matches:true});assert.equal(attrs['data-theme'],'light');
 }finally{globalThis.document=oldDocument;globalThis.matchMedia=oldMatchMedia;}
});
