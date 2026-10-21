import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizePreferences} from '../locale.js';
let id=0;
async function fixture(reduced=false){
 const previous={document:globalThis.document,matchMedia:globalThis.matchMedia};
 const attributes={};let listener;
 const media={matches:reduced,addEventListener:(type,callback)=>{assert.equal(type,'change');listener=callback;}};
 globalThis.document={documentElement:{setAttribute:(key,value)=>attributes[key]=value,removeAttribute:key=>delete attributes[key]}};
 globalThis.matchMedia=query=>{assert.equal(query,'(prefers-reduced-motion: reduce)');return media;};
 const motion=await import('../motion.js?test='+ ++id);
 return {motion,attributes,media,change:()=>listener(),restore(){Object.assign(globalThis,previous);}};
}
test('Old preference records enable gentle motion by default without keeping private fields',()=>{
 assert.equal(normalizePreferences({theme:'dark'}).animations,true);
 assert.deepEqual(Object.keys(normalizePreferences({animations:false,token:'private'})).sort(),['animations','language','tableSize','theme','timeZone']);
 assert.equal(normalizePreferences({animations:false}).animations,false);
});
test('Strict animation input rejects strings and arbitrary values',()=>{
 for(const value of ['false','on',0,1,{},[]])assert.throws(()=>normalizePreferences({animations:value},true),/animations/);
});
test('The explicit off preference disables theme transition markers immediately',async()=>{
 const f=await fixture();try{f.motion.applyMotion(true);f.motion.markThemeChange();assert.equal(f.attributes['data-theme-transition'],'active');f.motion.applyMotion(false);assert.equal(f.attributes['data-motion'],'off');assert.equal(f.attributes['data-theme-transition'],undefined);f.motion.markThemeChange();assert.equal(f.attributes['data-theme-transition'],undefined);}finally{f.restore();}
});
test('Device reduced motion takes priority over an enabled preference',async()=>{
 const f=await fixture(true);try{assert.equal(f.motion.applyMotion(true),false);assert.equal(f.attributes['data-motion'],'off');}finally{f.restore();}
});
test('Device preference changes take effect while the extension is open',async()=>{
 const f=await fixture();try{f.motion.applyMotion(true);assert.equal(f.attributes['data-motion'],'on');f.media.matches=true;f.change();assert.equal(f.attributes['data-motion'],'off');f.media.matches=false;f.change();assert.equal(f.attributes['data-motion'],'on');f.motion.applyMotion(false);f.media.matches=true;f.change();f.media.matches=false;f.change();assert.equal(f.attributes['data-motion'],'off');}finally{f.restore();}
});
test('Motion helpers safely run without a document in a service worker',async()=>{
 const previous={document:globalThis.document,matchMedia:globalThis.matchMedia};
 try{delete globalThis.document;delete globalThis.matchMedia;const motion=await import('../motion.js?worker');assert.equal(motion.applyMotion(false),false);assert.doesNotThrow(()=>motion.markThemeChange());}finally{Object.assign(globalThis,previous);}
});
