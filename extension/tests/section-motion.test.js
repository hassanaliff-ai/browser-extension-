import test from 'node:test';
import assert from 'node:assert/strict';
let serial=0;
async function setup(rtl=false){
 const old={document:globalThis.document,matchMedia:globalThis.matchMedia};let change;
 const root={dir:rtl?'rtl':'ltr',setAttribute(){},removeAttribute(){}};
 const media={matches:false,addEventListener:(name,fn)=>change=fn};
 globalThis.document={documentElement:root};globalThis.matchMedia=()=>media;
 const motion=await import('../motion.js?section='+ ++serial);motion.applyMotion(true);
 const attributes={},runs=[];
 const element={setAttribute:(k,v)=>attributes[k]=v,removeAttribute:k=>delete attributes[k],animate(frames,options){let finish,reject;const finished=new Promise((yes,no)=>{finish=yes;reject=no;});const run={frames,options,finished,finish,cancel(){this.cancelled=true;reject(new Error('cancelled'));}};runs.push(run);return run;}};
 return {motion,element,attributes,runs,media,change:()=>change(),restore(){motion.applyMotion(false);Object.assign(globalThis,old);}};
}
test('Section movement follows navigation order and keeps evidence visible',async()=>{
 const f=await setup();try{
  assert.equal(f.motion.animateSection(f.element,{from:'overview',to:'alerts',order:['overview','alerts']}),true);
  assert.equal(f.runs[0].frames[0].transform,'translate3d(24px,0,0)');
  assert.equal(f.runs[0].frames[0].opacity,.97);
  assert.equal(f.runs[0].options.fill,'none');assert.equal(f.runs[0].options.duration,320);
  f.runs[0].finish();await Promise.resolve();assert.equal(f.attributes['data-section-direction'],undefined);
 }finally{f.restore();}
});
test('RTL navigation reverses spatial direction',async()=>{
 const f=await setup(true);try{f.motion.animateSection(f.element,{from:'overview',to:'alerts',order:['overview','alerts']});assert.equal(f.runs[0].frames[0].transform,'translate3d(-24px,0,0)');}finally{f.restore();}
});
test('Turning motion off cancels movement already running',async()=>{
 const f=await setup();try{f.motion.animateSection(f.element);f.motion.applyMotion(false);assert.equal(f.runs[0].cancelled,true);assert.equal(f.attributes['data-section-direction'],undefined);assert.equal(f.motion.animateSection(f.element),false);}finally{f.restore();}
});
test('Device reduced motion cancels movement immediately',async()=>{
 const f=await setup();try{f.motion.animateSection(f.element);f.media.matches=true;f.change();assert.equal(f.runs[0].cancelled,true);assert.equal(f.motion.motionEnabled(),false);}finally{f.restore();}
});
test('Replacing movement does not let an old completion clear the current marker',async()=>{
 const f=await setup();try{f.motion.animateSection(f.element);f.motion.animateSection(f.element,{from:'a',to:'b',order:['a','b']});await Promise.resolve();assert.equal(f.runs[0].cancelled,true);assert.equal(f.attributes['data-section-direction'],'forward');f.runs[1].finish();await Promise.resolve();assert.equal(f.attributes['data-section-direction'],undefined);}finally{f.restore();}
});
test('Missing native animation support and absent targets remain usable',async()=>{
 const f=await setup();try{assert.equal(f.motion.animateSection(null),false);assert.equal(f.motion.animateSection({}),false);}finally{f.restore();}
});
