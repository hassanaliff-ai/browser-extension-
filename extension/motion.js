// Presentation never delays a security request, warning or containment action.
let enabled=true,media,timer;
const moving=new Map();
function stopMotion(){
 clearTimeout(timer);
 for(const [element,animation] of moving){animation.cancel?.();element.removeAttribute?.('data-section-direction');}
 moving.clear();
 const root=globalThis.document?.documentElement;
 root?.removeAttribute?.('data-theme-transition');
 root?.removeAttribute?.('data-theme-direction');
}
function sync(){
 const root=globalThis.document?.documentElement;
 root?.setAttribute?.('data-motion',motionEnabled()?'on':'off');
 if(!motionEnabled())stopMotion();
}
export function motionEnabled(){return enabled&&media?.matches!==true;}
export function applyMotion(value=true){
 enabled=value===true;
 if(!media&&typeof globalThis.matchMedia==='function'){
  media=globalThis.matchMedia('(prefers-reduced-motion: reduce)');
  media.addEventListener?.('change',sync);
 }
 sync();
 return motionEnabled();
}
export function markThemeChange(next){
 const root=globalThis.document?.documentElement;
 if(!root||!motionEnabled())return;
 clearTimeout(timer);
 root.setAttribute?.('data-theme-transition','active');
 root.setAttribute?.('data-theme-direction',next==='dark'?'dark':'light');
 const surface=globalThis.document?.querySelector?.('.console #main, .popup-main, .auth-content');
 animateSection(surface,{kind:'theme'});
 timer=setTimeout(()=>{
  root.removeAttribute?.('data-theme-transition');
  root.removeAttribute?.('data-theme-direction');
 },460);
 timer.unref?.();
}
export function animateSection(element,{from='',to='',order=[],kind='section'}={}){
 if(!element||typeof element.animate!=='function'||!motionEnabled())return false;
 moving.get(element)?.cancel?.();
 const previous=order.indexOf(from),current=order.indexOf(to);
 const direction=previous<0||current<0||previous===current?0:current>previous?1:-1;
 const rtl=globalThis.document?.documentElement?.dir==='rtl';
 const offset=direction*(rtl?-1:1)*36;
 element.setAttribute?.('data-section-direction',direction>0?'forward':direction<0?'backward':'refresh');
 const animation=element.animate([
  {opacity:kind==='theme'?.99:.97,transform:kind==='theme'?'translate3d(0,8px,0) scale(.985)':direction?`translate3d(${offset}px,0,0)`:'translate3d(0,18px,0)'},
  {opacity:1,transform:'none'}
 ],{duration:420,easing:'cubic-bezier(.16,1,.3,1)',fill:'none'});
 moving.set(element,animation);
 const cleanup=()=>{if(moving.get(element)===animation){moving.delete(element);element.removeAttribute?.('data-section-direction');}};
 Promise.resolve(animation.finished).then(cleanup,cleanup);
 return true;
}
