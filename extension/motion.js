// Motion is presentation-only. Security checks and actions never await it.
let enabled=true,media,timer;
function sync(){
 const root=globalThis.document?.documentElement;
 root?.setAttribute?.('data-motion',motionEnabled()?'on':'off');
 if(!motionEnabled())root?.removeAttribute?.('data-theme-transition');
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
export function markThemeChange(){
 const root=globalThis.document?.documentElement;
 if(!root||!motionEnabled())return;
 clearTimeout(timer);
 root.setAttribute?.('data-theme-transition','active');
 timer=setTimeout(()=>root.removeAttribute?.('data-theme-transition'),260);
 timer.unref?.();
}
