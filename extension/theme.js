export const THEMES=[['light','Light'],['dark','Dark'],['system','Use device setting']];
let activeTheme='light',media;
export function normalizeTheme(value='light',strict=false){
 const valid=THEMES.some(([key])=>key===value);
 if(strict&&!valid)throw new Error('Choose a supported appearance.');
 return valid?value:'light';
}
function paint(dark){
 if(typeof document!=='undefined'){
  document.documentElement.setAttribute?.('data-theme',dark?'dark':'light');
  for(const button of document.querySelectorAll?.('[data-theme-toggle]')??[])button.setAttribute('aria-pressed',String(dark));
 }
}
export const resolvedTheme=(value=activeTheme)=>normalizeTheme(value)==='dark'||normalizeTheme(value)==='system'&&media?.matches===true?'dark':'light';
export function applyTheme(value){
 activeTheme=normalizeTheme(value);
 if(!media&&typeof globalThis.matchMedia==='function'){
  media=globalThis.matchMedia('(prefers-color-scheme: dark)');
  media.addEventListener('change',event=>{if(activeTheme==='system')paint(event.matches);});
 }
 paint(resolvedTheme()==='dark');
}
