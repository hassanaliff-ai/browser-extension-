import {markThemeChange} from './motion.js';
export const THEMES=[['light','Light'],['dark','Dark'],['system','Use device setting']];
let activeTheme='light',media;
export function normalizeTheme(value='light',strict=false){
 const valid=THEMES.some(([key])=>key===value);
 if(strict&&!valid)throw new Error('Choose a supported appearance.');
 return valid?value:'light';
}
function paint(dark){
 if(typeof document!=='undefined'){
  const next=dark?'dark':'light',previous=document.documentElement.getAttribute?.('data-theme');
  if(previous&&previous!==next)markThemeChange(next);
  document.documentElement.setAttribute?.('data-theme',next);
  for(const button of document.querySelectorAll?.('[data-theme-toggle]')??[])button.setAttribute('aria-pressed',String(dark));
 }
}
export const resolvedTheme=(value=activeTheme)=>normalizeTheme(value)==='dark'||normalizeTheme(value)==='system'&&media?.matches===true?'dark':'light';
export function applyTheme(value){
 const previous=activeTheme;
 activeTheme=normalizeTheme(value);
 if(!media&&typeof globalThis.matchMedia==='function'){
  media=globalThis.matchMedia('(prefers-color-scheme: dark)');
  media.addEventListener('change',event=>{if(activeTheme==='system')paint(event.matches);});
 }
 paint(resolvedTheme()==='dark');
 for(const control of globalThis.document?.querySelectorAll?.('select[name=theme]')??[])if(control.value===previous)control.value=activeTheme;
}
