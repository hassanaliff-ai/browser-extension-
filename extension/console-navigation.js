import {escapeHtml as esc} from './core.js';

// Call with the already-authorized views. Search never adds routes or privileges.
export function consoleNavigation(views,current,icon){
  const groups=new Map();
  for(const row of views){const group=row[3];if(!groups.has(group))groups.set(group,[]);groups.get(group).push(row);}
  const sections=[...groups].map(([group,rows])=>`<details class="nav-group" data-nav-group="${esc(group)}" ${rows.some(([key])=>key===current)?'open':''}><summary>${esc(group)}</summary><div class="nav-group-items">${rows.map(([key,label,symbol])=>`<button class="nav-item ${current===key?'active':''}" data-view="${esc(key)}" data-nav-label="${esc(label)}" ${current===key?'aria-current="page"':''}>${icon(symbol)}<span>${esc(key==='files'?'File checks':key==='usability'?'Usability & accessibility':label)}</span></button>`).join('')}</div></details>`).join('');
  return `<div id="console-nav" class="console-nav"><label class="nav-search"><span class="sr-only">Find a section</span><input id="nav-filter" type="search" placeholder="Find a section…" aria-controls="console-nav-list" autocomplete="off"></label><nav id="console-nav-list" class="nav-scroll" aria-label="Security workflows">${sections}<p class="nav-empty" data-nav-empty hidden>No matching sections</p><p class="sr-only" data-nav-count role="status" aria-live="polite"></p></nav></div>`;
}

export function filterConsoleNavigation(container,query,translate=value=>value){
  const search=String(query??'').trim().toLocaleLowerCase();let visible=0;
  for(const group of container?.querySelectorAll('[data-nav-group]')??[]){
    const groupLabel=group.dataset.navGroup;
    const groupMatches=[groupLabel,translate(groupLabel)].some(value=>String(value).toLocaleLowerCase().includes(search));
    let matches=0;
    for(const button of group.querySelectorAll('[data-nav-label]')){
      const label=button.dataset.navLabel;
      const matched=!search||groupMatches||[label,translate(label),button.textContent].some(value=>String(value).toLocaleLowerCase().includes(search));
      button.hidden=!matched;if(matched){matches++;visible++;}
    }
    group.hidden=matches===0;
    if(search){if(group.dataset.searchOpen===undefined)group.dataset.searchOpen=String(group.open);group.open=matches>0;}
    else if(group.dataset.searchOpen!==undefined){group.open=group.dataset.searchOpen==='true';delete group.dataset.searchOpen;}
  }
  const empty=container?.querySelector('[data-nav-empty]');if(empty)empty.hidden=visible>0;
  const count=container?.querySelector('[data-nav-count]');if(count)count.textContent=visible+' '+translate('matching sections');
  return visible;
}

export function toggleConsoleNavigation(sidebar,button){
  const open=sidebar.classList.toggle('nav-open');button.setAttribute('aria-expanded',String(open));
  if(open)sidebar.querySelector('#nav-filter')?.focus();
  return open;
}
