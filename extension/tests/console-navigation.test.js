import test from 'node:test';
import assert from 'node:assert/strict';
import {consoleNavigation,filterConsoleNavigation,toggleConsoleNavigation} from '../console-navigation.js';

const makeButton=label=>({dataset:{navLabel:label},textContent:label,hidden:false});
const makeGroup=(label,labels,open=false)=>({dataset:{navGroup:label},open,hidden:false,buttons:labels.map(makeButton),querySelectorAll(){return this.buttons;}});
function fixture(){
 const groups=[makeGroup('Monitor',['Overview','Scan a page'],true),makeGroup('Inventory',['Devices','Extensions']),makeGroup('Investigate',['Reports'])];
 const empty={hidden:true},count={textContent:''};
 const container={querySelectorAll:()=>groups,querySelector:selector=>selector==='[data-nav-empty]'?empty:count};
 return {container,groups,empty,count};
}
test('Console navigation contains only authorized routes and opens the current group',()=>{
 const markup=consoleNavigation([['overview','Overview','grid','Monitor'],['reports','Reports','chart','Investigate']],'reports',()=>'<svg></svg>');
 assert.match(markup,/data-nav-group="Investigate" open/);assert.match(markup,/data-view="reports"[^>]+aria-current="page"/);
 assert.doesNotMatch(markup,/data-view="accounts"/);
 assert(!consoleNavigation([['reports','<script>bad</script>','chart','Investigate']],'reports',()=>'<svg></svg>').includes('<script>'));
});
test('Navigation search opens matching groups and clearing restores previous disclosure state',()=>{
 const {container,groups}=fixture();
 assert.equal(filterConsoleNavigation(container,'  DEVices  '),1);
 assert.equal(groups[1].open,true);assert.equal(groups[0].hidden,true);assert.equal(groups[1].buttons[1].hidden,true);
 assert.equal(filterConsoleNavigation(container,''),5);
 assert.equal(groups[0].open,true);assert.equal(groups[1].open,false);assert.equal(groups.every(g=>!g.hidden&&g.buttons.every(b=>!b.hidden)),true);
});
test('Arabic search finds the translated label without changing source route data',()=>{
 const {container,groups}=fixture();
 assert.equal(filterConsoleNavigation(container,'التقارير',value=>value==='Reports'?'التقارير':value),1);
 assert.equal(groups[2].buttons[0].dataset.navLabel,'Reports');assert.equal(groups[2].open,true);
});
test('Group searches match its sections and unmatched searches announce an empty result',()=>{
 const {container,groups,empty,count}=fixture();
 assert.equal(filterConsoleNavigation(container,'Inventory'),2);assert.equal(groups[1].hidden,false);
 assert.equal(filterConsoleNavigation(container,'nonexistent-section'),0);assert.equal(empty.hidden,false);assert.equal(count.textContent,'0 matching sections');
 filterConsoleNavigation(container,'');assert.equal(empty.hidden,true);
});
test('Mobile navigation toggle exposes its state and focuses search only when opening',()=>{
 let open=false,focus=0;const states=[];
 const sidebar={classList:{toggle:()=>open=!open},querySelector:()=>({focus:()=>focus++})};
 const button={setAttribute:(name,value)=>states.push([name,value])};
 assert.equal(toggleConsoleNavigation(sidebar,button),true);assert.equal(toggleConsoleNavigation(sidebar,button),false);
 assert.equal(focus,1);assert.deepEqual(states,[['aria-expanded','true'],['aria-expanded','false']]);
});
