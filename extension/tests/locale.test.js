import test from 'node:test';
import assert from 'node:assert/strict';
import {localize,setPreferences,translate} from '../locale.js';

// A small DOM fixture exercises localization mutations without browser APIs.
function fixture({text='Language',label='Language',placeholder='Password',protectedEvidence=false}={}){
 const attributes=new Map([['aria-label',label],['placeholder',placeholder]]);
 const element={getAttribute:name=>attributes.get(name)??null,setAttribute:(name,value)=>attributes.set(name,value),closest:()=>protectedEvidence?element:null};
 const node={nodeValue:text,parentElement:element};
 const root={querySelectorAll:()=>[element]};
 globalThis.NodeFilter={SHOW_TEXT:4};
 globalThis.document={documentElement:{},createTreeWalker:()=>{let visited=false;return {currentNode:null,nextNode(){if(visited)return false;visited=true;this.currentNode=node;return true;}};}};
 return {root,node,element};
}

test('Arabic labels and placeholders restore English on the same elements',()=>{
 const {root,element}=fixture();
 setPreferences({language:'ar'});localize(root);
 assert.equal(element.getAttribute('aria-label'),translate('Language'));
 assert.equal(element.getAttribute('placeholder'),translate('Password'));
 setPreferences({language:'en'});localize(root);
 assert.equal(element.getAttribute('aria-label'),'Language');
 assert.equal(element.getAttribute('placeholder'),'Password');
});

test('A new accessible label replaces the old source instead of being overwritten',()=>{
 const {root,element}=fixture();
 setPreferences({language:'ar'});localize(root);
 element.setAttribute('aria-label','Username');localize(root);
 assert.equal(element.getAttribute('aria-label'),translate('Username'));
 setPreferences({language:'en'});localize(root);
 assert.equal(element.getAttribute('aria-label'),'Username');
});

test('Repeated localization preserves punctuation and restores original text',()=>{
 const {root,node}=fixture({text:' · Language '});
 setPreferences({language:'ar'});localize(root);localize(root);
 assert.equal(node.nodeValue,' · '+translate('Language')+' ');
 setPreferences({language:'en'});localize(root);
 assert.equal(node.nodeValue,' · Language ');
});

test('Updated text on a reused node is localized using the new content',()=>{
 const {root,node}=fixture();
 setPreferences({language:'ar'});localize(root);
 node.nodeValue='Password';localize(root);
 assert.equal(node.nodeValue,translate('Password'));
 setPreferences({language:'en'});localize(root);
 assert.equal(node.nodeValue,'Password');
});

test('Recorded evidence is preserved even when it equals a translated UI phrase',()=>{
 const {root,node,element}=fixture({text:'Language',protectedEvidence:true});
 setPreferences({language:'ar'});localize(root);
 assert.equal(node.nodeValue,'Language');
 assert.equal(element.getAttribute('aria-label'),'Language');
 assert.equal(element.getAttribute('placeholder'),'Password');
});

test('Dynamic accessible labels outside the dictionary keep their exact value',()=>{
 const {root,element}=fixture();
 setPreferences({language:'ar'});localize(root);
 element.setAttribute('aria-label','Investigation ABC-123');localize(root);
 setPreferences({language:'en'});localize(root);
 assert.equal(element.getAttribute('aria-label'),'Investigation ABC-123');
});
