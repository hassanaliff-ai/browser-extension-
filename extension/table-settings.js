import {TABLE_SIZES} from './locale.js';

const KEY='extsecureTableSize';
const valid=value=>TABLE_SIZES.some(([key])=>key===value);

export async function loadTableSize(fallback='standard') {
  const storage=globalThis.chrome?.storage?.local;
  if(storage){const values=await storage.get([KEY,'preferences']);return valid(values[KEY])?values[KEY]:valid(values.preferences?.tableSize)?values.preferences.tableSize:valid(fallback)?fallback:'standard';}
  if(typeof localStorage!=='undefined'){const saved=localStorage.getItem(KEY);if(valid(saved))return saved;}
  return valid(fallback)?fallback:'standard';
}

export async function saveTableSize(value) {
  if(!valid(value))throw new Error('Choose a supported table size.');
  const storage=globalThis.chrome?.storage?.local;
  if(storage)await storage.set({[KEY]:value});
  else if(typeof localStorage!=='undefined')localStorage.setItem(KEY,value);
  else throw new Error('Table settings could not be saved. Reopen the extension and try again.');
  return value;
}

export function observeTableSize(onChange) {
  const changed=globalThis.chrome?.storage?.onChanged;
  if(changed)changed.addListener((changes,area)=>{
    if(area==='local'&&Object.hasOwn(changes,KEY))onChange(valid(changes[KEY].newValue)?changes[KEY].newValue:'standard');
  });
  else if(typeof window!=='undefined')window.addEventListener('storage',event=>{
    if(event.key===KEY||event.key===null)onChange(valid(event.newValue)?event.newValue:'standard');
  });
}
