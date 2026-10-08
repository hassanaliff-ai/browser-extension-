import {escapeHtml} from './core.js';

export const MAX_LOGO_FILE_SIZE=2*1024*1024;
export const MAX_LOGO_BYTES=160*1024;
const PREFIX='data:image/png;base64,';

export function validateLogo(value) {
  if(typeof value!=='string'||!value.startsWith(PREFIX)||value.length>PREFIX.length+MAX_LOGO_BYTES*4/3)
    throw new Error('Choose a valid PNG profile logo.');
  const encoded=value.slice(PREFIX.length);
  if(!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded))
    throw new Error('Choose a valid PNG profile logo.');
  const bytes=Uint8Array.from(atob(encoded),c=>c.charCodeAt(0));
  const signature=[137,80,78,71,13,10,26,10];
  if(bytes.length<33||signature.some((v,i)=>bytes[i]!==v)||String.fromCharCode(...bytes.slice(12,16))!=='IHDR')
    throw new Error('Choose a valid PNG profile logo.');
  const header=new DataView(bytes.buffer),width=header.getUint32(16),height=header.getUint32(20);
  if(header.getUint32(8)!==13||!width||!height||width>192||height>192)
    throw new Error('Profile logos must be 192 pixels or smaller.');
  return bytes;
}

export function avatar(profile,large=false) {
  let logo='';
  try{if(profile?.logo){validateLogo(profile.logo);logo=profile.logo;}}catch{/* Corrupt local images fall back to initials. */}
  return `<div class="avatar${large?' avatar-large':''}">${logo?`<img src="${escapeHtml(logo)}" alt="Profile logo" width="${large?80:35}" height="${large?80:35}">`:`<span data-no-translate>${escapeHtml(profile?.username?.slice(0,2).toUpperCase()??'')}</span>`}</div>`;
}

export async function prepareLogo(file) {
  if(!file)throw new Error('Choose an image first.');
  if(!['image/png','image/jpeg','image/webp'].includes(file.type))throw new Error('Choose a PNG, JPG or WebP image.');
  if(!file.size||file.size>MAX_LOGO_FILE_SIZE)throw new Error('Choose an image of 2 MiB or less.');
  let bitmap;
  try{bitmap=await createImageBitmap(file);}catch{throw new Error('This image could not be opened. Choose another image.');}
  try{
    if(!bitmap.width||!bitmap.height||bitmap.width>4096||bitmap.height>4096)throw new Error('Choose an image no larger than 4096 pixels on either side.');
    const canvas=document.createElement('canvas');canvas.width=192;canvas.height=192;
    const context=canvas.getContext('2d');
    const side=Math.min(bitmap.width,bitmap.height);
    context.drawImage(bitmap,(bitmap.width-side)/2,(bitmap.height-side)/2,side,side,0,0,192,192);
    const logo=canvas.toDataURL('image/png');validateLogo(logo);return logo;
  }finally{bitmap.close();}
}

export async function logoKey(username) {
  if(typeof username!=='string'||!username)throw new Error('Sign in with your approved account first.');
  const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(username));
  return 'accountLogo:'+Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');
}
