import {privateTarget} from './core.js';
export function qrDestination(value) {
  if (typeof value !== 'string' || !value.trim() || value.length > 8192) throw new Error('The QR code does not contain a supported web address.');
  const raw = value.trim();
  // Explicit schemes only: never execute QR payloads or guess URLs from text.
  if (!/^https?:\/\//i.test(raw) || /[\u0000-\u0020\u007f]/.test(raw)) throw new Error('Only HTTP or HTTPS QR destinations can be checked.');
  const target = privateTarget(raw,true);
  return {target,host:new URL(target).hostname,removedPrivateParts:new URL(raw).search!==''||new URL(raw).hash!==''};
}
export async function decodeQrImage(file) {
  if (!file || !['image/png','image/jpeg','image/webp'].includes(file.type)) throw new Error('Choose a PNG, JPEG or WebP QR image.');
  if (!file.size || file.size > 8*1024*1024) throw new Error('Choose a QR image of 8 MiB or less.');
  let bitmap;
  try {
    bitmap = await createImageBitmap(file);
    if (!bitmap.width || !bitmap.height || bitmap.width*bitmap.height > 16000000 || Math.max(bitmap.width,bitmap.height)>8192) throw new Error('The QR image is too large. Crop it around the QR code and try again.');
    const scale=Math.min(1,2048/Math.max(bitmap.width,bitmap.height));
    const canvas=new OffscreenCanvas(Math.max(1,Math.round(bitmap.width*scale)),Math.max(1,Math.round(bitmap.height*scale)));
    const context=canvas.getContext('2d',{willReadFrequently:true});
    context.fillStyle='#fff';context.fillRect(0,0,canvas.width,canvas.height);
    context.drawImage(bitmap,0,0,canvas.width,canvas.height);
    // Bundled decoder: no CDN, camera permission or image upload.
    await import('./vendor/jsQR.js');
    const pixels=context.getImageData(0,0,canvas.width,canvas.height);
    const code=globalThis.jsQR(pixels.data,pixels.width,pixels.height,{inversionAttempts:'attemptBoth'});
    pixels.data.fill(0);
    if (!code) throw new Error('No readable QR code found. Use a clear image with one QR code and a visible border.');
    return qrDestination(code.data);
  } catch(error) {
    if (error.name==='InvalidStateError') throw new Error('This image could not be read. Choose a valid QR image.');
    throw error;
  } finally {bitmap?.close();}
}
