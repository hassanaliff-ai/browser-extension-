import test from 'node:test';
import assert from 'node:assert/strict';
import {inspectFilename} from '../file-name-safety.js';
import {qrDestination,decodeQrImage} from '../qr-safety.js';

test('Disguised executable filenames warn and identify the real final extension',()=>{
  for(const name of ['invoice.pdf.exe','PHOTO.JPG.SCR','report.docx .cmd','archive.zip.js','invoice.pdf.backup.exe','invoice.pdf.exe. ','C:\\downloads\\statement.pdf.exe']){
    const result=inspectFilename(name);assert(result.warning,name);assert.match(result.message,/final extension/);
  }
});
test('Ordinary multi-dot names and plain executable names are not mislabelled as double extensions',()=>{
  for(const name of ['report.final.pdf','archive.tar.gz','photo.jpg','setup.exe','document.pdf.txt',''])assert.equal(inspectFilename(name).warning,false,name);
});
test('Unicode direction controls and compatibility dots cannot hide suspicious filenames',()=>{
  assert(inspectFilename('invoice\u202efdp.exe').warning);
  assert(inspectFilename('invoice.pdf\uff0eexe').warning);
});
test('QR destinations strip private query and fragment while keeping an explicit reviewable path',()=>{
  assert.deepEqual(qrDestination('https://example.com/invoice?secret=123#token'),{target:'https://example.com/invoice',host:'example.com',removedPrivateParts:true});
  assert.equal(qrDestination('http://example.com').target,'http://example.com/');
});
test('Executable QR payloads, credentials, whitespace tricks and non-URLs are rejected',()=>{
  for(const value of ['javascript:alert(1)','data:text/html,test','file:///tmp/a','https://user:pass@example.com','example.com','hello','https://exam\nple.com','https://','', 'https://example.com/'+'a'.repeat(8192)])assert.throws(()=>qrDestination(value),undefined,value.slice(0,80));
});
test('QR image validation refuses empty, oversized and unsupported uploads before decoding',async()=>{
  for(const file of [null,{type:'image/svg+xml',size:100},{type:'image/png',size:0},{type:'image/png',size:9*1024*1024}])await assert.rejects(()=>decodeQrImage(file));
});
