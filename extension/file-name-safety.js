// Filename signals are local warnings, not a malware verdict or backend score.
const DOCUMENTS = new Set(['pdf','doc','docx','xls','xlsx','ppt','pptx','txt','rtf','csv','jpg','jpeg','png','gif','webp','mp3','mp4','zip','rar','7z']);
const EXECUTABLES = new Set(['exe','scr','com','bat','cmd','ps1','vbs','vbe','js','jse','msi','msp','hta','lnk','jar','app','sh']);
export function inspectFilename(value) {
  const name = String(value ?? '').split(/[\\/]/).pop();
  const normalized = name.normalize('NFKC').trim().replace(/[. ]+$/,'').toLowerCase();
  const parts = normalized.split('.').map(part=>part.trim());
  const actual = parts.at(-1);
  const disguise = parts.slice(0,-1).reverse().find(part=>DOCUMENTS.has(part));
  if (/[\u202a-\u202e\u2066-\u2069]/.test(name)) return {name,actual,warning:true,
    message:'This filename contains direction-changing characters that can disguise its real extension. Do not open it until an administrator has reviewed it.'};
  if (parts.length >= 3 && EXECUTABLES.has(actual) && disguise) return {name,actual,warning:true,
    message:`This filename looks like a .${disguise} file, but its final extension is .${actual}, which can run code or launch another program. Do not open it until reviewed. A hash result does not cancel this filename warning.`};
  return {name,actual,warning:false};
}
