// Offline evaluation of the shipped origin-only detector. No URLs are fetched.
import fs from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {pathToFileURL} from 'node:url';
import {checkInlineOrigins} from '../extension/inline-checks.js';

const warningLevels = new Set(['Medium','High','Critical']);
const ratio = (a,b) => b ? a/b : null;
export function summarize(rows) {
  const positive=rows.filter(r=>r.label==='phishing');
  const negative=rows.filter(r=>r.label==='benign-assumed');
  const tp=positive.filter(r=>r.warned).length, fp=negative.filter(r=>r.warned).length;
  return {total:rows.length,phishing:positive.length,benign_assumed:negative.length,
    true_positive:tp,false_negative:positive.length-tp,false_positive:fp,true_negative:negative.length-fp,
    unknown:rows.filter(r=>r.severity==='Unknown').length,
    detection_rate:ratio(tp,positive.length),false_warning_rate:ratio(fp,negative.length),
    precision:ratio(tp,tp+fp),unknown_rate:ratio(rows.filter(r=>r.severity==='Unknown').length,rows.length)};
}
export function validateRows(rows) {
  if(!Array.isArray(rows)||!rows.length||rows.length>50000)throw new Error('Expected 1–50000 cases.');
  const ids=new Set(),origins=new Set();
  return rows.map(row=>{
    if(typeof row.id!=='string'||!row.id||ids.has(row.id))throw new Error('Case IDs must be unique.');
    if(!['phishing','benign-assumed'].includes(row.label)||typeof row.source!=='string'||!row.source)
      throw new Error('Each case needs a supported label and source.');
    const url=new URL(row.url);
    if(!['http:','https:'].includes(url.protocol)||url.username||url.password)throw new Error('Expected a web URL without credentials.');
    if(origins.has(url.origin))throw new Error('Duplicate origin: evaluate each origin only once.');
    ids.add(row.id);origins.add(url.origin);
    return {...row,origin:url.origin};
  });
}
export function evaluate(rows,repetitions=21) {
  if(!Number.isInteger(repetitions)||repetitions<1||repetitions>1000)throw new Error('Invalid repetition count.');
  return validateRows(rows).map(row=>{
    checkInlineOrigins([row.origin]); // Warm-up is not included in timings.
    const elapsed=[];let result;
    for(let i=0;i<repetitions;i++){
      const start=performance.now();result=checkInlineOrigins([row.origin]).results[0];
      elapsed.push(performance.now()-start);
    }
    elapsed.sort((a,b)=>a-b);
    return {id:row.id,label:row.label,severity:result.severity,warned:warningLevels.has(result.severity),
      reasons:result.reasons,local_classification_median_ms:elapsed[Math.floor(elapsed.length/2)]};
  });
}
async function main(){
  const [input,output]=process.argv.slice(2);
  if(!input||!output)throw new Error('Usage: node scripts/evaluate_inline.mjs DATASET.json OUTPUT.json');
  const bytes=await fs.readFile(input),dataset=JSON.parse(bytes);
  const predictions=evaluate(dataset.cases);
  const componentHash=createHash('sha256');
  for(const name of ['inline-checks.js','inline-score.js'])componentHash.update(await fs.readFile(new URL('../extension/'+name,import.meta.url)));
  const report={created_at:new Date().toISOString(),component:'ExtSecure origin-only inline rules',
    detector_sha256:componentHash.digest('hex'),dataset_sha256:createHash('sha256').update(bytes).digest('hex'),
    node_version:process.version,warning_threshold:['Medium','High','Critical'],
    metadata:dataset.metadata,summary:summarize(predictions),predictions,
    limitations:['Preliminary convenience sample; labels are not independently verified.',
      'Phishing labels refer to reported URLs; only their origins are scored.',
      'Unknown is a non-warning in the confusion counts and is reported separately; it is not safe.',
      'Local classification timings exclude Chrome messaging, rendering, network, RDAP and reputation.',
      'This does not assess the complete backend-assisted system or establish acceptance targets.']};
  await fs.writeFile(output,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
  console.log(JSON.stringify(report.summary,null,2));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(e=>{console.error(e.message);process.exitCode=1;});
