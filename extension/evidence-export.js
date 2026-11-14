// Explicit export fields: credentials, raw URLs, file bytes and arbitrary API fields stay out.
export function scanEvidenceExport(scan){
 const fields=['id','target_kind','target_display','score','severity','completeness','risk_policy_version','created_at','unknown_codes'];
 const result=Object.fromEntries(fields.filter(key=>scan[key]!==undefined).map(key=>[key,scan[key]]));
 result.findings=(scan.findings??[]).map(row=>Object.fromEntries(['code','signal_code','title','points','severity'].filter(key=>row[key]!==undefined).map(key=>[key,row[key]])));
 const provider=scan.provider_evidence;
 if(provider?.provider==='VirusTotal')result.provider_evidence={provider:'VirusTotal',
  status:['available','unavailable'].includes(provider.status)?provider.status:'unavailable',
  counts:Object.fromEntries(['malicious','suspicious','harmless','undetected'].map(key=>[key,Number.isSafeInteger(provider.counts?.[key])&&provider.counts[key]>=0?provider.counts[key]:null])),
  cached:provider.cached===true,analysis_at:typeof provider.analysis_at==='string'&&/^\d{4}-\d{2}-\d{2}T[0-9:.+Z-]+$/.test(provider.analysis_at)?provider.analysis_at:null,
  engine_total:Number.isSafeInteger(provider.engine_total)&&provider.engine_total>=0?provider.engine_total:null,
  report_id:/^[a-f0-9]{64}$/.test(provider.report_id??'')?provider.report_id:null,
  mapping:provider.mapping==='extsecure-provider-evidence-v1'?provider.mapping:null};
 if(scan.containment)result.containment=Object.fromEntries(['id','kind','active','severity','scan_id','case_id','revision'].filter(key=>scan.containment[key]!==undefined).map(key=>[key,scan.containment[key]]));
 return {format:'extsecure.scan-evidence.v1',...result};
}
