// Explicit export fields: credentials, raw URLs, file bytes and arbitrary API fields stay out.
export function scanEvidenceExport(scan){
 const fields=['id','target_kind','target_display','score','severity','completeness','risk_policy_version','created_at','unknown_codes'];
 const result=Object.fromEntries(fields.filter(key=>scan[key]!==undefined).map(key=>[key,scan[key]]));
 result.findings=(scan.findings??[]).map(row=>Object.fromEntries(['code','signal_code','title','points','severity'].filter(key=>row[key]!==undefined).map(key=>[key,row[key]])));
 if(scan.containment)result.containment=Object.fromEntries(['id','kind','active','severity','scan_id','case_id','revision'].filter(key=>scan.containment[key]!==undefined).map(key=>[key,scan.containment[key]]));
 return {format:'extsecure.scan-evidence.v1',...result};
}
