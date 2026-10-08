// Collect only the metadata needed for the enabled-extension inventory.
export function enabledExtensions(items) {
  const result=items.filter(item=>item.type==='extension'&&item.enabled===true).map(item=>({
    id:item.id,name:String(item.name).trim().slice(0,160),version:String(item.version).slice(0,40)
  }));
  if(result.length>500||result.some(item=>!/^[a-p]{32}$/.test(item.id)||!item.name||!item.version))
    throw new Error('Chrome returned an unsupported extension inventory.');
  return result;
}
export function platformName(os) {
  return {win:'Windows',mac:'macOS',linux:'Linux',cros:'ChromeOS',android:'Android',openbsd:'OpenBSD'}[os]??'Other';
}
