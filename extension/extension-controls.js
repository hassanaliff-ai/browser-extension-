// Execute only authenticated directives returned for this paired Chrome profile.
export async function applyExtensionControls(commands,{management,selfId,receipt,interactive=false}) {
  const results=[];
  for(const command of commands){
    if(!/^[a-p]{32}$/.test(command.chrome_id)||command.chrome_id===selfId||!Number.isInteger(command.revision)||!['enabled','disabled','blocked','removed'].includes(command.desired))continue;
    if(!interactive&&command.desired==='removed')continue;
    let status='applied',error=null;
    try {
      let item;
      try{item=await management.get(command.chrome_id);}catch{if(command.desired!=='removed')throw Object.assign(new Error(),{controlError:'not_installed'});}
      if(item?.type!=='extension'){
        if(item||command.desired!=='removed')throw Object.assign(new Error(),{controlError:'chrome_restricted'});
      }else if(command.desired==='removed'){
        if(item.mayDisable===false)throw Object.assign(new Error(),{controlError:'chrome_restricted'});
        await management.uninstall(command.chrome_id,{showConfirmDialog:true});
      }else {
        const enabled=command.desired==='enabled';
        if(item.enabled===enabled&&command.status==='applied')continue;
        if(item.enabled!==enabled){
          if((enabled&&item.mayEnable===false)||(!enabled&&item.mayDisable===false))throw Object.assign(new Error(),{controlError:'chrome_restricted'});
          await management.setEnabled(command.chrome_id,enabled);
          const updated=await management.get(command.chrome_id);
          if(updated.enabled!==enabled)throw new Error('Chrome did not apply the requested state');
        }
      }
    }catch(failure){status='failed';error=failure.controlError??(/gesture|permission|policy|not allowed/i.test(failure.message??'')?'chrome_restricted':/cancel|denied/i.test(failure.message??'')?'confirmation_cancelled':'browser_action_failed');}
    // A stale revision must never acknowledge a newer administrator decision.
    await receipt(command.extension_id,{revision:command.revision,status,error});
    results.push({extension_id:command.extension_id,status,error});
  }
  return results;
}
