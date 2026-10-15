import {applyExtensionControls} from './extension-controls.js';

export async function deviceControlRequest(origin,token,path,method='GET',body,fetcher=fetch){
 if(!token||!(/^\/api\/device\/extension-controls\?cursor=(-1|\d+)$/.test(path)&&method==='GET'||/^\/api\/device\/extensions\/[0-9a-f-]{36}\/receipt$/.test(path)&&method==='POST'||path==='/api/device/heartbeat'&&method==='POST'))throw new Error('Unsupported device control request.');
 const response=await fetcher(origin+'/monitor'+path,{method,headers:{Accept:'application/json','X-ExtSecure-Device':token,...(body?{'Content-Type':'application/json'}:{})},body:body?JSON.stringify(body):undefined,credentials:'omit',cache:'no-store',redirect:'error',signal:AbortSignal.timeout(path==='/api/device/heartbeat'?5000:25000)});
 const data=await response.json();if(!response.ok)throw Object.assign(new Error('Device control delivery is unavailable.'),{status:response.status});return data;
}

export async function executeDeviceCommands(batch,{origin,token,management,selfId,fetcher=fetch}){
 if(!Number.isInteger(batch.cursor)||!Array.isArray(batch.commands))throw new Error('Invalid device control response.');
 return applyExtensionControls(batch.commands,{management,selfId,interactive:false,receipt:(id,body)=>deviceControlRequest(origin,token,'/api/device/extensions/'+id+'/receipt','POST',body,fetcher)});
}
