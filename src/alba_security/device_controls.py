"""Device-scoped administrative control delivery without an end-user approval step."""
import asyncio,time
from collections import OrderedDict
from threading import Lock
from fastapi import Depends,HTTPException,Request,Query
from sqlalchemy import select,update
from alba_security.models import Extension,Device,utc_now
from alba_security.extension_controls import ExtensionControl,Receipt,control_data
from alba_security.governance import audit

class ControlWakeups:
    def __init__(self):self.values=OrderedDict();self.lock=Lock()
    def cursor(self,device):
        with self.lock:return self.values.get(device,0)
    def changed(self,device):
        with self.lock:
            self.values[device]=self.values.get(device,0)+1;self.values.move_to_end(device)
            while len(self.values)>4096:self.values.popitem(last=False)

def install_device_controls(app,session_scope):
    from alba_security.inventory import browser_registration,is_pending,DeviceEnrollment,ChromeObservation,ChromeSnapshot,lock_inventory_device,save_browser_inventory
    wakeups=ControlWakeups();app.state.extension_control_wakeups=wakeups
    @app.post('/api/device/heartbeat')
    def heartbeat(request:Request,db=Depends(session_scope)):
        from alba_security.inventory import lock_inventory_device
        row=browser_registration(db,request)
        if not row:raise HTTPException(403,'Device connection required.')
        # Presence never grants account, scan or management permissions.
        device=lock_inventory_device(db,row.device_id)
        if not browser_registration(db,request):raise HTTPException(403,'Device connection required.')
        row.last_heartbeat=utc_now();device.last_seen=row.last_heartbeat
        db.commit()
        return {'status':'Active','last_heartbeat':row.last_heartbeat.isoformat(),'heartbeat_timeout_seconds':90}
    def own(db,request):
        row=browser_registration(db,request)
        if not row or is_pending(db,row):raise HTTPException(403,'Approved device connection required.')
        device=db.get(Device,row.device_id)
        enrollment=db.get(DeviceEnrollment,row.device_id)
        if not device or device.inventory_removed or (enrollment and enrollment.status!='approved'):
            raise HTTPException(403,'Approved device connection required.')
        return row

    @app.post('/api/device/inventory')
    def inventory(payload:ChromeSnapshot,request:Request,db=Depends(session_scope)):
        row=own(db,request)
        lock_inventory_device(db,row.device_id)
        db.refresh(row)
        row=own(db,request)
        if row.blocked:raise HTTPException(403,'This device is blocked.')
        # The credential selects the only writable device; no caller-supplied
        # device/account identity can redirect a snapshot to another computer.
        return save_browser_inventory(db,row,payload,'device:'+row.device_id)
    def commands(db,row):
        items=db.execute(select(ExtensionControl,Extension).join(Extension,Extension.id==ExtensionControl.extension_id).where(Extension.device_id==row.device_id,Extension.inventory_removed.is_(False)))
        return [{'extension_id':item.id,'chrome_id':item.extension_key,'device_id':row.device_id,**control_data(control)} for control,item in items if item.extension_key!=row.chrome_extension_id and (control.status=='pending' or control.desired=='blocked')]
    @app.get('/api/device/extension-controls')
    async def wait(request:Request,cursor:int=Query(default=-1,ge=-1),db=Depends(session_scope)):
        row=own(db,request);device_id=row.device_id
        # A verified control poll also proves presence for existing installations.
        row.last_heartbeat=utc_now();db.get(Device,device_id).last_seen=row.last_heartbeat
        current=wakeups.cursor(device_id)
        # Release the connection before waiting; no idle transaction or per-tick SQL.
        db.commit()
        deadline=time.monotonic()+20
        while cursor==current and time.monotonic()<deadline:
            if await request.is_disconnected():return {'cursor':current,'commands':[]}
            await asyncio.sleep(.2);current=wakeups.cursor(device_id)
        row=own(db,request)
        return {'cursor':current,'commands':commands(db,row)}
    @app.post('/api/device/extensions/{extension_id}/receipt')
    def receipt(extension_id:str,payload:Receipt,request:Request,db=Depends(session_scope)):
        device=own(db,request);item=db.get(Extension,extension_id);row=db.get(ExtensionControl,extension_id)
        if not item or item.device_id!=device.device_id or item.inventory_removed or not row:raise HTTPException(404,'Extension control not found for this device.')
        if row.revision!=payload.revision:raise HTTPException(409,'A newer extension action is pending.')
        if row.status==payload.status and row.error==payload.error:return control_data(row)
        result=db.execute(update(ExtensionControl).where(ExtensionControl.extension_id==extension_id,ExtensionControl.revision==payload.revision).values(status=payload.status,error=payload.error))
        if result.rowcount!=1:raise HTTPException(409,'A newer extension action is pending.')
        if payload.status=='applied':
            observation=db.get(ChromeObservation,extension_id)
            if observation:
                observation.enabled=row.desired=='enabled'
                observation.present=row.desired!='removed'
                observation.last_sync=utc_now()
            item.last_seen=utc_now()
            db.get(Device,device.device_id).last_seen=utc_now()
        audit(db,'extension',extension_id,'device:'+device.device_id,'extension_control_'+payload.status,device_id=device.device_id,desired=row.desired,revision=payload.revision,error=payload.error)
        db.commit();db.refresh(row);return control_data(row)
