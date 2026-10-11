"""Remove active inventory entries without deleting retained security evidence."""
from fastapi import Depends,HTTPException
from pydantic import BaseModel,ConfigDict,Field
from sqlalchemy import select,update
from sqlalchemy.orm import Session
from alba_security.models import Device,Extension
from alba_security.governance import audit

class Removal(BaseModel):
    model_config=ConfigDict(extra='forbid',str_strip_whitespace=True)
    expected_revision:int=Field(strict=True,ge=1)
    confirmed:bool=Field(strict=True)
    reason:str=Field(min_length=8,max_length=1000)

def install_inventory_removal(app,session_scope,require_actor):
    from alba_security.inventory import DeviceRegistration,BrowserCredential
    def change(db,model,key,payload,removed):
        row=db.get(model,key)
        if not row:raise HTTPException(404,'Inventory record not found.')
        if not payload.confirmed:raise HTTPException(422,'Confirm the selected inventory record before removing or restoring it.')
        result=db.execute(update(model).where(model.id==key,model.inventory_revision==payload.expected_revision,model.inventory_removed.is_(not removed)).values(inventory_removed=removed,inventory_revision=model.inventory_revision+1))
        if result.rowcount!=1:raise HTTPException(409,'Inventory changed. Refresh before trying again.')
        return row

    @app.post('/api/inventory/extensions/{extension_id}/remove')
    def remove_extension(extension_id:str,payload:Removal,actor:str=Depends(require_actor),db:Session=Depends(session_scope)):
        row=change(db,Extension,extension_id,payload,True)
        audit(db,'extension',extension_id,actor,'extension_removed_from_inventory',device_id=row.device_id,reason=payload.reason)
        db.commit();return {'id':extension_id,'removed':True,'history_preserved':True,'uninstalled':False}

    @app.post('/api/inventory/extensions/{extension_id}/restore')
    def restore_extension(extension_id:str,payload:Removal,actor:str=Depends(require_actor),db:Session=Depends(session_scope)):
        row=db.get(Extension,extension_id)
        device=db.scalar(select(Device).where(Device.id==row.device_id).with_for_update()) if row else None
        if device and device.inventory_removed:raise HTTPException(409,'The device was removed. Reconnect it before managing active inventory.')
        row=change(db,Extension,extension_id,payload,False)
        audit(db,'extension',extension_id,actor,'extension_restored_to_inventory',device_id=row.device_id,reason=payload.reason)
        db.commit();return {'id':extension_id,'removed':False}

    @app.post('/api/inventory/devices/{device_id}/remove')
    def remove_device(device_id:str,payload:Removal,actor:str=Depends(require_actor),db:Session=Depends(session_scope)):
        change(db,Device,device_id,payload,True)
        db.execute(update(BrowserCredential).where(BrowserCredential.device_id==device_id).values(revoked=True))
        db.execute(update(DeviceRegistration).where(DeviceRegistration.device_id==device_id).values(blocked=True,revision=DeviceRegistration.revision+1,pairing_hash=None,pairing_expires=None))
        result=db.execute(update(Extension).where(Extension.device_id==device_id,Extension.inventory_removed.is_(False)).values(inventory_removed=True,inventory_revision=Extension.inventory_revision+1))
        audit(db,'device',device_id,actor,'device_removed_from_inventory',reason=payload.reason,extensions_removed=result.rowcount,credentials_revoked=True)
        db.commit();return {'id':device_id,'removed':True,'extensions_removed':result.rowcount,'credentials_revoked':True,'history_preserved':True}
