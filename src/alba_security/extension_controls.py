"""Audited extension directives, executed only by the paired target Chrome profile."""
from typing import Literal
from fastapi import Depends,HTTPException,Request
from pydantic import BaseModel,ConfigDict,Field,model_validator
from sqlalchemy import CheckConstraint,ForeignKey,Integer,String,select,update
from sqlalchemy.orm import Mapped,Session,mapped_column
from sqlalchemy.exc import IntegrityError
from alba_security.models import Base,Extension,Device
from alba_security.governance import audit

class ExtensionControl(Base):
    __tablename__='inventory_extension_controls'
    __table_args__=(CheckConstraint("desired IN ('enabled','disabled','blocked','removed')",name='ck_extension_control_desired'),CheckConstraint("status IN ('pending','applied','failed')",name='ck_extension_control_status'),CheckConstraint('revision >= 1',name='ck_extension_control_revision'))
    extension_id:Mapped[str]=mapped_column(ForeignKey('extensions.id'),primary_key=True)
    desired:Mapped[str]=mapped_column(String(16),nullable=False)
    status:Mapped[str]=mapped_column(String(16),default='pending',nullable=False)
    revision:Mapped[int]=mapped_column(Integer,default=1,nullable=False)
    error:Mapped[str|None]=mapped_column(String(300))

class Decision(BaseModel):
    model_config=ConfigDict(extra='forbid',str_strip_whitespace=True)
    desired:Literal['enabled','disabled','blocked','removed']
    expected_revision:int=Field(strict=True,ge=0)
    reason:str=Field(min_length=8,max_length=1000)
    confirmed:bool=Field(strict=True)

class Receipt(BaseModel):
    model_config=ConfigDict(extra='forbid')
    revision:int=Field(strict=True,ge=1)
    status:Literal['applied','failed']
    error:Literal['chrome_restricted','confirmation_cancelled','not_installed','permission_required','browser_action_failed']|None=None
    @model_validator(mode='after')
    def valid_outcome(self):
        if (self.status=='applied' and self.error is not None) or (self.status=='failed' and self.error is None):
            raise ValueError('Applied receipts cannot have an error; failed receipts require a reason')
        return self

def control_data(row):
    return {'desired':row.desired,'status':row.status,'revision':row.revision,'error':row.error} if row else {'desired':None,'status':None,'revision':0,'error':None}

def can_control_device(db,directory,actor,device_id,context=None):
    from alba_security.inventory import DeviceRegistration,DeviceEnrollment
    from alba_security.permissions import ROLE_LEVELS
    role=directory.role(db,actor)
    if role=='head_administrator':return True
    if role not in {'administrator','manager'}:return False
    registration=context['registrations'].get(device_id) if context is not None else db.get(DeviceRegistration,device_id)
    enrollment=context['enrollments'].get(device_id) if context is not None else db.get(DeviceEnrollment,device_id)
    owner=enrollment.requested_by if enrollment else registration.added_by if registration else None
    if actor==owner:return True
    owner_role=directory.role(db,owner)
    return owner_role in ROLE_LEVELS and ROLE_LEVELS[role]>ROLE_LEVELS[owner_role]

def install_extension_controls(app,session_scope,require_actor):
    from alba_security.inventory import ChromeObservation,DeviceRegistration,browser_registration,is_pending
    def own(db,request):
        row=browser_registration(db,request)
        if not row or row.blocked or is_pending(db,row):raise HTTPException(403,'Link an approved active device before applying extension controls.')
        return row

    @app.post('/api/inventory/extensions/{extension_id}/control')
    def decide(extension_id:str,payload:Decision,actor:str=Depends(require_actor),db:Session=Depends(session_scope)):
        item=db.get(Extension,extension_id);observation=db.get(ChromeObservation,extension_id)
        if not item or not observation:raise HTTPException(404,'Sync Chrome inventory before managing this extension.')
        if not can_control_device(db,app.state.admin_directory,actor,item.device_id):raise HTTPException(403,'A higher approver is required to manage this device.')
        if app.state.admin_directory.role(db,actor)=='manager' and payload.desired=='removed':raise HTTPException(403,'Managers may turn on, turn off or block; uninstall requires an administrator.')
        if item.inventory_removed or db.get(Device,item.device_id).inventory_removed:raise HTTPException(409,'This inventory record was removed. Restore active inventory first.')
        registration=db.get(DeviceRegistration,item.device_id)
        if not registration or item.extension_key==registration.chrome_extension_id:raise HTTPException(409,'ExtSecure protects this connection and cannot be disabled, blocked or removed here.')
        if not observation.present:raise HTTPException(409,'This extension is no longer installed. Refresh inventory.')
        if payload.desired=='enabled' and not observation.may_enable:raise HTTPException(409,'Chrome does not allow this extension to be enabled.')
        if payload.desired!='enabled' and not observation.may_disable:raise HTTPException(409,'Chrome or organization policy protects this extension.')
        if not payload.confirmed:raise HTTPException(422,'Confirm the extension and device before applying this action.')
        row=db.get(ExtensionControl,extension_id)
        if row:
            result=db.execute(update(ExtensionControl).where(ExtensionControl.extension_id==extension_id,ExtensionControl.revision==payload.expected_revision).values(desired=payload.desired,status='pending',revision=ExtensionControl.revision+1,error=None))
            if result.rowcount!=1:raise HTTPException(409,'Extension controls changed. Refresh before trying again.')
            db.expire(row)
        else:
            if payload.expected_revision!=0:raise HTTPException(409,'Refresh extension controls.')
            row=ExtensionControl(extension_id=extension_id,desired=payload.desired);db.add(row)
            try:db.flush()
            except IntegrityError:
                db.rollback();raise HTTPException(409,'Extension controls changed. Refresh before trying again.') from None
        audit(db,'extension',extension_id,actor,'extension_control_requested',device_id=item.device_id,desired=payload.desired,revision=row.revision,reason=payload.reason)
        db.commit();app.state.extension_control_wakeups.changed(item.device_id)
        return {'extension_id':extension_id,'device_id':item.device_id,**control_data(row)}

    @app.get('/api/inventory/extension-controls')
    def commands(request:Request,actor:str=Depends(require_actor),db:Session=Depends(session_scope)):
        device=own(db,request)
        rows=db.execute(select(ExtensionControl,Extension).join(Extension,Extension.id==ExtensionControl.extension_id).where(Extension.device_id==device.device_id))
        return [{'extension_id':item.id,'chrome_id':item.extension_key,'device_id':device.device_id,**control_data(row)} for row,item in rows if item.extension_key!=device.chrome_extension_id and (row.status!='applied' or row.desired=='blocked')]

    @app.post('/api/inventory/extensions/{extension_id}/receipt')
    def receipt(extension_id:str,payload:Receipt,request:Request,actor:str=Depends(require_actor),db:Session=Depends(session_scope)):
        device=own(db,request);item=db.get(Extension,extension_id);row=db.get(ExtensionControl,extension_id)
        if not item or item.device_id!=device.device_id or not row:raise HTTPException(404,'Extension control not found for this Chrome profile.')
        if row.revision!=payload.revision:raise HTTPException(409,'A newer extension action is pending. Refresh controls.')
        if row.status==payload.status and row.error==payload.error:return control_data(row)
        updated=db.execute(update(ExtensionControl).where(ExtensionControl.extension_id==extension_id,ExtensionControl.revision==payload.revision).values(status=payload.status,error=payload.error))
        if updated.rowcount!=1:raise HTTPException(409,'A newer extension action is pending.')
        audit(db,'extension',extension_id,actor,'extension_control_'+payload.status,device_id=device.device_id,desired=row.desired,revision=payload.revision,error=payload.error)
        db.commit();db.refresh(row);return control_data(row)
