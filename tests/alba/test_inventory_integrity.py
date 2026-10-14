from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import pytest
from fastapi import HTTPException
from sqlalchemy import text,select,func
from sqlalchemy.exc import IntegrityError
from tests.alba.test_threat_containment import system
from tests.alba.test_inventory_removal import inventory,remove
from alba_security.inventory import DeviceRegistration,DeviceEnrollment,ChromeItem,save_extensions
from alba_security.models import Device,Extension

@pytest.mark.parametrize('table,column,value',[('devices','inventory_revision',0),('extensions','inventory_revision',-1),('device_registrations','revision',0),('inventory_device_enrollments','status','invalid')])
def test_database_rejects_invalid_inventory_state(system,table,column,value):
    client,app,headers,_=system
    device,_,_=inventory(client,headers['hasan'])
    with app.state.session_factory() as db:
        if table=='inventory_device_enrollments' and not db.get(DeviceEnrollment,device['id']):
            db.add(DeviceEnrollment(device_id=device['id'],status='approved',requested_by='hasan',ip_source='Entered IP'));db.commit()
        with pytest.raises(IntegrityError):
            with db.begin_nested():db.execute(text(f'UPDATE {table} SET {column}=:value'),{'value':value})
        assert db.scalar(select(func.count(Device.id)))==1

def test_prefetched_device_cannot_sync_after_removal(system):
    client,app,headers,_=system;device,browser,rows=inventory(client,headers['hasan'])
    with app.state.session_factory() as db:
        row=db.get(DeviceRegistration,device['id']);db.get(Device,device['id']);db.commit()
        assert remove(client,headers['hasan'],'devices',device).status_code==200
        with pytest.raises(HTTPException) as error:save_extensions(db,row,[ChromeItem(id='c'*32,name='Late snapshot',version='1')],full_snapshot=True)
        assert error.value.status_code==403

def test_postgresql_concurrent_snapshots_do_not_duplicate_extensions(system):
    client,app,headers,_=system
    if app.state.engine.dialect.name!='postgresql':pytest.skip('Row-lock test requires isolated PostgreSQL')
    device,_,_=inventory(client,headers['hasan']);barrier=Barrier(2)
    def write_snapshot():
        with app.state.session_factory() as db:
            row=db.get(DeviceRegistration,device['id']);barrier.wait(timeout=10)
            save_extensions(db,row,[ChromeItem(id='c'*32,name='Concurrent inventory fixture',version='1')])
            db.commit()
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures=[pool.submit(write_snapshot) for _ in range(2)]
        for future in futures:future.result(timeout=20)
    with app.state.session_factory() as db:
        assert db.scalar(select(func.count(Extension.id)).where(Extension.extension_key=='c'*32))==1
