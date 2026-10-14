from sqlalchemy import select,event
from tests.alba.test_threat_containment import system
from tests.alba.test_inventory_removal import inventory
from alba_security.inventory import inventory_context,device_metadata,extension_metadata,DeviceRegistration,BrowserCredential,DeviceEnrollment
from alba_security.models import Device,Extension

def test_batched_inventory_matches_existing_records(system):
    client,app,headers,_=system;device,_,_=inventory(client,headers['hasan'])
    with app.state.session_factory() as db:
        devices=list(db.scalars(select(Device)));extensions=list(db.scalars(select(Extension)))
        expected_devices={d.id:device_metadata(db,d.id) for d in devices}
        expected_extensions={e.id:extension_metadata(db,e.id) for e in extensions}
        context=inventory_context(db,devices,extensions)
        assert {d.id:device_metadata(db,d.id,context) for d in devices}==expected_devices
        assert {e.id:extension_metadata(db,e.id,context) for e in extensions}==expected_extensions

def test_inventory_query_count_does_not_grow_per_device(system):
    _,app,_,_=system
    with app.state.session_factory() as db:
        for i in range(40):
            device=Device(id='batch-test-'+str(i),name='Batch fixture '+str(i));db.add(device);db.flush()
            db.add(DeviceRegistration(device_id=device.id,ip_address='Not available',operating_system='Windows',blocked=i%3==0,added_by='hasan'))
            db.add(DeviceEnrollment(device_id=device.id,status='pending' if i%3==0 else 'approved',requested_by='hasan',ip_source='Entered IP'))
            db.add(BrowserCredential(token_hash=str(i).zfill(64),device_id=device.id,revoked=i%2==0))
        db.commit();devices=list(db.scalars(select(Device)))
        statements=[]
        def count(*args):statements.append(args[2])
        event.listen(app.state.engine,'before_cursor_execute',count)
        try:
            context=inventory_context(db,devices)
            rows=[device_metadata(db,d.id,context) for d in devices]
        finally:event.remove(app.state.engine,'before_cursor_execute',count)
        assert len(statements)==3
        assert len(rows)==40
        by_id={d.id:row for d,row in zip(devices,rows)}
        assert by_id['batch-test-0']['pending'] and not by_id['batch-test-0']['linked']
        assert by_id['batch-test-1']['trusted']
