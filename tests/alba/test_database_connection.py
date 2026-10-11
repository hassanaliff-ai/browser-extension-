from sqlalchemy import event,select,func
from sqlalchemy.exc import IntegrityError
from alba_security.models import Base,PersonalScan,Scan,Finding,Alert,SecurityEvent
from tests.alba.test_roles import roles
from test_threat_containment import system

def test_database_identity_is_admin_only_and_never_contains_secrets(roles):
    client,_,headers,_=roles
    assert client.get('/api/database/status').status_code==401
    for role in ('manager','normal_user'):
        assert client.get('/api/database/status',headers=headers[role]).status_code==403
    response=client.get('/api/database/status',headers=headers['administrator'])
    assert response.status_code==200
    assert response.headers['cache-control']=='no-store'
    assert 'password' not in response.json().get('connection',{})

def test_verified_database_route_uses_the_runtime_connection(system):
    client,app,headers,_=system
    response=client.get('/api/database/status',headers=headers['hasan'])
    assert response.status_code==200
    if app.state.engine.dialect.name=='postgresql':
        result=response.json()
        assert result['healthy']
        assert result['connection']['database']==app.state.engine.url.database
        assert result['table_count']>=len(Base.metadata.tables) and result['view_count']==8
        assert not any(k in result['connection'] for k in ('password','url','dsn'))
    else:
        assert response.json()['healthy'] is False

def test_ownership_failure_rolls_back_every_scan_record(system):
    client,app,headers,_=system
    def reject(*args):
        raise IntegrityError('synthetic ownership failure',{},Exception('test'))
    with app.state.session_factory() as db:
        def counts():
            return [db.scalar(select(func.count()).select_from(model)) for model in (Scan,Finding,Alert,SecurityEvent,PersonalScan)]
        before=counts()
        event.listen(PersonalScan,'before_insert',reject)
        try:
            from alba_security.api import ScanCreate
            result=None
            try:
                result=app.state.record_scan(ScanCreate(device_id='atomic-test',device_name='Atomic evidence test',target_kind='url',target='https://example.com',signals=[{'code':'malicious_url','status':'detected'}]),db,notify=False,actor='hasan')
            except Exception as error:
                assert getattr(error,'status_code',None)==503
            assert result is None
            assert counts()==before
        finally:
            event.remove(PersonalScan,'before_insert',reject)
