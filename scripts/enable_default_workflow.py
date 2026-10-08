"""Apply the user's requested local workflow configuration; never publish private state."""
from pathlib import Path
import os,sys,json,sqlite3
from dotenv import dotenv_values
from sqlalchemy.engine import make_url
from sqlalchemy import create_engine,select
from sqlalchemy.orm import Session
root=Path(__file__).resolve().parents[1]
import argparse
parser=argparse.ArgumentParser(description='Enable the first High/Critical workflow for the configured head administrator. Existing rules are preserved.')
parser.add_argument('--confirm',action='store_true',help='Confirm local workflow configuration with 24-hour escalation')
if not parser.parse_args().confirm:parser.error('Pass --confirm to enable the workflow. This changes security workflow configuration.')
values=dotenv_values(root/'.env')
os.environ.update({k:v for k,v in values.items() if v is not None})
sys.path.insert(0,str(root/'src'))
from alba_security.admin_auth import AdminAuth
from alba_security.admin_directory import AdminDirectory
from alba_security.governance import audit
from alba_security.operations import WorkflowRule,RuleInput
directory=AdminDirectory.configured(AdminAuth.from_environment())
url=make_url(values['DATABASE_URL']);assert url.drivername.startswith('sqlite')
database=Path(url.database);database=(database if database.is_absolute() else root/database).resolve()
assert database.is_relative_to(root)
backup=(root/'.private/updates/workflow-activation-20261008').resolve();assert backup.is_relative_to(root)
backup.mkdir(parents=True,exist_ok=True)
snapshot=backup/'before-activation.sqlite'
if not snapshot.exists():
 with sqlite3.connect(database.as_uri()+'?mode=ro',uri=True) as source,sqlite3.connect(snapshot) as destination:source.backup(destination)
engine=create_engine(url.set(database=str(database)))
with Session(engine) as db:
 # Take the SQLite write lock before checking so an existing rule is never replaced.
 db.connection().exec_driver_sql('BEGIN IMMEDIATE')
 if db.scalar(select(WorkflowRule.id)):
  print('Existing workflow rule preserved; no configuration changed.')
 else:
  head=directory.primary.username
  assert directory.role(db,head)=='head_administrator' and head in directory.operators(db)
  payload=RuleInput(name='High and critical threat review',enabled=True,priority=50,
   minimum_severity='High',target_kind='any',auto_create=True,assignee=head,
   notify_reviewer=True,reviewer=head,escalate_after_hours=24,escalate_to=head,
   reason='Initialize workflow automation requested by the project owner: head administrator handles high and critical threats with a 24-hour escalation deadline.')
  settings=payload.model_dump(exclude={'reason','name','enabled','priority'})
  row=WorkflowRule(name=payload.name,enabled=True,priority=payload.priority,settings=settings,author='system')
  db.add(row);db.flush()
  audit(db,'workflow',row.id,'system','rule_created',reason=payload.reason,enabled=True,name=row.name,
   priority=row.priority,settings=settings,revision=1,source='local_owner_requested_setup')
  db.commit()
  print(json.dumps({'configured':True,'minimum_severity':'High','file_and_website_scans':True,
   'assignee':head,'reviewer':head,'escalation_recipient':head,'escalate_after_hours':24,'existing_scans_unchanged':True}))
engine.dispose()
