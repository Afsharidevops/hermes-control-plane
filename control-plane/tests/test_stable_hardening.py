from __future__ import annotations
import os, sqlite3, subprocess, sys
from pathlib import Path
from fastapi.testclient import TestClient

os.environ["HERMES_CONTROL_ADMIN_TOKEN"]="test-admin"
os.environ["HERMES_EXECUTION_HMAC_KEY"]="ticket-key"
os.environ["HERMES_KUBERNETES_BROKER_TOKEN"]="broker-key"
os.environ["HERMES_BOT_SERVICE_TOKEN"]="test-bot"
os.environ["HERMES_APPROVAL_BOT_TOKEN"]="test-approval"
from hermes_control_plane import db
from hermes_control_plane import main as cp
AUTH={"Authorization":"Bearer test-admin"}

def test_raw_secret_metadata_rejected_and_rotation_audited(tmp_path: Path):
    db.DB_PATH=tmp_path/'db.sqlite3'
    with TestClient(cp.app) as c:
        bad=c.post('/v1/credential-refs',headers=AUTH,json={'name':'bad','kind':'token','metadata':{'token':'super-secret'}})
        assert bad.status_code==422
        good=c.post('/v1/credential-refs',headers=AUTH,json={'name':'k','kind':'kubeconfig','metadata':{'storage':'external','sha256':'a'*64,'path_ref':'vault://kube/prod'}})
        assert good.status_code==201
        cid=good.json()['id']
        rot=c.post(f'/v1/credential-refs/{cid}/rotate',headers=AUTH,json={'metadata':{'storage':'external','sha256':'b'*64,'path_ref':'vault://kube/prod-v2'}})
        assert rot.status_code==200
        assert rot.json()['metadata']['sha256']=='b'*64
        assert any(e['event_type']=='credential_ref.rotated' for e in c.get('/v1/audit').json())

def test_audit_export_has_digest(tmp_path: Path):
    db.DB_PATH=tmp_path/'db.sqlite3'
    with TestClient(cp.app) as c:
        c.post('/v1/environments',headers=AUTH,json={'name':'Prod'})
        exported=c.get('/v1/audit/export',headers=AUTH)
        assert exported.status_code==200
        assert exported.headers['x-hermes-audit-sha256']
        assert 'environment.created' in exported.text

def test_backup_restore_round_trip(tmp_path: Path):
    source=tmp_path/'source.sqlite3'; backup=tmp_path/'backup.sqlite3'; restored=tmp_path/'restored.sqlite3'
    with sqlite3.connect(source) as conn:
        conn.execute('create table demo(value text)'); conn.execute("insert into demo values ('before')"); conn.commit()
    tool=Path(__file__).resolve().parents[2]/'scripts'/'control-db.py'
    subprocess.run([sys.executable,str(tool),'backup',str(source),str(backup)],check=True,capture_output=True,text=True)
    with sqlite3.connect(restored) as conn:
        conn.execute('create table demo(value text)'); conn.execute("insert into demo values ('wrong')"); conn.commit()
    subprocess.run([sys.executable,str(tool),'restore',str(backup),str(restored)],check=True,capture_output=True,text=True)
    with sqlite3.connect(restored) as conn:
        assert conn.execute('select value from demo').fetchone()[0]=='before'
