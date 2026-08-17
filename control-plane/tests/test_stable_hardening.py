from __future__ import annotations
import os, sqlite3, subprocess, sys
from pathlib import Path
from fastapi.testclient import TestClient

os.environ["HERMES_CONTROL_ADMIN_TOKEN"]="test-admin"
os.environ["HERMES_EXECUTION_HMAC_KEY"]="ticket-key"
os.environ["HERMES_KUBERNETES_BROKER_TOKEN"]="broker-key"
os.environ["HERMES_BOT_SERVICE_TOKEN"]="test-bot"
os.environ["HERMES_APPROVAL_BOT_TOKEN"]="test-approval"
os.environ["HERMES_APPROVAL_HMAC_KEY"] = "approval-hmac-key-0123456789abcdef0123456789abcdef"
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
        patched_secret=c.patch(f'/v1/credential-refs/{cid}',headers=AUTH,json={'metadata':{'password':'still-secret'}})
        assert patched_secret.status_code==422
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

def test_agent_enrollment_nonce_replay_and_revocation(tmp_path: Path):
    db.DB_PATH=tmp_path/'db.sqlite3'
    with TestClient(cp.app) as c:
        issued=c.post('/v1/agents/enrollment-tokens',headers=AUTH,json={'name':'edge-1','ttl_seconds':300})
        assert issued.status_code==201, issued.text
        token=issued.json()['enrollment_token']
        enrolled=c.post('/v1/agents/enroll',json={'enrollment_token':token,'capabilities':['docker.read']})
        assert enrolled.status_code==201, enrolled.text
        agent=enrolled.json()
        # Enrollment credentials are strictly one-use.
        reused=c.post('/v1/agents/enroll',json={'enrollment_token':token,'capabilities':[]})
        assert reused.status_code==401
        agent_auth={'Authorization':f"Bearer {agent['agent_token']}"}
        nonce='nonce-0123456789abcdef'
        first=c.post('/v1/agents/heartbeat',headers=agent_auth,json={'nonce':nonce})
        assert first.status_code==200, first.text
        replay=c.post('/v1/agents/heartbeat',headers=agent_auth,json={'nonce':nonce})
        assert replay.status_code==409
        revoked=c.post(f"/v1/agents/{agent['id']}/revoke",headers=AUTH,json={'actor':'admin:release','reason':'rotation'})
        assert revoked.status_code==200
        denied=c.post('/v1/agents/heartbeat',headers=agent_auth,json={'nonce':'nonce-fedcba9876543210'})
        assert denied.status_code==403
        listed=c.get('/v1/agents',headers=AUTH)
        assert listed.status_code==200
        assert all('token_hash' not in row for row in listed.json())

def test_ssh_credential_reference_lifecycle_stays_redacted(tmp_path: Path):
    db.DB_PATH=tmp_path/'db.sqlite3'
    with TestClient(cp.app) as c:
        created=c.post('/v1/credential-refs',headers=AUTH,json={
            'name':'prod-ssh','kind':'ssh-key','provider':'vault',
            'metadata':{'backend':'vault','path_ref':'vault://ssh/prod','fingerprint':'SHA256:old','username':'deploy'},
        })
        assert created.status_code==201, created.text
        body=created.json(); cid=body['id']
        assert body['secret_material_stored'] is False
        assert 'private_key' not in str(body).lower()
        rotated=c.post(f'/v1/credential-refs/{cid}/rotate',headers=AUTH,json={
            'metadata':{'backend':'vault','path_ref':'vault://ssh/prod-v2','fingerprint':'SHA256:new','username':'deploy'},
        })
        assert rotated.status_code==200, rotated.text
        assert rotated.json()['metadata']['fingerprint']=='SHA256:new'
        deleted=c.delete(f'/v1/credential-refs/{cid}',headers=AUTH)
        assert deleted.status_code==204


def test_audit_retention_prunes_old_events_and_audits_action(tmp_path: Path):
    db.DB_PATH=tmp_path/'db.sqlite3'
    with TestClient(cp.app) as c:
        c.post('/v1/environments',headers=AUTH,json={'name':'Prod'})
        with db.connect() as conn:
            conn.execute("UPDATE audit_events SET created_at=?", (1,))
            conn.commit()
        pruned=c.post('/v1/audit/retention?days=30&actor=admin%3Arelease',headers=AUTH)
        assert pruned.status_code==200, pruned.text
        assert pruned.json()['deleted'] >= 1
        events=c.get('/v1/audit').json()
        assert events[0]['event_type']=='audit.retention_enforced'


def test_single_active_failover_preserves_policy_and_audit_state(tmp_path: Path):
    primary=tmp_path/'primary.sqlite3'; standby=tmp_path/'standby.sqlite3'
    db.DB_PATH=primary
    with TestClient(cp.app) as c:
        assert c.post('/v1/environments',headers=AUTH,json={'name':'Failover Prod'}).status_code==201
        bumped=c.post('/v1/policy-generation/bump',headers=AUTH,json={'actor':'admin:ha','reason':'failover acceptance'})
        assert bumped.json()['policy_generation']==2
    tool=Path(__file__).resolve().parents[2]/'scripts'/'control-db.py'
    subprocess.run([sys.executable,str(tool),'backup',str(primary),str(standby)],check=True,capture_output=True,text=True)
    db.DB_PATH=standby
    with TestClient(cp.app) as c:
        system=c.get('/v1/system').json()
        assert system['policy_generation']==2
        assert system['counts']['environments']>=2  # includes the default environment
        events=c.get('/v1/audit').json()
        assert any(e['event_type']=='policy.generation_bumped' for e in events)
