# Upgrade and rollback to Hermes Control Plane 0.5.10

The supported stable upgrade path is backup-first and fail-closed.

## Upgrade

```bash
./hermesctl backup
./hermesctl upgrade 0.5.10
./hermesctl wait 180
./hermesctl doctor
```

`hermesctl upgrade` verifies published Control Plane/Kubernetes Broker image tags and takes an online SQLite backup when the Control Plane is running before changing the configured version.

## Rollback

Keep the backup created immediately before the upgrade. If stable validation fails:

```bash
./hermesctl version set <previous-published-version>
./hermesctl up --pull
./hermesctl restore backups/<pre-upgrade-backup>.sqlite3
./hermesctl wait 180
./hermesctl doctor
```

Never run an older binary against a database that has already been migrated by a newer release and assume compatibility. Restore the matching pre-upgrade database as part of rollback.

## Migration to Kubernetes

For Docker -> Kubernetes, restore the verified SQLite backup into a persistent Helm Control Plane volume while the destination is stopped. Re-create referenced credential material in the destination secret backend; the Control Plane database contains only redacted references/fingerprints. Run `scripts/acceptance/api-equivalence.py` and `scripts/acceptance/migration-acceptance.py` before switching traffic.
