# Postgres high-availability cluster (jungle-prod)

This document describes the Postgres cluster for the Ark server deployment.
captaind, watchmand and Core Lightning (CLN) use this cluster.
The cluster has three nodes, one on each Proxmox host.
Patroni manages the cluster, and etcd stores the cluster state.
vip-manager holds one stable address (the VIP) on the current leader.

## Topology

| Node | LAN (eth0, SSH only) | Backend (enp6s19) | Role |
|------|----------------------|-------------------|------|
| ark-pg-1 | 192.168.128.150 | 10.42.0.11 | Patroni, Postgres, etcd, vip-manager |
| ark-pg-2 | 192.168.128.149 | 10.42.0.12 | Patroni, Postgres, etcd, vip-manager |
| ark-pg-3 | 192.168.128.148 | 10.42.0.13 | Patroni, Postgres, etcd, vip-manager |

- The VIP is `10.42.0.10` (port 5432). It is a secondary address on `enp6s19` of the leader.
- Clients: ark-captaind `10.42.0.20`, ark-watchmand `10.42.0.21`, ark-cln `10.42.0.22`.
- `10.42.0.0/24` is a private VXLAN L2 network with MTU 1450 and no gateway.
- Only sshd listens on `0.0.0.0` (port 22).
  All other services listen on the `10.42.0.x` address or on localhost.
  The Postgres `listen_addresses` is the node address, the VIP and `127.0.0.1`.
- The sysctl `net.ipv4.ip_nonlocal_bind=1` (`/etc/sysctl.d/90-ark-pg.conf`) lets
  Postgres bind to the VIP on a node that does not hold it.
- The Patroni cluster is `ark-pg`. The leader key in etcd is `/service/ark-pg/leader`.
- Patroni uses `synchronous_mode: true` and `synchronous_mode_strict: true` with
  `synchronous_node_count: 1`.
  The cluster has one leader, one synchronous standby and one asynchronous replica.
  Postgres acknowledges a commit only after the synchronous standby has the WAL.
  If no standby is available, writes block. Postgres does not lose the write.

## Versions

| Component | Version | Source |
|-----------|---------|--------|
| Debian | 12 (bookworm), kernel 6.1.0-56 | |
| PostgreSQL | 17.12 | PGDG (apt.postgresql.org) |
| Patroni | 4.1.5 | PGDG |
| vip-manager | 1.0.2 | PGDG |
| pgBackRest | 2.60.1 | PGDG |
| etcd | 3.4.23 (`etcd-server`, `etcd-client`) | Debian bookworm main |

PGDG does not ship etcd for bookworm.
The etcd packages come from the Debian archive.
The PGDG signing key fingerprint is `B97B0AFC AA1A47F0 44F244A0 7FCC7D46 ACCC4CF8`.
The key is at `/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc`.

### Known follow-ups

- **etcd 3.4 support status.**
  The 3.4 branch is old. Upstream etcd no longer treats it as a current release.
  Debian backports security fixes, but verify this against the Debian security tracker.
  Plan an upgrade of etcd.
- **etcd v2 API.**
  vip-manager 1.0.2 can only read the leader key with the etcd v2 API.
  etcd 3.4 turns the v2 API off by default, so `ETCD_ENABLE_V2="true"` is set.
  Patroni therefore uses the `etcd:` section (v2 API) and not `etcd3:`.
  etcd 3.6 removes the v2 API.
  When PGDG ships a vip-manager version that supports etcd v3, switch Patroni to
  `etcd3:`, remove `ETCD_ENABLE_V2` and upgrade etcd.
- **etcd has no authentication or TLS.**
  Any host on `10.42.0.0/24` can read and write the cluster state.
  The Proxmox firewall must limit ports 2379, 2380 and 8008 to `10.42.0.11-13`.
- **No watchdog.** Patroni runs without a hardware or `softdog` watchdog.

## File locations

On each node:

| Path | Purpose | Mode |
|------|---------|------|
| `/srv/pgdata` | Mount point of the 150G data disk (ext4, label `pgdata`, mounted by UUID in `/etc/fstab`) | |
| `/srv/pgdata/17/main` | Postgres data directory | 700 postgres |
| `/etc/patroni/config.yml` | Patroni configuration (no secrets) | 640 postgres |
| `/etc/patroni_env.conf` | Patroni secrets as `PATRONI_*` variables | 600 root |
| `/etc/systemd/system/patroni.service.d/10-ark.conf` | Patroni waits for the data disk mount and for etcd | |
| `/etc/default/etcd` | etcd configuration | |
| `/var/lib/etcd/ark-pg-N` | etcd data directory | |
| `/etc/default/vip-manager` | vip-manager configuration | |
| `/var/log/postgresql/postgresql-<day>.log` | Postgres log | |
| `/usr/local/bin/pctl` | Runs `patronictl` with the REST API credentials | 750 root |

Only ark-pg-1 holds the application secrets:

| Path | Content |
|------|---------|
| `/root/ark-db-credentials` (ark-pg-1, mode 600) | Passwords of the `captaind`, `watchmand` and `cln` roles |
| `/root/patroni-secrets.env` (ark-pg-1, mode 600) | Master copy of `/etc/patroni_env.conf` |

The data disk is `/dev/sdb` on ark-pg-1 and ark-pg-3, and `/dev/sda` on ark-pg-2.
Never use these names. Use `/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi1`.

## Configuration templates

The templates are in `contrib/deploy/jungle-prod/postgres/`.
Replace `@NAME@` (for example `ark-pg-1`) and `@IP@` (for example `10.42.0.11`).

| Template | Installs as |
|----------|-------------|
| `patroni.yml.tmpl` | `/etc/patroni/config.yml` |
| `patroni_env.conf.tmpl` | `/etc/patroni_env.conf` |
| `etcd.env.tmpl` | `/etc/default/etcd` |
| `vip-manager.env.tmpl` | `/etc/default/vip-manager` |

Key settings in `patroni.yml.tmpl`:

- Memory (8 vCPU, 7 GiB RAM): `shared_buffers` 1920MB, `effective_cache_size` 5GB,
  `work_mem` 16MB, `maintenance_work_mem` 512MB, `max_connections` 200.
- Durability: `fsync`, `full_page_writes` and `synchronous_commit` are `on`.
  Data checksums are on.
- WAL: `wal_compression` on, `max_wal_size` 4GB, `checkpoint_timeout` 15min.
- Authentication: `password_encryption` is `scram-sha-256`.
  `pg_hba` allows only these connections:
  - `postgres` over the local socket (peer).
  - `replicator` (replication) from `10.42.0.11-13`.
  - `rewind_user` from `10.42.0.11-13`.
  - `captaind` to database `captaind` from `10.42.0.20`.
  - `watchmand` to database `captaind` from `10.42.0.21`.
  - `cln` to databases `cln` and `hold` from `10.42.0.22`.

Patroni applies the `bootstrap.dcs` section only once, when it creates the cluster.
After that, change shared settings with `pctl edit-config`.
`pg_hba` is in the local file: the `postgresql.pg_hba` list in `/etc/patroni/config.yml`.
Edit it on each node and run `pctl reload ark-pg --force`. Patroni rewrites `pg_hba.conf` within about 10 seconds.

## Roles and databases

| Role | Database | Allowed from |
|------|----------|--------------|
| `captaind` | `captaind` (owner `captaind`) | `10.42.0.20` |
| `watchmand` | `captaind` (member of role `captaind`) | `10.42.0.21` |
| `cln` | `cln` and `hold` (owner `cln`) | `10.42.0.22` |

watchmand must run against captaind's database (`docs/expiry-payouts.md`).
It keeps its own login, but the role is a member of `captaind` and has
`ALTER ROLE watchmand SET role = 'captaind'`, so every object it creates is
owned by `captaind` and both daemons can run migrations.
`hold` is the database of CLN's hold plugin.

`PUBLIC` has no `CONNECT` right on these databases.
The roles have no `CREATEDB` right. The databases exist, so `captaind` does not need to create one.

Set up on 2026-11-20 on the leader (`sudo -u postgres psql`):

```sql
GRANT captaind TO watchmand;
ALTER ROLE watchmand SET role = 'captaind';
DROP DATABASE watchmand;            -- was empty; replaced by the shared database
CREATE DATABASE hold OWNER cln;
REVOKE CONNECT, TEMPORARY ON DATABASE hold FROM PUBLIC;
```

## Client DSN

Clients must connect to the VIP, never to a node address.
Read the passwords from `/root/ark-db-credentials` on ark-pg-1.

```
postgres://captaind:<password>@10.42.0.10:5432/captaind
postgres://watchmand:<password>@10.42.0.10:5432/captaind
postgres://cln:<password>@10.42.0.10:5432/cln
postgresql://cln:<password>@10.42.0.10:5432/hold
```

captaind and watchmand take separate fields. Use this `[postgres]` content:

```toml
host = "10.42.0.10"
port = 5432
name = "captaind"   # also "captaind" for watchmand
user = "captaind"   # "watchmand" for watchmand
password = "<password>"
```

captaind connects without TLS (`NoTls`). The traffic stays on the private VXLAN network.
CLN uses `wallet=postgres://cln:<password>@10.42.0.10:5432/cln` and
`hold-database=postgresql://cln:<password>@10.42.0.10:5432/hold` in its configuration.
Percent-encode any special character in a password. The generated passwords are alphanumeric.

On failover, the VIP moves to the new leader and open connections drop.
In the drill, the new leader and the VIP were ready within 15 seconds.
Clients must reconnect with retry.

## Runbook

Use `sudo pctl <command>` on any node. `pctl` is `patronictl` with the REST API credentials.

### Status

```
sudo pctl list
ip -br a show enp6s19                    # the leader holds 10.42.0.10
sudo -u postgres psql -c "select application_name, sync_state from pg_stat_replication"
ETCDCTL_API=3 etcdctl --endpoints=http://10.42.0.11:2379,http://10.42.0.12:2379,http://10.42.0.13:2379 endpoint status -w table
pg_isready -h 10.42.0.10
```

A healthy cluster has one `Leader`, one `Sync Standby` and one `Replica`, all with zero lag.

### Planned switchover

```
sudo pctl switchover --leader <current> --candidate <target>
```

Use a sync standby as the candidate. Patroni refuses a candidate that is not in sync.

### Unplanned failover

Patroni promotes the sync standby when the leader stops renewing its lease
(`ttl` 30 seconds, `loop_wait` 10 seconds).
No action is needed. A manual failover is only for a stuck cluster:

```
sudo pctl failover --candidate <target>
```

With `synchronous_mode_strict`, Patroni promotes only a node that has all acknowledged WAL.

### Rejoin a failed node

1. Fix the cause (VM, disk or etcd).
2. Run `sudo systemctl start etcd patroni` on the node.
3. Patroni runs `pg_rewind` if the timelines differ, or rebuilds the node from the leader with `basebackup`.
4. Run `sudo pctl list` and wait for `streaming`.

To rebuild a node on purpose, run `sudo pctl reinit ark-pg Name`.
Replace `Name` with the node name, for example `ark-pg-2`.

### Both replicas down

With strict mode, the leader blocks every write (`wait_event SyncRep`) until a standby returns.
Reads continue. Do not turn off strict mode to unblock writes.
Restore a replica. If you must accept the risk, `pctl edit-config` can set `synchronous_mode_strict: false`.
Set it back to `true` afterwards.

### Add the pgBackRest repository

pgBackRest 2.60.1 is installed. It is not configured, because the S3 bucket is not chosen.
`archive_mode` is `on` and `archive_command` is `/bin/true`.
This command discards each WAL segment after Postgres archives it, and it never fails.
The disk does not fill with unarchived WAL.
To enable backups, change only configuration:

1. Create the bucket and an access key limited to that bucket.
2. On all three nodes, create `/etc/pgbackrest/pgbackrest.conf` (owner `postgres`, mode 640):

   ```
   [global]
   repo1-type=s3
   repo1-s3-endpoint=<endpoint>
   repo1-s3-bucket=<bucket>
   repo1-s3-region=<region>
   repo1-s3-key=<key>
   repo1-s3-key-secret=<secret>
   repo1-path=/ark-pg
   repo1-retention-full=2
   repo1-cipher-type=aes-256-cbc
   repo1-cipher-pass=<secret>
   compress-type=zst
   start-fast=y

   [ark-pg]
   pg1-path=/srv/pgdata/17/main
   pg1-socket-path=/var/run/postgresql
   ```

   Store the secrets in a root-only file. Keep the cipher passphrase in a safe place.
   Without it, you cannot restore.
3. On the leader, run `sudo -u postgres pgbackrest --stanza=ark-pg stanza-create`.
4. Change the archive command. This needs only a reload:

   ```
   sudo pctl edit-config -s postgresql.parameters.archive_command="pgbackrest --stanza=ark-pg archive-push %p"
   ```

5. Run `sudo -u postgres pgbackrest --stanza=ark-pg check`.
6. Run the first full backup now: `sudo -u postgres pgbackrest --stanza=ark-pg --type=full backup`.
   WAL from before step 4 is not in the repository, so a backup is required.
7. Add a schedule (a systemd timer or cron job) on the leader only, or on all nodes with a leader check.
8. Optional: add a `pgbackrest` entry in `postgresql.create_replica_methods` to build replicas from the repository.

Run a restore test before you rely on the backups.

### Rotate passwords

Application roles (`captaind`, `watchmand`, `cln`):

1. Generate a password: `tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40`.
2. On the leader, run `ALTER ROLE <role> PASSWORD '<new>'` with `sudo -u postgres psql`.
   Send the statement through stdin, not through a command line argument.
3. Update `/root/ark-db-credentials` on ark-pg-1.
4. Update the configuration of the client and restart it.

Patroni secrets (`postgres`, `replicator`, `rewind_user`, REST API):

1. Generate the new passwords. Update `/root/patroni-secrets.env` on ark-pg-1.
2. On the leader, run `ALTER ROLE` for `postgres`, `replicator` and `rewind_user`.
   The change replicates to the standbys.
3. Copy the new `/etc/patroni_env.conf` (root, mode 600) to all three nodes.
4. Restart Patroni on one replica at a time: `sudo systemctl restart patroni`.
   Wait for `sudo pctl list` to show `streaming` before the next node.
5. Run `sudo pctl switchover` away from the leader, then restart Patroni on the old leader.

Restarting Patroni stops Postgres on that node.
Never restart the leader and the sync standby at the same time.

## Verification record

The drills ran on 2026-11-19:

- A row that Postgres acknowledged was present on the new leader after Patroni stopped on the leader.
  The VIP moved to the new leader.
  The old leader rejoined as a replica, and the cluster returned to 1 leader, 1 sync standby and 1 replica.
- With both replicas stopped, a write on the leader blocked in `SyncRep`.
  After the replicas returned, all three nodes held the same rows.
- `pctl switchover` moved the leader and the VIP back to ark-pg-1.
