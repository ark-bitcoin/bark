#!/bin/sh
set -e

export RUST_BACKTRACE=1

echo "${ASPD__DATA_DIR}"

if [ -f "${ASPD__DATA_DIR}/mnemonic" ]; then
  echo "Config already exists at ${ASPD__DATA_DIR}"
  su postgres -s /bin/sh -c "pg_ctl start -D /var/lib/postgresql/data -l /var/lib/postgresql/log.log" &
  sleep 2s
else
#  mkdir -p /var/lib/postgresql/data
  chmod 0700 /var/lib/postgresql/data
  chown -R postgres:postgres /var/lib/postgresql/data
  mkdir -p /run/postgresql/
  chown -R postgres:postgres /run/postgresql/
  su postgres -s /bin/sh -c "initdb /var/lib/postgresql/data"
  echo "host all  all    0.0.0.0/0  md5" >> /var/lib/postgresql/data/pg_hba.conf
  echo "listen_addresses='*'" >> /var/lib/postgresql/data/postgresql.conf
  su postgres -s /bin/sh -c "pg_ctl start -D /var/lib/postgresql/data -l /var/lib/postgresql/log.log" &
  sleep 2s
  psql -U postgres -c "ALTER USER postgres WITH ENCRYPTED PASSWORD 'postgres';"
  cat /var/lib/postgresql/log.log

  echo "Creating new config at ${ASPD__DATA_DIR}"
  /usr/local/bin/aspd --config /root/aspd/aspd.toml create
  sleep 2s
fi

echo "Booting"
/usr/local/bin/aspd --config /root/aspd/aspd.toml start
