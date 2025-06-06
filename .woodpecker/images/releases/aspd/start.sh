#!/bin/sh
set -e

export RUST_BACKTRACE=1

mkdir -p /run/postgresql/
chown -R postgres:postgres /run/postgresql/
export PATH=/usr/lib/postgresql/16/bin:${PATH}

if [ ! -f "/data/aspd/mnemonic" ]; then
#  mkdir -p /var/lib/postgresql/data
  chmod 0700 /var/lib/postgresql/data
  chown -R postgres:postgres /var/lib/postgresql/data
  su postgres -s /bin/sh -c "initdb /var/lib/postgresql/data"
fi

echo "host all  all    0.0.0.0/0  md5" >> /var/lib/postgresql/data/pg_hba.conf
echo "listen_addresses='*'" >> /var/lib/postgresql/data/postgresql.conf

su postgres -s /bin/sh -c "pg_ctl start -D /var/lib/postgresql/data -l /var/lib/postgresql/log.log" &
sleep 2s

if [ ! -f "/data/aspd/mnemonic" ]; then
  psql -U postgres -c "ALTER USER postgres WITH ENCRYPTED PASSWORD 'postgres';"
  echo "Creating new config at /data/aspd/"
  /usr/local/bin/aspd --config /root/aspd/aspd.toml create
  sleep 2s
fi

cat /var/lib/postgresql/log.log
echo "Booting"
/usr/local/bin/aspd --config /root/aspd/aspd.toml start
