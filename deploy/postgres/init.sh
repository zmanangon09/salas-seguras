#!/bin/sh
# Se ejecuta una sola vez, al crear el volumen. Crea una BD y dos roles por servicio (spec §7.6).
set -eu
for svc in auth stego; do
  owner_file="/run/secrets/db_${svc}_owner"
  app_file="/run/secrets/db_${svc}_app"
  for f in "$owner_file" "$app_file"; do
    [ -s "$f" ] || { echo "secreto requerido ausente o vacío: $f" >&2; exit 1; }
  done
  # psql lee las contraseñas del archivo (\set con `cat`): nunca van en la línea de comandos (ps).
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
    -v db="$svc" -v owner="${svc}_owner" -v app="${svc}_app" \
    -v owner_file="$owner_file" -v app_file="$app_file" <<'SQL'
\set owner_pw `cat :'owner_file'`
\set app_pw `cat :'app_file'`
-- Las sentencias llevan contraseñas: ni se registran ni se citan si fallan.
SET log_statement = 'none';
SET log_min_error_statement = 'panic';
CREATE ROLE :"owner" LOGIN PASSWORD :'owner_pw';
CREATE ROLE :"app" LOGIN PASSWORD :'app_pw';
ALTER ROLE :"owner" SET log_statement = 'all';
CREATE DATABASE :"db" OWNER :"owner";
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO :"app";
SQL
done
# Los roles de los servicios solo entran a su BD: nada de postgres ni template1 (R11).
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -c 'REVOKE ALL ON DATABASE postgres, template1 FROM PUBLIC'
