#!/bin/sh
# Lo ejecuta el servicio `setup` de deploy/docker-compose.yml, dentro de la imagen de stego.
set -eu
python /deploy/gen_secrets.py --dir /deploy "$@"  # p. ej. --rotate jwt_signing_key
if [ ! -f /imagenes/grande.png ]; then
  # La imagen de más de 5 MB (prueba del 413) no se versiona: sale del mismo laboratorio que las demás.
  python /srv/svc/tools/stego_lab.py demo /tmp/demo > /dev/null
  cp /tmp/demo/grande.png /imagenes/grande.png
  echo "generado: postman/imagenes/grande.png"
fi
# Tras rotar, los contenedores que ya corren solo toman el secreto nuevo al reiniciarse.
[ "$#" -eq 0 ] && next="up -d --build --wait" || next="restart auth stego gateway"
echo "listo: docker compose -f deploy/docker-compose.yml $next"
