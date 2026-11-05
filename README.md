# Salas de Chat Seguras: Backend V1

Dos microservicios REST detrás de un API Gateway, todo en Docker:

- **`auth`** administra usuarios, roles (ADMIN, ANALYST, USER) y su relación N:M `user_roles`. Emite JWT firmados con RS256 y decide la autorización vigente en cada petición.
- **`stego`** analiza imágenes en busca de esteganografía (chi², RS y entropía del LSB, más la estructura del archivo). Clasifica cada archivo en `sin_indicios`, `sospechoso`, `no_concluyente` o `error`, aplica una política y guarda cada análisis.
- **`gateway`** (Nginx) es el único punto de entrada. Termina TLS 1.3, aplica rate limit y, en cada petición, pregunta a `auth` antes de enrutar.

Equipo: Zaith Manangón, Andrés Cedeño y Stefany Díaz.

## Requisitos

- Docker con Docker Compose v2 (Docker Desktop en Windows y macOS), con los puertos 80 y 443 libres. No hace falta nada más: los secretos, el certificado y las imágenes de prueba también se generan en contenedores.
- Postman para probar la API, o Node.js para correr la colección con Newman.

## Puesta en marcha

Todos los comandos se ejecutan desde la raíz del repositorio.

1. **Preparar (una sola vez).** Genera los secretos en `deploy/secrets/`, el certificado TLS de `localhost` en `deploy/certs/` y la imagen de más de 5 MB que usa la colección. No reemplaza secretos ni certificados que ya existan, y nada de eso se versiona.

   ```bash
   docker compose -f deploy/docker-compose.yml run --rm setup
   ```

2. **Levantar el stack** (`db`, `auth-migrate`, `auth`, `stego-migrate`, `stego` y `gateway`):

   ```bash
   docker compose -f deploy/docker-compose.yml up -d --build --wait
   ```

   `auth-migrate` y `stego-migrate` crean las tablas y terminan en `Exited (0)`. Si alguna falla: `docker compose -f deploy/docker-compose.yml logs auth-migrate stego-migrate`.

3. **Crear el administrador.** No existen credenciales por defecto. El comando pide la contraseña dos veces, sin mostrarla (en scripts, `exec -T ... --password-stdin` la lee de la entrada estándar):

   ```bash
   docker compose -f deploy/docker-compose.yml exec auth python -m auth_svc.create_admin admin --email admin@example.com
   ```

4. **Comprobar.** Debe responder `{"error":"no autenticado"}` (401):

   ```bash
   curl --cacert deploy/certs/ca.pem https://localhost/api/auth/profile
   ```

   En PowerShell usa `curl.exe --ssl-revoke-best-effort --cacert deploy/certs/ca.pem https://localhost/api/auth/profile`: el curl de Windows intenta revisar la revocación, y un certificado local no tiene dónde publicarla.

## Probar con Postman

1. Importa `postman/parcial-1.postman_collection.json`.
2. En *Settings → Certificates*, activa *CA certificates* y elige `deploy/certs/ca.pem`.
3. En *Settings → General*, apunta el *Working directory* a la raíz de este repositorio: las imágenes salen de `postman/imagenes/`.
4. Crea un entorno con `admin_username` y `admin_password`, los del paso 3. Pon la contraseña solo en *Current value*, que no se sincroniza con la nube de Postman.
5. Con el Runner, ejecuta en orden las carpetas `1 - Admin` y `2 - Usuario y Stego`. La carpeta `3` se corre con `auth` detenido (T08).

Por consola, con el entorno exportado desde Postman (git ignora los `*.postman_environment.json` y la carpeta `newman/` de los reportes, porque guardan la contraseña y los JWT):

```bash
npx newman run postman/parcial-1.postman_collection.json -e local.postman_environment.json --folder "1 - Admin" --folder "2 - Usuario y Stego" --working-dir . --ssl-extra-ca-certs deploy/certs/ca.pem
```

## API

| Servicio | Método | Ruta | Acceso |
|---|---|---|---|
| AUTH | POST | `/api/auth/login` | Público, con límite de intentos |
| AUTH | GET | `/api/auth/profile` | Usuario autenticado |
| AUTH | POST | `/api/auth/logout` | Sesión autenticada |
| AUTH | POST, GET | `/api/users` | ADMIN (`users.manage`) |
| AUTH | PATCH | `/api/users/{id}` | ADMIN (`users.manage`) |
| AUTH | GET | `/api/roles/permissions` | ADMIN (`roles.manage`) |
| AUTH | POST, GET | `/api/roles` | ADMIN (`roles.manage`) |
| AUTH | PATCH | `/api/roles/{id}` | ADMIN (`roles.manage`) |
| AUTH | POST | `/api/user-roles` | ADMIN (`roles.manage`) |
| AUTH | DELETE | `/api/user-roles/{id}` | ADMIN (`roles.manage`) |
| AUTH | POST | `/internal/authorization/check` | Solo el gateway, con token de servicio; desde afuera da 404 |
| STEGO | POST | `/api/steganography/analyze` | ADMIN o ANALYST (`steganography.analyze`) |
| STEGO | GET | `/api/steganography/results/{id}` | El dueño, o quien tenga `steganography.results.read_any` |

## Escenarios de la demo

| ID | Cómo |
|---|---|
| T01 | `docker compose -f deploy/docker-compose.yml stop stego`: el análisis da 503 y `auth` sigue respondiendo. Después, `start stego` |
| T02–T07, T09–T11 | Colección de Postman, carpetas 1 y 2 |
| T08 | `docker compose -f deploy/docker-compose.yml stop auth` y la carpeta 3: 503, y ningún `stego.analyzed` en los registros. Después, `start auth` |
| T12 | `docker compose -f deploy/docker-compose.yml logs gateway auth stego`: eventos JSON con `request_id`, sin JWT ni contraseñas |

## Operación

- **Detener:** `docker compose -f deploy/docker-compose.yml down`. Los datos quedan en los volúmenes; `down -v` borra también la BD y la cuarentena de `stego`.
- **Rotar** la clave de los JWT o el token del gateway: `docker compose -f deploy/docker-compose.yml run --rm setup --rotate jwt_signing_key` (o `svc_token_gateway`) y después `docker compose -f deploy/docker-compose.yml restart auth stego gateway`. Con la clave nueva, los JWT emitidos dejan de valer.
- **Secretos:** si borras `deploy/secrets/`, borra también los volúmenes (`down -v`), porque Postgres solo lee las contraseñas al crear el suyo. Después, repite el paso 1.
- **Certificado:** para uno nuevo, borra `deploy/certs/`, repite el paso 1 y vuelve a cargar `ca.pem` en Postman. La clave de esa CA no se guarda, así que confiar en ella solo cubre este certificado. Si prefieres mkcert, deja su `fullchain.pem` y su `privkey.pem` en `deploy/certs/` antes del paso 1; `setup` no los toca (en Linux, además, `sudo chown root deploy/certs/privkey.pem`, porque nginx no lee una clave 0600 de otro usuario).
- **Linux:** `setup` corre como root, así que borrar `deploy/secrets/` o `deploy/certs/` pide `sudo`.
- **Configuración:** las variables no secretas de cada servicio están en `services/auth/.env.example` y `services/stego/.env.example`. Los secretos se leen siempre desde `/run/secrets`.

## Estructura

```
services/   auth, stego y la librería común (shared), con un Dockerfile para ambos
gateway/    Nginx: TLS 1.3, rate limit y autorización en cada petición
deploy/     docker-compose.yml, preparación (setup.sh y gen_secrets.py) e inicio de PostgreSQL
postman/    colección de Postman e imágenes de prueba
```
