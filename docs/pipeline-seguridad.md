# Pipeline de seguridad (GitHub Actions)

El workflow [`.github/workflows/security-ci.yml`](../.github/workflows/security-ci.yml) se construyó a partir de la auditoría de seguridad del proyecto (security-audit, perfil `quick`, run-1). Cada job ataca una o varias pistas concretas de esa auditoría.

## Cuándo se ejecuta

| Evento | Qué revisa |
|---|---|
| Pull request a `main` | Todos los jobs. Gitleaks revisa solo los commits del PR |
| Push a `main` o tag `v*` | Todos los jobs |
| Lunes 05:23 UTC (`schedule`) | Todos los jobs. Gitleaks revisa **todo el historial** |
| Manual (`workflow_dispatch`) | Igual que el semanal |

## Jobs

| Job | Herramienta | ¿Bloquea? | Pistas de la auditoría que cubre |
|---|---|---|---|
| `secrets` | Gitleaks + [`.gitleaks.toml`](../.gitleaks.toml) | Sí | 5: hash bcrypt de `basic_auth` en el historial. También tokens de Telegram y URLs de Postgres con contraseña |
| `policy` | [`policy_check.py`](../.github/security/policy_check.py) | Sí, en reglas de nivel *error* | 1: sirena en broker MQTT público. 6: puerto 8000 expuesto. 5: credenciales en el Caddyfile. 14: Caddy sin límite de cuerpo. Además: mosquitto anónimo, contenedores como root, dependencias sin fijar y ignores incompletos |
| `semgrep` | Semgrep (`p/python`, `p/secrets` y [reglas propias](../.github/security/semgrep-intivision.yml)) | Sí, solo en severidad ERROR | 2 y 3: `storage_key` del primero que lo registra. 7: confianza en `X-Forwarded-For`. 12: análisis bloqueante en un handler async. 14: límite de tamaño solo por `Content-Length`. 1: MQTT sin TLS. Tokens en los logs |
| `bandit` | Bandit | Sí, en severidad alta con confianza media o alta | Patrones inseguros genéricos de Python |
| `codeql` | CodeQL (`python`, `actions`), consultas `security-extended` | No (se publica en Code Scanning) | Flujo de datos: inyecciones, rutas y uso inseguro de los workflows |
| `iac` | Hadolint + Trivy config | Hadolint sí en *error*; Trivy no | Dockerfiles (contenedores como root, malas prácticas) |
| `images` | Build + Trivy image | Sí, con HIGH/CRITICAL que tengan parche | Dependencias realmente instaladas. `requirements.txt` no está fijado, así que se escanea la imagen construida |

Los resultados de Semgrep, Bandit, CodeQL y Trivy se publican en **Security → Code scanning** del repositorio. El job `policy` deja una tabla en el resumen de la ejecución.

## Reglas del chequeo de políticas

| Regla | Nivel | Qué exige |
|---|---|---|
| POL-001 | error (backend), warning (otros) | Ningún servicio publica puertos en todas las interfaces. Solo Caddy recibe tráfico externo |
| POL-002 | warning | `mosquitto.conf` sin `allow_anonymous true` |
| POL-003 | error | El actuador de la sirena no usa un broker MQTT público |
| POL-003b/c | warning | El actuador MQTT tiene credenciales y usa TLS (8883) |
| POL-004 | warning | El firmware no apunta a un broker público ni se conecta sin credenciales |
| POL-005 | error | El Caddyfile no contiene `basic_auth` ni hashes bcrypt |
| POL-006 | warning | Caddy limita el tamaño del cuerpo (`request_body max_size`) |
| POL-007 | warning | Los Dockerfiles terminan con un `USER` sin privilegios |
| POL-008 | warning | `requirements.txt` fija las versiones con `==` |
| POL-009 | warning | `.gitignore` y `.dockerignore` excluyen secretos, dumps y videos |
| POL-010 | error | No hay archivos `.env`, `.pem` ni `.key` versionados |

Para probarlo localmente:

```bash
pip install pyyaml==6.0.3
python .github/security/policy_check.py --root .
```

Con `--strict`, los avisos también fallan.

## Estado esperado hoy

Cuando se agregó el pipeline, el chequeo de políticas **falla a propósito** con 2 errores que vienen de la auditoría:

1. **POL-001:** `docker-compose.yml` publica `8000:8000` en todas las interfaces. Se corrige con `127.0.0.1:8000:8000` o quitando `ports` del backend.
2. **POL-003:** `config.yaml` usa `broker.hivemq.com` para la sirena. Se corrige con un broker propio con usuario, contraseña y TLS, o poniendo `actuator.type: log` mientras sea solo una demo.

El escaneo semanal de gitleaks también va a reportar el hash bcrypt de `basic_auth` que está en el historial (commits `b99bce4`…`41b30dc`). Para resolverlo:

- cambiar esa contraseña donde se use;
- reescribir el historial (`git filter-repo`), o aceptar el riesgo de forma explícita agregando la huella a `.gitleaksignore`.

## Lo que el pipeline no cubre

La auditoría dejó pistas que dependen de cómo se comporta el sistema en ejecución y no se pueden detectar con análisis estático:

- WebSockets que siguen activos tras un logout;
- cooldowns compartidos;
- el `ThreatScorer` compartido entre subidas;
- la diferencia de tiempo en el login de cuentas bloqueadas.

Para esas pistas conviene agregar tests de integración con una base de datos de prueba, siguiendo los planes locales del informe `NEEDS-VALIDATION.md` de la auditoría.
