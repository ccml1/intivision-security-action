#!/usr/bin/env python3
"""
Chequeo de políticas de seguridad derivado de la auditoría (security-audit, run-1).

Revisa la configuración versionada (compose, Caddy, MQTT, Dockerfiles, dependencias, ignores) y
falla si encuentra una violación de nivel "error". Las de nivel "warning" se muestran pero no bloquean.

Uso:  python .github/security/policy_check.py [--root .] [--strict]
      --strict convierte los warnings en errores.

Cada regla cita la pista de la auditoría que la originó (ver docs/pipeline-seguridad.md).
"""
import argparse
import os
import re
import sys

try:
    import yaml
except ImportError:  # el workflow instala PyYAML; sin él no se pueden leer compose ni config
    print("::error::PyYAML no está instalado (pip install pyyaml)")
    sys.exit(2)

PUBLIC_MQTT_BROKERS = {
    "broker.hivemq.com", "test.mosquitto.org", "broker.emqx.io",
    "mqtt.eclipseprojects.io", "public.mqtthq.com", "broker.mqttdashboard.com",
}
LOOPBACK = ("127.0.0.1", "localhost", "[::1]", "::1")

findings = []


def add(level, rule, path, line, message):
    findings.append({"level": level, "rule": rule, "path": path, "line": line or 1, "message": message})


def read(root, rel):
    p = os.path.join(root, rel)
    if not os.path.isfile(p):
        return None
    with open(p, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def line_of(text, needle):
    for i, ln in enumerate(text.splitlines(), 1):
        if needle in ln:
            return i
    return 1


# ---------------------------------------------------------------- reglas

def check_compose(root):
    """POL-001: ningún servicio interno publica puertos en todas las interfaces (auditoría: pista 6)."""
    rel = "docker-compose.yml"
    text = read(root, rel)
    if text is None:
        return
    data = yaml.safe_load(text) or {}
    exposed_ok = {"caddy"}  # el proxy TLS es la única entrada prevista
    for name, svc in (data.get("services") or {}).items():
        for port in svc.get("ports") or []:
            spec = str(port if not isinstance(port, dict) else f"{port.get('host_ip', '')}:{port.get('published')}:{port.get('target')}")
            parts = spec.split(":")
            bound_loopback = len(parts) >= 3 and parts[0].strip("[]") in [h.strip("[]") for h in LOOPBACK]
            if name in exposed_ok or bound_loopback:
                continue
            level = "error" if name == "backend" else "warning"
            add(level, "POL-001", rel, line_of(text, f'"{spec}"') if f'"{spec}"' in text else line_of(text, spec),
                f"El servicio '{name}' publica el puerto {spec} en todas las interfaces. "
                f"Usa '127.0.0.1:{parts[-2] if len(parts) > 1 else parts[0]}:{parts[-1]}' o quita 'ports' "
                f"y deja que solo Caddy reciba tráfico externo.")


def check_mosquitto(root):
    """POL-002: el broker propio no admite clientes anónimos (auditoría: mejoras recomendadas / pista 1)."""
    rel = "mosquitto.conf"
    text = read(root, rel)
    if text is None:
        return
    if re.search(r"^\s*allow_anonymous\s+true\b", text, re.M):
        add("warning", "POL-002", rel, line_of(text, "allow_anonymous"),
            "mosquitto permite clientes anónimos. Usa 'allow_anonymous false' con password_file y acl_file.")


def check_actuator(root):
    """POL-003: la sirena no se controla desde un broker MQTT público sin credenciales (auditoría: pista 1)."""
    rel = "config.yaml"
    text = read(root, rel)
    if text is None:
        return
    cfg = yaml.safe_load(text) or {}
    act = cfg.get("actuator") or {}
    if str(act.get("type", "")).lower() != "mqtt":
        return
    host = str(act.get("host") or "").lower()
    if host in PUBLIC_MQTT_BROKERS:
        add("error", "POL-003", rel, line_of(text, "host:"),
            f"El actuador de la sirena usa el broker público '{host}'. Cualquiera que conozca el tópico "
            f"puede encender o apagar la sirena. Usa un broker propio con usuario/contraseña y TLS.")
    if not act.get("username") and not act.get("password"):
        add("warning", "POL-003b", rel, line_of(text, "username:"),
            "El actuador MQTT no tiene credenciales en config.yaml; verifica que MQTT_USERNAME/MQTT_PASSWORD "
            "se definan en el despliegue.")
    if int(act.get("port") or 1883) == 1883:
        add("warning", "POL-003c", rel, line_of(text, "port:"),
            "MQTT en el puerto 1883 viaja sin cifrar; usa 8883 con TLS.")


def check_firmware(root):
    """POL-004: el firmware no lleva un broker público ni un tópico fijo (auditoría: pista 1)."""
    rel = "wokwi/sketch.ino"
    text = read(root, rel)
    if text is None:
        return
    for host in PUBLIC_MQTT_BROKERS:
        if host in text:
            add("warning", "POL-004", rel, line_of(text, host),
                f"El firmware se conecta al broker público '{host}' sin autenticación.")
    if re.search(r"\.connect\(\s*\w+\s*\)", text):
        add("warning", "POL-004b", rel, line_of(text, ".connect("),
            "mqtt.connect() sin usuario ni contraseña: cualquier publicador del tópico controla la sirena.")


def check_caddy(root):
    """POL-005/006: sin credenciales en el Caddyfile y con límite de cuerpo (auditoría: pistas 5 y 14)."""
    rel = "Caddyfile"
    text = read(root, rel)
    if text is None:
        return
    if re.search(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", text) or "basic_auth" in text or "basicauth" in text:
        add("error", "POL-005", rel, line_of(text, "basic"),
            "El Caddyfile contiene basic_auth o un hash bcrypt. Las credenciales no se versionan; "
            "usa una variable de entorno ({$VAR}) o un archivo fuera del repositorio.")
    if "max_size" not in text:
        add("warning", "POL-006", rel, 1,
            "Caddy no limita el tamaño del cuerpo de las peticiones. Agrega 'request_body { max_size 210MB }' "
            "para que un cuerpo chunked no se reciba completo antes de llegar a la app.")


def check_dockerfiles(root):
    """POL-007: los contenedores no corren como root (auditoría: mejoras recomendadas)."""
    for rel in ("Dockerfile", "backend/Dockerfile"):
        text = read(root, rel)
        if text is None:
            continue
        users = re.findall(r"^\s*USER\s+(\S+)", text, re.M | re.I)
        if not users or users[-1].lower() in ("root", "0", "0:0"):
            add("warning", "POL-007", rel, 1,
                "La imagen corre como root (no hay USER sin privilegios al final del Dockerfile).")


def check_requirements(root):
    """POL-008: dependencias fijadas a una versión exacta (auditoría: mejoras recomendadas)."""
    rel = "requirements.txt"
    text = read(root, rel)
    if text is None:
        return
    for i, ln in enumerate(text.splitlines(), 1):
        s = ln.split("#", 1)[0].strip()
        if not s or s.startswith("-"):
            continue
        if "==" not in s:
            add("warning", "POL-008", rel, i, f"'{s}' no está fijada con '=='; las builds no son reproducibles.")


def check_ignores(root):
    """POL-009: los ignores cubren secretos y datos locales (auditoría: mejoras recomendadas)."""
    gi = read(root, ".gitignore") or ""
    for pat in (".env", ".env.*", "*.pem", "*.key"):
        if pat not in gi.split():
            add("warning", "POL-009", ".gitignore", 1, f".gitignore no incluye '{pat}'.")
    di = read(root, ".dockerignore")
    if di is not None:
        for pat in ("*.dump", "backups/", "*.mp4", ".git/"):
            if pat not in di.split():
                add("warning", "POL-009b", ".dockerignore", 1,
                    f".dockerignore no incluye '{pat}': 'COPY . .' lo metería en la imagen.")


def check_tracked_secrets(root):
    """POL-010: no hay archivos de secretos versionados."""
    bad = (".env", ".pem", ".key", "credentials.json", "id_rsa")
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "venv", ".venv")]
        for f in files:
            if f == ".env" or f.startswith(".env.") and not f.endswith(".example") or f.endswith(bad[1:]):
                rel = os.path.relpath(os.path.join(base, f), root).replace("\\", "/")
                add("error", "POL-010", rel, 1, "Archivo de secretos dentro del repositorio.")


CHECKS = [check_compose, check_mosquitto, check_actuator, check_firmware, check_caddy,
          check_dockerfiles, check_requirements, check_ignores, check_tracked_secrets]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--strict", action="store_true", help="los warnings también fallan")
    args = ap.parse_args()

    for check in CHECKS:
        check(args.root)

    gha = os.environ.get("GITHUB_ACTIONS") == "true"
    for f in findings:
        level = "error" if f["level"] == "error" or args.strict else "warning"
        if gha:
            print(f"::{level} file={f['path']},line={f['line']},title={f['rule']}::{f['message']}")
        else:
            print(f"[{level.upper():7}] {f['rule']:9} {f['path']}:{f['line']}  {f['message']}")

    errors = [f for f in findings if f["level"] == "error" or args.strict]
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("## Chequeo de políticas (auditoría run-1)\n\n")
            fh.write(f"**{len(errors)} bloqueantes, {len(findings) - len(errors)} avisos**\n\n")
            if findings:
                fh.write("| Nivel | Regla | Archivo | Mensaje |\n|---|---|---|---|\n")
                for f in sorted(findings, key=lambda x: (x["level"] != "error", x["rule"])):
                    msg = f["message"].replace("|", "\\|")
                    fh.write(f"| {f['level']} | {f['rule']} | `{f['path']}:{f['line']}` | {msg} |\n")
    print(f"\n{len(errors)} bloqueante(s), {len(findings) - len(errors)} aviso(s).")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
