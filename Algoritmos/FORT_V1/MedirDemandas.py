
#!/usr/bin/env python3
"""Etapa 03 - Actividad 04: seis flujos concurrentes con iperf2."""

import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path.cwd()
DIR = BASE / "resultados/etapa03"
SALIDA = DIR / "DemandasObservadas_iperf2.json"
LOGS = DIR / "logs_iperf2"

DURACION = 15

# Perfil piloto configurable: no son resultados medidos.
PERFIL = [
    ("h1", "h2", "TCP", 10),
    ("h2", "h3", "TCP", 12),
    ("h3", "h4", "TCP", 8),
    ("h4", "h1", "UDP", 8),
    ("h1", "h3", "UDP", 10),
    ("h2", "h4", "UDP", 6),
]

PATRON = re.compile(
    r"^\[\s*\d+\]\s+"
    r"([\d.]+)-([\d.]+)\s+sec\s+"
    r"[\d.]+\s+[KMGT]?Bytes\s+"
    r"([\d.]+)\s+([KMGT]?)bits/sec",
    re.MULTILINE
)

FACTORES = {
    "": 1,
    "K": 1e3,
    "M": 1e6,
    "G": 1e9,
    "T": 1e12,
}


def exigir(condicion, mensaje):
    if not condicion:
        raise RuntimeError(mensaje)


def leer(ruta):
    return json.loads(ruta.read_text(encoding="utf-8"))


def analizar(texto, protocolo):
    partes = texto.split("Server Report:")
    emisor = list(PATRON.finditer(partes[0]))

    exigir(bool(emisor), "Falta resumen del emisor")

    resumen = emisor[-1]
    tasa_envio = float(resumen[3]) * FACTORES[resumen[4]]
    duracion = float(resumen[2]) - float(resumen[1])

    receptor_bps = None
    perdida = None
    jitter = None

    if protocolo == "UDP":
        exigir(
            len(partes) > 1,
            "No se recibio informe UDP del servidor"
        )

        receptor = list(PATRON.finditer(partes[1]))
        exigir(bool(receptor), "Falta tasa recibida UDP")

        resumen_receptor = receptor[-1]
        receptor_bps = (
            float(resumen_receptor[3])
            * FACTORES[resumen_receptor[4]]
        )

        perdida_match = re.search(
            r"(\d+)/(\d+)\s+\(([\d.]+)%\)",
            partes[1]
        )
        exigir(
            perdida_match is not None,
            "Faltan estadisticas de perdida UDP"
        )
        perdida = float(perdida_match[3])

        jitter_match = re.search(
            r"([\d.]+)\s+ms\s+\d+/\d+",
            partes[1]
        )
        if jitter_match:
            jitter = float(jitter_match[1])

    intervalos = [
        {
            "inicio_s": float(m[1]),
            "fin_s": float(m[2]),
            "tasa_bps": float(m[3]) * FACTORES[m[4]]
        }
        for m in emisor[:-1]
    ]

    return {
        "tasa_enviada_bps": tasa_envio,
        "tasa_recibida_bps": receptor_bps,
        "duracion_real_s": duracion,
        "perdida_udp_pct": perdida,
        "jitter_udp_ms": jitter,
        "intervalos_emisor": intervalos,
    }


def ejecutar(net):
    sys.path.insert(0, str(BASE / "herramientas"))
    from CalcularCaminos import verificar_estado_actual

    topologia = leer(
        DIR / "TopologiaPostFallo.json"
    )
    verificar_estado_actual(topologia)

    fallos = topologia["enlaces_caidos"]
    exigir(len(fallos) == 1, "Se requiere un fallo simple")

    hosts = {h.name: h for h in net.hosts}

    exigir(
        len(PERFIL) == 6
        and sum(f[2] == "TCP" for f in PERFIL) == 3
        and sum(f[2] == "UDP" for f in PERFIL) == 3,
        "Perfil 3 TCP + 3 UDP invalido"
    )

    exigir(
        len({(f[0], f[1]) for f in PERFIL}) == 6,
        "Comunicaciones duplicadas"
    )

    for origen, destino, _, tasa in PERFIL:
        exigir(
            origen in hosts
            and destino in hosts
            and origen != destino
            and tasa > 0,
            "Perfil de flujo invalido"
        )

    LOGS.mkdir(parents=True, exist_ok=True)

    servidores = []
    clientes = []
    archivos = []

    print("\n=== DEMANDAS CONCURRENTES - IPERF2 ===")
    print("Fallo:", fallos[0]["extremo_a"].upper(),
          "-", fallos[0]["extremo_b"].upper())
    print("Perfil: 3 TCP + 3 UDP")
    print("Duracion solicitada:", DURACION, "segundos")

    try:
        # Cada flujo utiliza un puerto de servidor diferente.
        for i, (_, destino, protocolo, _) in enumerate(PERFIL):
            puerto = 5601 + i
            comando = [
                "iperf", "-s", "-p", str(puerto)
            ]

            if protocolo == "UDP":
                comando.append("-u")

            servidor = hosts[destino].popen(
                comando,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            servidores.append(servidor)

        time.sleep(1)

        inicio = datetime.now(timezone.utc).isoformat()

        # Se lanzan todos los clientes sin esperar a los otros.
        for i, (origen, destino, protocolo, tasa) in (
            enumerate(PERFIL)
        ):
            puerto = 5601 + i
            ruta_log = LOGS / f"F{i + 1:02d}.log"
            archivo = ruta_log.open("w", encoding="utf-8")
            archivos.append(archivo)

            comando = [
                "iperf",
                "-c", hosts[destino].IP(),
                "-p", str(puerto),
                "-t", str(DURACION),
                "-i", "2",
                "-b", f"{tasa}M",
            ]

            if protocolo == "UDP":
                comando.append("-u")

            cliente = hosts[origen].popen(
                comando,
                stdout=archivo,
                stderr=subprocess.STDOUT
            )
            clientes.append(cliente)

        for i, cliente in enumerate(clientes):
            cliente.wait(timeout=DURACION + 45)
            exigir(
                cliente.returncode == 0,
                f"F{i + 1:02d} fallo; revisar logs_iperf2"
            )

        for archivo in archivos:
            archivo.close()
        archivos.clear()

        registros = []

        for i, (origen, destino, protocolo, tasa) in (
            enumerate(PERFIL)
        ):
            ruta_log = LOGS / f"F{i + 1:02d}.log"
            datos = analizar(
                ruta_log.read_text(encoding="utf-8"),
                protocolo
            )

            registros.append({
                "id": f"F{i + 1:02d}",
                "origen": origen,
                "destino": destino,
                "protocolo": protocolo,
                "tasa_solicitada_mbps": tasa,
                **datos,
            })

        resultado = {
            "tipo": "DemandasObservadas_Piloto_iperf2",
            "inicio_utc": inicio,
            "fin_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "enlace_fallado": [
                fallos[0]["extremo_a"],
                fallos[0]["extremo_b"]
            ],
            "duracion_solicitada_s": DURACION,
            "cantidad_flujos": len(registros),
            "nota": (
                "Tasa enviada observada y tasa recibida "
                "UDP. TCP receptor no medido por este "
                "registrador. Prueba piloto, no demanda "
                "futura garantizada."
            ),
            "flujos": registros,
        }

        temporal = SALIDA.with_suffix(".json.tmp")
        temporal.write_text(
            json.dumps(
                resultado,
                indent=2,
                ensure_ascii=False
            ) + "\n",
            encoding="utf-8"
        )
        temporal.replace(SALIDA)

        print("\n=== RESULTADOS OBSERVADOS ===")

        for f in registros:
            porcentaje = (
                f["tasa_enviada_bps"]
                / (f["tasa_solicitada_mbps"] * 1e6)
                * 100
            )

            print(
                f'{f["id"]}: {f["origen"].upper()} -> '
                f'{f["destino"].upper()} {f["protocolo"]} | '
                f'Solicitado: {f["tasa_solicitada_mbps"]} | '
                f'Enviado: {f["tasa_enviada_bps"]/1e6:.3f} '
                f'Mbps | {porcentaje:.1f}%'
            )

            if porcentaje < 75 or (
                f["duracion_real_s"] > DURACION * 1.3
            ):
                print(
                    "  ALERTA: tasa o duracion irregular"
                )

        print("\nFlujos registrados:", len(registros))
        print("Archivo generado:", SALIDA)

    finally:
        for proceso in clientes + servidores:
            if proceso.poll() is None:
                proceso.terminate()

        for proceso in clientes + servidores:
            if proceso.poll() is None:
                try:
                    proceso.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proceso.kill()

        for archivo in archivos:
            archivo.close()


if __name__ == "__main__":
    ejecutar(net)
