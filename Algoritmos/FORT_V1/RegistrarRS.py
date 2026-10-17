
#!/usr/bin/env python3
"""Etapa 02 - Actividad 04: medicion real de recursos SDN."""

import json
import re
import subprocess
import time
import argparse
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DIR = BASE / "resultados/etapa02"
SALIDA = DIR / "RS_postfallo.json"


def comando(*argumentos):
    return subprocess.run(
        argumentos,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def leer_json(ruta):
    return json.loads(ruta.read_text(encoding="utf-8"))


def estado_puertos(switch):
    texto = comando(
        "ovs-ofctl", "-O", "OpenFlow13",
        "dump-ports-desc", switch
    )
    cabeceras = list(re.finditer(
        r"(?m)^\s*(\d+)\(([^)]+)\):", texto
    ))
    resultado = {}

    for i, cabecera in enumerate(cabeceras):
        fin = (
            cabeceras[i + 1].start()
            if i + 1 < len(cabeceras)
            else len(texto)
        )
        bloque = texto[cabecera.end():fin]
        config = re.search(
            r"(?m)^\s*config:\s*(.+)$", bloque
        )
        estado = re.search(
            r"(?m)^\s*state:\s*(.+)$", bloque
        )

        if not config or not estado:
            raise RuntimeError(
                f"Estado incompleto: {switch}:{cabecera[1]}"
            )

        activo = (
            "PORT_DOWN" not in config[1]
            and "LINK_DOWN" not in estado[1]
        )

        resultado[int(cabecera[1])] = activo

    return resultado


def capacidad_tc(interfaz):
    texto = comando("tc", "class", "show", "dev", interfaz)

    raiz = next(
        (
            linea for linea in texto.splitlines()
            if "class htb " in linea and " root " in linea
        ),
        None
    )
    if raiz is None:
        raise RuntimeError(
            f"Sin clase HTB raiz en {interfaz}"
        )

    tasa = re.search(
        r"\bceil\s+([\d.]+)([kmg]?)bit\b",
        raiz,
        flags=re.IGNORECASE
    )
    if tasa is None:
        tasa = re.search(
            r"\brate\s+([\d.]+)([kmg]?)bit\b",
            raiz,
            flags=re.IGNORECASE
        )

    if tasa is None:
        raise RuntimeError(
            f"Capacidad no interpretable: {interfaz}"
        )

    factores = {
        "": 1,
        "k": 1000,
        "m": 1000000,
        "g": 1000000000,
    }

    capacidad = float(tasa[1]) * factores[tasa[2].lower()]

    if capacidad <= 0:
        raise RuntimeError(
            f"Capacidad invalida: {interfaz}"
        )

    return capacidad


def muestra_contador(switch, puerto):
    instante_a = time.monotonic()
    texto = comando(
        "ovs-ofctl", "-O", "OpenFlow13",
        "dump-ports", switch, str(puerto)
    )
    instante_b = time.monotonic()

    rx = re.search(
        r"\brx pkts=(\d+), bytes=(\d+)", texto
    )
    tx = re.search(
        r"\btx pkts=(\d+), bytes=(\d+)", texto
    )

    if not rx or not tx:
        raise RuntimeError(
            f"Contadores ausentes: {switch}:{puerto}"
        )

    return {
        "tiempo": (instante_a + instante_b) / 2,
        "rx_paquetes": int(rx[1]),
        "rx_bytes": int(rx[2]),
        "tx_paquetes": int(tx[1]),
        "tx_bytes": int(tx[2]),
    }


def identificador_fallo(registro):
    fallos = registro["enlaces_fallados_observados"]
    return {
        frozenset((e["extremo_a"], e["extremo_b"]))
        for e in fallos
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--intervalo", type=float, default=5.0
    )
    args = parser.parse_args()

    if args.intervalo < 1:
        raise RuntimeError(
            "Intervalo minimo: 1 segundo"
        )

    escenario = leer_json(
        BASE / "config/escenario.json"
    )
    inventario = leer_json(
        BASE / "resultados/etapa01/puertos_detectados.json"
    )
    fs = leer_json(DIR / "FS_postfallo.json")
    ps = leer_json(DIR / "PS_postfallo.json")

    switches = set(escenario["switches"])
    esperados = {
        frozenset(e)
        for e in escenario["enlaces"]
    }

    estados = {
        sw: estado_puertos(sw)
        for sw in sorted(switches)
    }

    direcciones = []
    observados = set()
    fallos = []

    for enlace in inventario:
        a, b = enlace["nodo_a"], enlace["nodo_b"]

        if a not in switches or b not in switches:
            continue

        par = frozenset((a, b))

        if par in observados or par not in esperados:
            raise RuntimeError(
                f"Enlace duplicado o inesperado: {a}-{b}"
            )
        observados.add(par)

        pa = int(enlace["puerto_a"])
        pb = int(enlace["puerto_b"])

        if pa not in estados[a] or pb not in estados[b]:
            raise RuntimeError(
                f"Puerto no encontrado: {a}-{b}"
            )

        activo_a = estados[a][pa]
        activo_b = estados[b][pb]

        if not (activo_a and activo_b):
            fallos.append({
                "extremo_a": a,
                "extremo_b": b,
                "puerto_a": pa,
                "puerto_b": pb,
                "activo_a": activo_a,
                "activo_b": activo_b,
            })

        for origen, destino, puerto in (
            (a, b, pa),
            (b, a, pb),
        ):
            interfaz = f"{origen}-eth{puerto}"
            direcciones.append({
                "origen": origen,
                "destino": destino,
                "puerto": puerto,
                "interfaz": interfaz,
                "activo": estados[origen][puerto],
                "capacidad_configurada_bps": capacidad_tc(
                    interfaz
                ),
            })

    if observados != esperados:
        raise RuntimeError(
            "El inventario no coincide con la topologia"
        )

    if len(fallos) != 1:
        raise RuntimeError(
            f"Se esperaba un fallo unico; observados: {fallos}"
        )

    fallo_actual = {
        frozenset((
            fallos[0]["extremo_a"],
            fallos[0]["extremo_b"],
        ))
    }

    if (
        identificador_fallo(fs) != fallo_actual
        or identificador_fallo(ps) != fallo_actual
    ):
        raise RuntimeError(
            "FS, PS y estado actual tienen fallos distintos"
        )

    print("\n=== RS POST-FAST-FAILOVER ===")
    print("Enlace fallado:", fallos[0])
    print("Enlaces fisicos:", len(observados))
    print("Direcciones de transmision:", len(direcciones))
    print(f"Midiendo durante {args.intervalo:g} segundos...")

    iniciales = {
        d["interfaz"]: muestra_contador(
            d["origen"], d["puerto"]
        )
        for d in direcciones
    }

    time.sleep(args.intervalo)

    finales = {
        d["interfaz"]: muestra_contador(
            d["origen"], d["puerto"]
        )
        for d in direcciones
    }

    estados_finales = {
        sw: estado_puertos(sw)
        for sw in sorted(switches)
    }

    if estados_finales != estados:
        raise RuntimeError(
            "Cambio de estado de puertos durante la medicion"
        )

    for d in direcciones:
        interfaz = d["interfaz"]
        ini = iniciales[interfaz]
        fin = finales[interfaz]

        dt = fin["tiempo"] - ini["tiempo"]
        delta_tx = fin["tx_bytes"] - ini["tx_bytes"]
        delta_rx = fin["rx_bytes"] - ini["rx_bytes"]

        if dt <= 0 or delta_tx < 0 or delta_rx < 0:
            raise RuntimeError(
                f"Contadores reiniciados o tiempo invalido: "
                f"{interfaz}"
            )

        tasa_tx = delta_tx * 8 / dt
        tasa_rx = delta_rx * 8 / dt

        capacidad = d["capacidad_configurada_bps"]
        operativa = capacidad if d["activo"] else 0

        d.update({
            "intervalo_real_s": round(dt, 6),
            "tx_bytes_inicial": ini["tx_bytes"],
            "tx_bytes_final": fin["tx_bytes"],
            "tx_bytes_delta": delta_tx,
            "rx_bytes_delta": delta_rx,
            "tx_paquetes_delta": (
                fin["tx_paquetes"] - ini["tx_paquetes"]
            ),
            "tasa_tx_bps": round(tasa_tx, 2),
            "tasa_rx_bps": round(tasa_rx, 2),
            "capacidad_operativa_bps": operativa,
            "utilizacion_pct": (
                round(100 * tasa_tx / capacidad, 4)
                if d["activo"] else None
            ),
            "capacidad_disponible_estimada_bps": (
                round(max(0, capacidad - tasa_tx), 2)
                if d["activo"] else 0
            ),
        })

    utilizaciones = [
        d["utilizacion_pct"]
        for d in direcciones
        if d["utilizacion_pct"] is not None
    ]

    registro = {
        "tipo": "RS_post_Fast_Failover",
        "fecha_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "fuente": (
            "Capacidad HTB de tc y diferencias de "
            "contadores OpenFlow 1.3"
        ),
        "nota": (
            "Utilizacion medida por sentido TX; "
            "disponibilidad estimada en la ventana. "
            "No representa demanda futura ni garantiza "
            "capacidad disponible bajo otra carga."
        ),
        "enlaces_fallados_observados": fallos,
        "cantidad_enlaces": len(observados),
        "cantidad_direcciones": len(direcciones),
        "intervalo_solicitado_s": args.intervalo,
        "maxima_utilizacion_observada_pct": (
            max(utilizaciones) if utilizaciones else None
        ),
        "direcciones": direcciones,
    }

    DIR.mkdir(parents=True, exist_ok=True)
    temporal = SALIDA.with_suffix(".json.tmp")
    temporal.write_text(
        json.dumps(registro, indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8"
    )
    temporal.replace(SALIDA)

    for d in direcciones:
        if not d["activo"]:
            print(
                f'{d["origen"].upper()} -> '
                f'{d["destino"].upper()}: CAIDO'
            )
        else:
            print(
                f'{d["origen"].upper()} -> '
                f'{d["destino"].upper()}: '
                f'{d["tasa_tx_bps"]/1e6:.3f} Mbps / '
                f'{d["capacidad_configurada_bps"]/1e6:g} Mbps '
                f'({d["utilizacion_pct"]:.2f}%)'
            )

    print(
        "\nMaxima utilizacion observada:",
        registro["maxima_utilizacion_observada_pct"],
        "%"
    )
    print("Consistencia con FS y PS: CORRECTA")
    print("Archivo generado:", SALIDA)


if __name__ == "__main__":
    main()
