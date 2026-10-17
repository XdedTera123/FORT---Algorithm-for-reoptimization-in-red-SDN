
#!/usr/bin/env python3
# Etapa 02 - Actividad 02
# Registro del forwarding seleccionado post-Fast-Failover.

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path

from MostrarRuta import (
    leer_json,
    buscar_regla,
    interpretar_acciones,
    puerto_activo,
)

BASE = Path(__file__).resolve().parents[1]
CONFIG = BASE / "config" / "escenario.json"
INVENTARIO = (
    BASE / "resultados" / "etapa01"
    / "puertos_detectados.json"
)
SALIDA = (
    BASE / "resultados" / "etapa02"
    / "FS_postfallo.json"
)


def preparar_escenario():
    escenario = leer_json(CONFIG)
    inventario = leer_json(INVENTARIO)

    switches = set(escenario["switches"])
    hosts = {
        h["nombre"]: {
            "switch": h["switch"],
            "ip": str(
                ipaddress.ip_interface(h["ip"]).ip
            )
        }
        for h in escenario["hosts"]
    }

    puertos = {}
    vecinos = {}
    enlaces_reales = set()

    for enlace in inventario:
        a = enlace["nodo_a"]
        b = enlace["nodo_b"]
        enlaces_reales.add(frozenset((a, b)))

        for sw, vecino, puerto in (
            (a, b, enlace["puerto_a"]),
            (b, a, enlace["puerto_b"])
        ):
            if sw not in switches:
                continue

            puertos[(sw, vecino)] = puerto
            vecinos[(sw, str(puerto))] = vecino
            vecinos[
                (sw, f"{sw}-eth{puerto}")
            ] = vecino

    enlaces_esperados = {
        frozenset(e)
        for e in escenario["enlaces"]
    }

    enlaces_esperados.update(
        frozenset((h, datos["switch"]))
        for h, datos in hosts.items()
    )

    if (
        enlaces_reales != enlaces_esperados
        or len(inventario) != len(enlaces_esperados)
    ):
        raise RuntimeError(
            "Inventario inconsistente con escenario.json"
        )

    return escenario, hosts, puertos, vecinos


def detectar_fallos(escenario, puertos):
    fallados = []

    for a, b in escenario["enlaces"]:
        pa = puertos[(a, b)]
        pb = puertos[(b, a)]

        activo_a = puerto_activo(a, str(pa))
        activo_b = puerto_activo(b, str(pb))

        if not (activo_a and activo_b):
            fallados.append({
                "extremo_a": a,
                "extremo_b": b,
                "puerto_a": pa,
                "puerto_b": pb,
                "activo_a": activo_a,
                "activo_b": activo_b
            })

    return fallados


def reconstruir_flujo(
    origen, destino, hosts, vecinos, switches
):
    ip_origen = hosts[origen]["ip"]
    ip_destino = hosts[destino]["ip"]

    actual = hosts[origen]["switch"]
    vlan = None

    ruta = [origen, actual]
    pasos = []
    grupos = []
    visitados = set()

    for _ in range(32):
        estado = (actual, vlan)

        if estado in visitados:
            raise RuntimeError(
                f"Bucle en {origen}->{destino}: {estado}"
            )

        visitados.add(estado)

        acciones = buscar_regla(
            actual, ip_origen, ip_destino, vlan
        )

        vlan_entrada = vlan
        inicio_grupos = len(grupos)

        puerto, vlan = interpretar_acciones(
            actual, acciones, vlan, grupos
        )

        siguiente = vecinos.get((actual, puerto))

        if siguiente is None:
            raise RuntimeError(
                f"Puerto sin vecino: {actual}:{puerto}"
            )

        if not puerto_activo(actual, puerto):
            raise RuntimeError(
                f"Puerto de salida caido: {actual}:{puerto}"
            )

        pasos.append({
            "switch": actual,
            "vlan_entrada": vlan_entrada,
            "acciones_openflow": acciones,
            "puerto_salida": puerto,
            "siguiente_nodo": siguiente,
            "vlan_salida": vlan,
            "grupos_ff": grupos[inicio_grupos:]
        })

        ruta.append(siguiente)

        if siguiente == destino:
            return {
                "origen": origen,
                "destino": destino,
                "ip_origen": ip_origen,
                "ip_destino": ip_destino,
                "ruta_seleccionada": ruta,
                "grupos_ff": grupos,
                "pasos_openflow": pasos
            }

        if siguiente not in switches:
            raise RuntimeError(
                f"Salida inesperada hacia {siguiente}"
            )

        actual = siguiente

    raise RuntimeError(
        f"Demasiados saltos: {origen}->{destino}"
    )


def main():
    escenario, hosts, puertos, vecinos = (
        preparar_escenario()
    )

    fallados = detectar_fallos(escenario, puertos)

    if len(fallados) != 1:
        raise RuntimeError(
            "Se esperaba un unico enlace fallado; "
            f"se detectaron {len(fallados)}: {fallados}"
        )

    flujos = []

    for origen in sorted(hosts):
        for destino in sorted(hosts):
            if origen == destino:
                continue

            flujo = reconstruir_flujo(
                origen,
                destino,
                hosts,
                vecinos,
                set(escenario["switches"])
            )

            flujos.append(flujo)

    registro = {
        "tipo": "FS_post_Fast_Failover",
        "fecha_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "fuente": (
            "Reglas y grupos OpenFlow 1.3; "
            "estado de puertos Open vSwitch"
        ),
        "interpretacion": (
            "Caminos seleccionados reconstruidos; "
            "no equivalen por si solos a mediciones "
            "de demanda o throughput"
        ),
        "enlaces_fallados_observados": fallados,
        "cantidad_comunicaciones": len(flujos),
        "comunicaciones": flujos
    }

    SALIDA.parent.mkdir(
        parents=True, exist_ok=True
    )

    SALIDA.write_text(
        json.dumps(
            registro,
            indent=2,
            ensure_ascii=False
        ) + "\n",
        encoding="utf-8"
    )

    print("\n=== FS POST-FAST-FAILOVER ===")
    print("Enlaces fallados:", fallados)
    print("Comunicaciones:", len(flujos))

    for flujo in flujos:
        print(
            f'{flujo["origen"].upper()} -> '
            f'{flujo["destino"].upper()}: '
            + " -> ".join(
                n.upper()
                for n in flujo["ruta_seleccionada"]
            )
        )

    print("\nArchivo generado:", SALIDA)


if __name__ == "__main__":
    main()
