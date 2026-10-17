
#!/usr/bin/env python3
"""Reconstruye rutas usando reglas, grupos y puertos OpenFlow."""

import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]


def ejecutar(operacion, switch):
    return subprocess.check_output(
        ["ovs-ofctl", "-O", "OpenFlow13", operacion, switch],
        text=True,
        stderr=subprocess.STDOUT
    )


def leer_json(ruta):
    return json.loads(ruta.read_text(encoding="utf-8"))


def puerto_activo(switch, puerto):
    respuesta = ejecutar("dump-ports-desc", switch)

    cabeceras = list(re.finditer(
        r"(?m)^\s*(\d+)\(([^)]+)\):", respuesta
    ))

    for indice, cabecera in enumerate(cabeceras):
        numero, nombre = cabecera.groups()

        if puerto not in (numero, nombre):
            continue

        fin = (
            cabeceras[indice + 1].start()
            if indice + 1 < len(cabeceras)
            else len(respuesta)
        )

        bloque = respuesta[cabecera.end():fin]

        config = re.search(
            r"(?m)^\s*config:\s*(.+)$", bloque
        )
        estado = re.search(
            r"(?m)^\s*state:\s*(.+)$", bloque
        )

        if config is None or estado is None:
            raise RuntimeError(
                f"Estado de puerto desconocido: "
                f"{switch}:{puerto}"
            )

        return (
            "PORT_DOWN" not in config[1]
            and "LINK_DOWN" not in estado[1]
        )

    raise RuntimeError(
        f"Puerto no encontrado: {switch}:{puerto}"
    )


def buscar_regla(switch, origen, destino, vlan):
    candidatas = []

    for linea in ejecutar(
        "dump-flows", switch
    ).splitlines():

        if ",ip," not in linea or " actions=" not in linea:
            continue

        if (
            f"nw_src={origen}" not in linea
            or f"nw_dst={destino}" not in linea
        ):
            continue

        coincidencia = re.search(
            r"\bdl_vlan=(\d+)", linea
        )

        etiqueta = (
            int(coincidencia[1])
            if coincidencia else None
        )

        if etiqueta != vlan:
            continue

        prioridad = re.search(
            r"\bpriority=(\d+)", linea
        )

        if prioridad:
            acciones = linea.split(
                " actions=", 1
            )[1]

            candidatas.append(
                (int(prioridad[1]), acciones)
            )

    if not candidatas:
        raise RuntimeError(
            f"Sin regla en {switch}, VLAN={vlan}"
        )

    return max(candidatas, key=lambda x: x[0])[1]


def bucket_activo(switch, identificador):
    respuesta = ejecutar("dump-groups", switch)

    grupo = next(
        (
            linea
            for linea in respuesta.splitlines()
            if re.search(
                rf"\bgroup_id={identificador}(?:,|$)",
                linea
            )
        ),
        None
    )

    if grupo is None or "type=ff" not in grupo:
        raise RuntimeError(
            f"Grupo FF inexistente: "
            f"{switch}:{identificador}"
        )

    buckets = grupo.split(",bucket=")[1:]

    for indice, bucket in enumerate(buckets):
        if "actions=" not in bucket:
            raise RuntimeError("Bucket sin acciones")

        datos, acciones = bucket.split(
            "actions=", 1
        )

        match = re.search(
            r'watch_port:(?:"([^"]+)"|([^,]+))',
            datos
        )

        if match is None:
            raise RuntimeError(
                "Bucket sin watch_port"
            )

        puerto = match[1] or match[2]

        if puerto_activo(switch, puerto):
            return acciones, indice, puerto

    raise RuntimeError(
        f"Sin bucket activo: {switch}:{identificador}"
    )


def interpretar_acciones(
    switch, acciones, vlan, grupos, profundidad=0
):
    if profundidad > 4:
        raise RuntimeError(
            "Demasiados grupos encadenados"
        )

    salida = None

    # Respetar el orden de las acciones OpenFlow.
    for accion in acciones.split(","):
        accion = accion.strip()

        if accion == "pop_vlan":
            vlan = None

        elif accion.startswith("push_vlan:"):
            pass

        elif accion.startswith("set_field:"):
            match = re.fullmatch(
                r"set_field:(\d+)->vlan_vid",
                accion
            )

            if not match:
                raise RuntimeError(
                    f"Accion no soportada: {accion}"
                )

            vlan = int(match[1]) & 0xFFF

        elif accion.startswith("group:"):
            identificador = int(
                accion.split(":", 1)[1]
            )

            acciones_bucket, indice, puerto = (
                bucket_activo(
                    switch, identificador
                )
            )

            modo = (
                "PRINCIPAL"
                if indice == 0
                else "RESPALDO"
            )

            grupos.append(
                f"{switch.upper()} - Grupo "
                f"{identificador}: {modo} "
                f"(watch_port={puerto})"
            )

            salida, vlan = interpretar_acciones(
                switch,
                acciones_bucket,
                vlan,
                grupos,
                profundidad + 1
            )

        elif accion.startswith("output:"):
            match = re.fullmatch(
                r'output:(?:"([^"]+)"|(\d+))',
                accion
            )

            if match is None:
                raise RuntimeError(
                    f"Salida invalida: {accion}"
                )

            salida = match[1] or match[2]

        else:
            raise RuntimeError(
                f"Accion no reconocida: {accion}"
            )

    if salida is None:
        raise RuntimeError(
            f"Sin salida en {switch}"
        )

    return salida, vlan


def mostrar_ruta(origen, destino):
    escenario = leer_json(
        BASE / "config/escenario.json"
    )

    inventario = leer_json(
        BASE / "resultados/etapa01/puertos_detectados.json"
    )

    hosts = {
        h["nombre"]: h
        for h in escenario["hosts"]
    }

    if (
        origen not in hosts
        or destino not in hosts
        or origen == destino
    ):
        raise RuntimeError("Hosts invalidos")

    ip_a = str(
        ipaddress.ip_interface(
            hosts[origen]["ip"]
        ).ip
    )

    ip_b = str(
        ipaddress.ip_interface(
            hosts[destino]["ip"]
        ).ip
    )

    vecinos = {}

    for enlace in inventario:
        extremos = [
            (
                enlace["nodo_a"],
                enlace["nodo_b"],
                enlace["puerto_a"]
            ),
            (
                enlace["nodo_b"],
                enlace["nodo_a"],
                enlace["puerto_b"]
            )
        ]

        for nodo, vecino, puerto in extremos:
            if nodo not in escenario["switches"]:
                continue

            vecinos[(nodo, str(puerto))] = vecino
            vecinos[
                (nodo, f"{nodo}-eth{puerto}")
            ] = vecino

    switch = hosts[origen]["switch"]
    camino = [origen, switch]
    vlan = None
    visitados = set()
    grupos = []

    for _ in range(32):
        estado = (switch, vlan)

        if estado in visitados:
            raise RuntimeError(
                f"Bucle detectado en {switch}"
            )

        visitados.add(estado)

        acciones = buscar_regla(
            switch, ip_a, ip_b, vlan
        )

        puerto, vlan = interpretar_acciones(
            switch, acciones, vlan, grupos
        )

        vecino = vecinos.get(
            (switch, puerto)
        )

        if vecino is None:
            raise RuntimeError(
                f"Puerto desconocido: "
                f"{switch}:{puerto}"
            )

        camino.append(vecino)

        if vecino == destino:
            print(
                f"\nFLUJO: {origen.upper()} "
                f"-> {destino.upper()}"
            )

            print(
                "RUTA SELECCIONADA: "
                + " -> ".join(
                    nodo.upper()
                    for nodo in camino
                )
            )

            for grupo in grupos:
                print(grupo)

            print(
                "Fuente: reglas OpenFlow, grupos FF "
                "y estado de puertos OVS.\n"
            )
            return

        if vecino not in escenario["switches"]:
            raise RuntimeError(
                f"Destino inesperado: {vecino}"
            )

        switch = vecino

    raise RuntimeError(
        "Limite de saltos excedido"
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(
            "Uso: MostrarRuta.py h1 h2"
        )

    try:
        mostrar_ruta(
            sys.argv[1].lower(),
            sys.argv[2].lower()
        )

    except (
        RuntimeError,
        OSError,
        ValueError,
        KeyError,
        subprocess.CalledProcessError
    ) as error:
        sys.exit(f"ERROR: {error}")
