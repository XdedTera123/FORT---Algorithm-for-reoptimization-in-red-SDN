
#!/usr/bin/env python3
"""Etapa 02 - Actividad 03: registro de PS desde Open vSwitch."""

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SALIDA = BASE / "resultados/etapa02/PS_postfallo.json"


def consultar(switch, operacion):
    proceso = subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", operacion, switch],
        capture_output=True,
        text=True,
        check=True,
    )
    return proceso.stdout


def leer_json(ruta):
    return json.loads(ruta.read_text(encoding="utf-8"))


def obtener_puertos(switch):
    texto = consultar(switch, "dump-ports-desc")

    patrones = list(re.finditer(
        r"(?m)^\s*(\d+)\(([^)]+)\):", texto
    ))

    mapa = {}
    registros = []

    for i, patron in enumerate(patrones):
        fin = (
            patrones[i + 1].start()
            if i + 1 < len(patrones)
            else len(texto)
        )

        bloque = texto[patron.end():fin]
        configuracion = re.search(
            r"(?m)^\s*config:\s*(.+)$", bloque
        )
        estado = re.search(
            r"(?m)^\s*state:\s*(.+)$", bloque
        )

        if not configuracion or not estado:
            raise RuntimeError(
                f"Estado incompleto en {switch}: {patron[2]}"
            )

        config = configuracion[1].strip()
        state = estado[1].strip()

        registro = {
            "numero": int(patron[1]),
            "nombre": patron[2],
            "config": config,
            "state": state,
            "activo": (
                "PORT_DOWN" not in config
                and "LINK_DOWN" not in state
            ),
        }

        mapa[patron[1]] = registro
        mapa[patron[2]] = registro
        registros.append(registro)

    if not registros:
        raise RuntimeError(
            f"No se detectaron puertos en {switch}"
        )

    return mapa, registros


def obtener_grupos(switch, puertos):
    texto = consultar(switch, "dump-groups")
    grupos = []

    for linea in texto.splitlines():
        encabezado = re.search(
            r"\bgroup_id=(\d+),type=([a-z]+)", linea
        )

        if not encabezado:
            continue

        if encabezado[2] != "ff":
            continue

        partes = linea.split(",bucket=")
        buckets = []

        if len(partes) < 2:
            raise RuntimeError(
                f"Grupo sin buckets: {switch}:{encabezado[1]}"
            )

        for indice, segmento in enumerate(partes[1:]):
            if ",actions=" not in segmento:
                raise RuntimeError(
                    f"Bucket sin acciones en {switch}"
                )

            atributos, acciones = segmento.split(
                ",actions=", 1
            )

            vigilado = re.search(
                r'watch_port:(?:"([^"]+)"|([^,]+))',
                atributos
            )

            if not vigilado:
                raise RuntimeError(
                    f"Bucket sin watch_port en {switch}"
                )

            nombre_puerto = vigilado[1] or vigilado[2]
            puerto = puertos.get(nombre_puerto)

            if puerto is None:
                raise RuntimeError(
                    f"Puerto vigilado desconocido: "
                    f"{switch}:{nombre_puerto}"
                )

            buckets.append({
                "indice": indice,
                "watch_port": nombre_puerto,
                "puerto_activo": puerto["activo"],
                "config_puerto": puerto["config"],
                "estado_puerto": puerto["state"],
                "acciones": acciones.strip(),
            })

        seleccionado = next(
            (
                b["indice"]
                for b in buckets
                if b["puerto_activo"]
            ),
            None
        )

        grupos.append({
            "group_id": int(encabezado[1]),
            "tipo": "ff",
            "buckets": buckets,
            "bucket_seleccionado_inferido": seleccionado,
            "modo_inferido": (
                "sin_bucket_activo"
                if seleccionado is None
                else "principal"
                if seleccionado == 0
                else "respaldo"
            ),
        })

    return grupos


def obtener_reglas_proteccion(switch):
    texto = consultar(switch, "dump-flows")
    reglas = []

    for linea in texto.splitlines():
        if " actions=" not in linea:
            continue

        izquierda, acciones = linea.split(
            " actions=", 1
        )

        prioridad = re.search(
            r"\bpriority=(\d+)", izquierda
        )

        referencias = [
            int(numero)
            for numero in re.findall(
                r"\bgroup:(\d+)", acciones
            )
        ]

        usa_vlan = (
            "dl_vlan=" in izquierda
            or "vlan_tci=" in izquierda
            or "push_vlan:" in acciones
            or "pop_vlan" in acciones
        )

        if not referencias and not usa_vlan:
            continue

        if not prioridad:
            raise RuntimeError(
                f"Regla de proteccion sin prioridad: {switch}"
            )

        reglas.append({
            "prioridad": int(prioridad[1]),
            "coincidencia": izquierda[
                prioridad.start():
            ].strip(),
            "acciones": acciones.strip(),
            "grupos_referenciados": referencias,
            "usa_vlan": usa_vlan,
        })

    return reglas


def identificar_fallo(escenario, inventario, datos):
    esperados = {
        frozenset(enlace)
        for enlace in escenario["enlaces"]
    }

    observados = set()
    fallados = []

    for enlace in inventario:
        a = enlace["nodo_a"]
        b = enlace["nodo_b"]

        if a not in datos or b not in datos:
            continue

        par = frozenset((a, b))

        if par not in esperados or par in observados:
            raise RuntimeError(
                f"Enlace inesperado o duplicado: {a}-{b}"
            )

        observados.add(par)

        pa = datos[a]["mapa"].get(
            str(enlace["puerto_a"])
        )
        pb = datos[b]["mapa"].get(
            str(enlace["puerto_b"])
        )

        if pa is None or pb is None:
            raise RuntimeError(
                f"Puerto inexistente en enlace {a}-{b}"
            )

        if not (pa["activo"] and pb["activo"]):
            fallados.append({
                "extremo_a": a,
                "extremo_b": b,
                "puerto_a": enlace["puerto_a"],
                "puerto_b": enlace["puerto_b"],
                "activo_a": pa["activo"],
                "activo_b": pb["activo"],
            })

    if observados != esperados:
        raise RuntimeError(
            "Inventario de enlaces incompleto"
        )

    if len(fallados) != 1:
        raise RuntimeError(
            "Se esperaba un unico enlace fallado; "
            f"se detectaron {len(fallados)}: {fallados}"
        )

    return fallados


def main():
    escenario = leer_json(
        BASE / "config/escenario.json"
    )
    inventario = leer_json(
        BASE / "resultados/etapa01/puertos_detectados.json"
    )

    datos = {}

    for switch in escenario["switches"]:
        mapa, lista = obtener_puertos(switch)

        datos[switch] = {
            "mapa": mapa,
            "puertos": lista,
            "grupos": obtener_grupos(switch, mapa),
            "reglas": obtener_reglas_proteccion(switch),
        }

    fallados = identificar_fallo(
        escenario, inventario, datos
    )

    registro_switches = {}
    total_grupos = 0
    total_buckets = 0
    total_reglas = 0

    for switch, contenido in datos.items():
        ids_grupos = {
            grupo["group_id"]
            for grupo in contenido["grupos"]
        }

        for regla in contenido["reglas"]:
            for referencia in regla["grupos_referenciados"]:
                if referencia not in ids_grupos:
                    raise RuntimeError(
                        f"Referencia a grupo inexistente: "
                        f"{switch}:{referencia}"
                    )

        grupos = contenido["grupos"]
        reglas = contenido["reglas"]

        total_grupos += len(grupos)
        total_buckets += sum(
            len(g["buckets"]) for g in grupos
        )
        total_reglas += len(reglas)

        registro_switches[switch] = {
            "puertos": contenido["puertos"],
            "grupos_fast_failover": grupos,
            "reglas_openflow_proteccion": reglas,
        }

    if total_grupos == 0:
        raise RuntimeError(
            "No se encontraron grupos Fast Failover"
        )

    resultado = {
        "tipo": "PS_post_Fast_Failover",
        "fecha_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "fuente": (
            "OpenFlow 1.3: dump-groups, "
            "dump-ports-desc y dump-flows"
        ),
        "nota": (
            "El bucket seleccionado se infiere "
            "del orden de buckets FF y del estado "
            "observado de los puertos."
        ),
        "enlaces_fallados_observados": fallados,
        "cantidad_switches": len(datos),
        "cantidad_grupos_ff": total_grupos,
        "cantidad_buckets_ff": total_buckets,
        "cantidad_reglas_proteccion": total_reglas,
        "switches": registro_switches,
    }

    SALIDA.parent.mkdir(
        parents=True, exist_ok=True
    )

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

    print("\n=== PS POST-FAST-FAILOVER ===")
    print("Enlace fallado:", fallados[0])
    print("Switches consultados:", len(datos))
    print("Grupos FF registrados:", total_grupos)
    print("Buckets FF registrados:", total_buckets)
    print(
        "Reglas de proteccion registradas:",
        total_reglas
    )

    for switch, contenido in registro_switches.items():
        grupos = contenido["grupos_fast_failover"]

        principales = sum(
            g["modo_inferido"] == "principal"
            for g in grupos
        )
        respaldos = sum(
            g["modo_inferido"] == "respaldo"
            for g in grupos
        )

        print(
            f"{switch.upper()}: {len(grupos)} FF, "
            f"{principales} principal, "
            f"{respaldos} respaldo"
        )

    print("\nArchivo generado:", SALIDA)


if __name__ == "__main__":
    main()
