
#!/usr/bin/env python3
"""Etapa 03 - Actividad 04: estimar carga de Targets."""

import json
import math
import time
from datetime import datetime, timezone
from pathlib import Path

from CalcularCaminos import (
    construir_grafo,
    verificar_estado_actual,
)
from RegistrarRS import capacidad_tc

BASE = Path(__file__).resolve().parents[1]
DIR = BASE / "resultados/etapa03"
SALIDA = DIR / "EstimacionCargaTargets.json"


def cargar(ruta):
    return json.loads(ruta.read_text(encoding="utf-8"))


def exigir(condicion, mensaje):
    if not condicion:
        raise RuntimeError(mensaje)


def main():
    inicio = time.perf_counter()

    topologia = cargar(DIR / "TopologiaPostFallo.json")
    targets = cargar(DIR / "TargetsCandidatos.json")
    demandas = cargar(DIR / "DemandasObservadas_iperf2.json")
    estado = cargar(
        BASE / "resultados/etapa02/EstadoPostFallo.json"
    )

    grafo = construir_grafo(topologia)
    verificar_estado_actual(topologia)

    fallo = frozenset(estado["enlace_fallado"])

    for registro in (targets, demandas):
        exigir(
            frozenset(registro["enlace_fallado"]) == fallo,
            "Los datos pertenecen a fallos diferentes"
        )

    exigir(
        {
            frozenset((e["extremo_a"], e["extremo_b"]))
            for e in topologia["enlaces_caidos"]
        } == {fallo},
        "Topologia y fallo inconsistentes"
    )

    hosts = {
        h["nombre"]: h["switch"]
        for h in topologia["hosts"]
    }

    pares = {
        (a, b)
        for a in hosts
        for b in hosts
        if a != b
    }

    fs = {
        (f["origen"], f["destino"]): f["ruta_seleccionada"]
        for f in estado["estado"]["FS"]["comunicaciones"]
    }

    exigir(
        len(fs) == len(pares) and set(fs) == pares,
        "FS incompleto o duplicado"
    )

    # Capacidades dirigidas obtenidas de la topologia
    # y comprobadas nuevamente contra tc.
    capacidades = {}

    for enlace in topologia["enlaces_operativos"]:
        a = enlace["extremo_a"]
        b = enlace["extremo_b"]

        for origen, destino, puerto, clave in (
            (a, b, enlace["puerto_a"], "capacidad_a_b_bps"),
            (b, a, enlace["puerto_b"], "capacidad_b_a_bps"),
        ):
            par = (origen, destino)

            exigir(
                par not in capacidades,
                f"Enlace dirigido duplicado: {par}"
            )

            capacidad = float(enlace[clave])
            actual = capacidad_tc(
                f"{origen}-eth{puerto}"
            )

            exigir(
                math.isclose(
                    capacidad, actual,
                    rel_tol=0.001
                ),
                f"Capacidad tc cambiada: {origen}->{destino}"
            )

            capacidades[par] = capacidad

    exigir(
        len(capacidades) ==
        2 * len(topologia["enlaces_operativos"]),
        "Capacidades incompletas"
    )

    # Las tasas son mediciones del emisor, no valores
    # asignados manualmente por el estimador.
    flujos = {}
    protocolos = {"TCP": 0, "UDP": 0}

    for flujo in demandas["flujos"]:
        par = (flujo["origen"], flujo["destino"])

        exigir(
            par in pares and par not in flujos,
            f"Flujo desconocido o duplicado: {par}"
        )

        protocolo = flujo["protocolo"]
        tasa = float(flujo["tasa_enviada_bps"])

        exigir(
            protocolo in protocolos
            and math.isfinite(tasa)
            and tasa >= 0,
            f"Medicion de demanda invalida: {par}"
        )

        exigir(
            float(flujo["duracion_real_s"]) > 0,
            f"Duracion invalida: {par}"
        )

        protocolos[protocolo] += 1
        flujos[par] = {
            "id": flujo["id"],
            "protocolo": protocolo,
            "tasa_enviada_bps": tasa,
            "tasa_solicitada_mbps": flujo[
                "tasa_solicitada_mbps"
            ],
            "tasa_recibida_udp_bps": flujo[
                "tasa_recibida_bps"
            ],
            "perdida_udp_pct": flujo[
                "perdida_udp_pct"
            ],
        }

    exigir(
        len(flujos) == demandas["cantidad_flujos"]
        and protocolos == {"TCP": 3, "UDP": 3},
        "Perfil experimental distinto de 3 TCP + 3 UDP"
    )

    exigir(
        len(targets["targets"]) ==
        targets["cantidad_targets"],
        "Cantidad de Targets inconsistente"
    )

    registros = []
    huellas = set()
    perfiles_carga = set()

    for target in targets["targets"]:
        identificador = target["id"]
        huella = target["hash_configuracion"]

        exigir(
            huella not in huellas,
            f"Target duplicado: {identificador}"
        )
        huellas.add(huella)

        cargas = {
            arco: 0.0
            for arco in capacidades
        }

        contribuciones = {
            arco: []
            for arco in capacidades
        }

        vistos = set()
        modificadas = 0

        for comunicacion in target["configuracion"]:
            par = (
                comunicacion["origen"],
                comunicacion["destino"]
            )
            ruta = comunicacion["ruta"]

            exigir(
                par in pares and par not in vistos,
                f"Comunicacion duplicada o invalida: {par}"
            )
            vistos.add(par)

            exigir(
                ruta[0] == par[0]
                and ruta[-1] == par[1]
                and ruta[1] == hosts[par[0]]
                and ruta[-2] == hosts[par[1]],
                f"Extremos incorrectos: {identificador}:{par}"
            )

            switches_ruta = ruta[1:-1]

            exigir(
                len(switches_ruta) ==
                len(set(switches_ruta)),
                f"Ruta con bucle: {identificador}:{par}"
            )

            es_fs = ruta == fs[par]

            exigir(
                comunicacion["es_ruta_fs"] == es_fs,
                f"Referencia FS incorrecta: {identificador}:{par}"
            )

            if not es_fs:
                modificadas += 1

            # Las comunicaciones fuera del perfil piloto
            # no aportan carga EN ESTA PRUEBA.
            tasa = (
                flujos[par]["tasa_enviada_bps"]
                if par in flujos else 0.0
            )

            for a, b in zip(
                switches_ruta,
                switches_ruta[1:]
            ):
                arco = (a, b)

                exigir(
                    b in grafo[a]
                    and arco in capacidades,
                    f"Enlace no operativo: {identificador}:{arco}"
                )

                cargas[arco] += tasa

                if par in flujos:
                    contribuciones[arco].append(
                        flujos[par]["id"]
                    )

        exigir(
            vistos == pares
            and len(vistos) ==
            target["cantidad_comunicaciones"],
            f"Target incompleto: {identificador}"
        )

        exigir(
            modificadas ==
            target["cantidad_rutas_modificadas"],
            f"Cantidad de cambios incorrecta: {identificador}"
        )

        if identificador == "T000":
            exigir(
                modificadas == 0,
                "T000 no coincide con FS"
            )

        enlaces = []

        for (a, b), capacidad in sorted(
            capacidades.items()
        ):
            carga = cargas[(a, b)]

            enlaces.append({
                "origen": a,
                "destino": b,
                "capacidad_bps": capacidad,
                "carga_estimada_bps": round(carga, 2),
                "utilizacion_estimada_pct": round(
                    carga / capacidad * 100, 6
                ),
                "flujos_contribuyentes": (
                    contribuciones[(a, b)]
                ),
            })

        # Dos Targets pueden diferir en rutas sin tráfico
        # y tener exactamente el mismo perfil de carga.
        firma_carga = tuple(
            round(cargas[a], 2)
            for a in sorted(capacidades)
        )
        perfiles_carga.add(firma_carga)

        registros.append({
            "target_id": identificador,
            "rutas_modificadas": modificadas,
            "direcciones_con_carga": sum(
                x["carga_estimada_bps"] > 0
                for x in enlaces
            ),
            "enlaces_dirigidos": enlaces,
        })

    exigir(
        len(registros) == targets["cantidad_targets"],
        "Faltan estimaciones de Targets"
    )

    duracion = time.perf_counter() - inicio

    resultado = {
        "tipo": "Estimacion_Carga_Targets_Piloto",
        "generado_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "enlace_fallado": sorted(fallo),
        "fuente_demandas": str(
            DIR / "DemandasObservadas_iperf2.json"
        ),
        "fuente_targets": str(
            DIR / "TargetsCandidatos.json"
        ),
        "modelo": (
            "Suma de tasas enviadas observadas por "
            "flujo sobre cada enlace dirigido del Target"
        ),
        "limitaciones": (
            "Estimacion piloto con seis flujos. No incluye "
            "sobrecarga de protocolos, retransmisiones "
            "adicionales, otras demandas ni efectos de "
            "congestion causados por un nuevo Target. "
            "Los registros FS-PS-RS originales no fueron "
            "capturados simultaneamente."
        ),
        "flujos_medidos": list(flujos.values()),
        "comunicaciones_sin_trafico_piloto": [
            list(par) for par in sorted(pares)
            if par not in flujos
        ],
        "cantidad_targets": len(registros),
        "perfiles_carga_diferentes": len(perfiles_carga),
        "direcciones_operativas": len(capacidades),
        "tiempo_estimacion_s": round(duracion, 6),
        "targets": registros,
    }

    SALIDA.parent.mkdir(parents=True, exist_ok=True)
    temporal = SALIDA.with_suffix(".json.tmp")
    temporal.write_text(
        json.dumps(
            resultado, indent=2, ensure_ascii=False
        ) + "\n",
        encoding="utf-8"
    )
    temporal.replace(SALIDA)

    print("\n=== ESTIMACION DE CARGA DE TARGETS ===")
    print("Fallo:", " - ".join(
        s.upper() for s in sorted(fallo)
    ))
    print("Flujos medidos:", len(flujos))
    print("TCP:", protocolos["TCP"],
          "| UDP:", protocolos["UDP"])
    print("Targets evaluados:", len(registros))
    print("Direcciones operativas:", len(capacidades))
    print(
        "Perfiles de carga diferentes:",
        len(perfiles_carga)
    )
    print(
        f"Tiempo de estimacion: {duracion:.6f} s"
    )
    print("Capacidades tc: VERIFICADAS")
    print("Factibilidad y Transitions: PENDIENTES")
    print("Archivo generado:", SALIDA)


if __name__ == "__main__":
    try:
        main()
    except (
        RuntimeError, ValueError, KeyError,
        OSError
    ) as error:
        raise SystemExit(f"ERROR: {error}")
