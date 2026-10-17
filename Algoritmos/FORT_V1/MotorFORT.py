
#!/usr/bin/env python3
"""FORT: busqueda adaptativa de Targets y presupuesto computacional.

Utiliza FS, PS, RS y demandas capturadas por AlgoritmoFORT.
La busqueda prioriza comunicaciones de enlaces criticos.

No ejecuta OpenFlow ni valida definitivamente las Transitions.
"""

import heapq
import json
import math
import os
import sys
import time

from datetime import datetime, timezone
from pathlib import Path

from os_ken.base import app_manager
from os_ken.lib import hub
from os_ken.ofproto import ofproto_v1_3


BASE = Path(__file__).resolve().parents[1]

ESTADOS = (
    BASE / "resultados/etapa06/fort_capturas_estado"
)

DECISIONES = (
    BASE / "resultados/etapa06/fort_decisiones"
)

# Limites de seguridad, no cantidad fija de Targets.
TIEMPO_MAX_S = float(
    os.environ.get("FORT_TIEMPO_MAX_S", "6")
)

EXPANSIONES_MAX = int(
    os.environ.get("FORT_EXPANSIONES_MAX", "20000")
)

DEMANDA_MINIMA_BPS = 1000000.0
EPS = 1e-7

if (
    not 0.5 <= TIEMPO_MAX_S <= 30
    or EXPANSIONES_MAX < 100
):
    raise RuntimeError(
        "Presupuestos FORT invalidos"
    )


def leer(ruta):
    return json.loads(
        ruta.read_text(encoding="utf-8")
    )


def guardar(ruta, datos):
    ruta.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporal = ruta.with_suffix(".tmp")

    temporal.write_text(
        json.dumps(
            datos,
            indent=2,
            ensure_ascii=False,
        ) + "\n",
        encoding="utf-8",
    )

    temporal.replace(ruta)


def ahora():
    return datetime.now(
        timezone.utc
    ).isoformat()


def arcos(ruta):
    return list(
        zip(ruta[1:-1], ruta[2:-1])
    )


def firma(rutas, pares):
    return tuple(
        tuple(rutas[p])
        for p in pares
    )


def medir(rutas, demandas, capacidades):
    cargas = {
        arco: 0.0
        for arco in capacidades
    }

    for par, ruta in rutas.items():
        for arco in arcos(ruta):
            if arco not in cargas:
                raise RuntimeError(
                    f"Enlace inoperativo: {par}, {arco}"
                )

            cargas[arco] += demandas[par]

    usos = {
        arco: cargas[arco] * 100.0 / capacidades[arco]
        for arco in capacidades
    }

    return (
        cargas,
        usos,
        max(usos.values(), default=0.0),
    )


def validar_ruta(ruta, par, hosts, grafo):
    if (
        len(ruta) < 3
        or ruta[0] != par[0]
        or ruta[-1] != par[1]
        or ruta[1] != hosts[par[0]]
        or ruta[-2] != hosts[par[1]]
    ):
        raise RuntimeError(
            f"Extremos invalidos: {par}"
        )

    switches = ruta[1:-1]

    if len(set(switches)) != len(switches):
        raise RuntimeError(
            f"Bucle en FS: {par}"
        )

    for a, b in zip(
        switches, switches[1:]
    ):
        if b not in grafo[a]:
            raise RuntimeError(
                f"Ruta FS usa enlace caido: {a}-{b}"
            )


def enumerar_caminos(
    grafo,
    origen,
    destino,
    plazo,
    contador,
):
    """Caminos simples progresivos, sin K fijo."""

    cola = [(0, (origen,))]

    while (
        cola
        and time.monotonic() < plazo
        and contador[0] < EXPANSIONES_MAX
    ):
        _, camino = heapq.heappop(
            cola
        )

        contador[0] += 1

        if camino[-1] == destino:
            yield list(camino)
            continue

        for vecino in sorted(
            grafo[camino[-1]]
        ):
            if vecino in camino:
                continue

            nuevo = camino + (vecino,)

            heapq.heappush(
                cola,
                (len(nuevo), nuevo),
            )


def domina(a, b):
    criterios = (
        "final_modelada_pct",
        "peak_modelada_pct",
        "saltos_cambiados",
    )

    return (
        all(
            a[k] <= b[k] + EPS
            for k in criterios
        )
        and any(
            a[k] < b[k] - EPS
            for k in criterios
        )
    )


def decidir_fort_dinamico(estado):
    inicio = time.monotonic()
    plazo_seguridad = inicio + TIEMPO_MAX_S

    ruta_herramientas = str(
        BASE / "herramientas"
    )

    if ruta_herramientas not in sys.path:
        sys.path.insert(
            0, ruta_herramientas
        )

    from CompararFSvsTargets import comparar_rutas

    escenario = leer(
        BASE / "config/escenario.json"
    )

    switches = set(
        escenario["switches"]
    )

    hosts = {
        h["nombre"]: h["switch"]
        for h in escenario["hosts"]
    }

    pares = sorted(
        (a, b)
        for a in hosts
        for b in hosts
        if a != b
    )

    fallo = frozenset(
        estado["fallo"].split("-")
    )

    enlaces = {
        frozenset(e)
        for e in escenario["enlaces"]
    }

    if (
        len(fallo) != 2
        or fallo not in enlaces
    ):
        raise RuntimeError(
            "Fallo no corresponde a la topologia"
        )

    grafo = {
        s: set()
        for s in switches
    }

    for a, b in escenario["enlaces"]:
        if frozenset((a, b)) != fallo:
            grafo[a].add(b)
            grafo[b].add(a)

    # FS de la captura actual.
    fs = {}

    for registro in estado["fs"]["comunicaciones"]:
        par = (
            registro["origen"],
            registro["destino"],
        )

        if par not in pares or par in fs:
            raise RuntimeError(
                f"FS duplicado o desconocido: {par}"
            )

        ruta = list(
            registro["ruta_seleccionada"]
        )

        validar_ruta(
            ruta, par, hosts, grafo
        )

        fs[par] = ruta

    if set(fs) != set(pares):
        raise RuntimeError(
            "FS no contiene las 12 comunicaciones"
        )

    # RS: capacidades por direccion.
    capacidades = {}
    observadas = {}

    for d in estado["rs"]["direcciones"]:
        arco = (
            d["origen"],
            d["destino"],
        )

        if arco in observadas:
            raise RuntimeError(
                "Direccion RS duplicada"
            )

        observadas[arco] = float(
            d["utilizacion_observada_pct"]
        )

        if not d["activo"]:
            continue

        capacidad = float(
            d["capacidad_configurada_bps"]
        )

        if (
            not math.isfinite(capacidad)
            or capacidad <= 0
        ):
            raise RuntimeError(
                f"Capacidad invalida: {arco}"
            )

        capacidades[arco] = capacidad

    esperados = {
        (a, b)
        for a in grafo
        for b in grafo[a]
    }

    if set(capacidades) != esperados:
        raise RuntimeError(
            "RS no coincide con topologia operativa"
        )

    # Demandas actuales.
    demandas = {}

    for d in estado["demandas"]["comunicaciones"]:
        par = (
            d["origen"],
            d["destino"],
        )

        tasa = float(
            d["tasa_ipv4_observada_bps"]
        )

        if (
            par not in pares
            or par in demandas
            or not math.isfinite(tasa)
            or tasa < 0
        ):
            raise RuntimeError(
                f"Demanda invalida: {par}"
            )

        demandas[par] = tasa

    if set(demandas) != set(pares):
        raise RuntimeError(
            "Demandas incompletas"
        )

    cargas_fs, uso_fs, mlu_fs = medir(
        fs, demandas, capacidades
    )

    mlu_observada = float(
        estado["rs"]["maxima_utilizacion_observada_pct"]
    )

    activos = [
        p for p in pares
        if demandas[p] > 0
    ]

    base = {
        "tipo": (
            "FORT_DECISION_DINAMICA_GUIADA_POR_CARGA"
        ),
        "generado_utc": ahora(),
        "fallo": sorted(fallo),
        "captura_origen_utc": estado["fecha_utc"],
        "captura_atomica": False,
        "mlu_fs_observada_pct": round(
            mlu_observada, 6
        ),
        "mlu_fs_modelada_pct": round(
            mlu_fs, 6
        ),
        "demanda_total_observada_bps": round(
            sum(demandas.values()), 3
        ),
        "mejora_real_observada_pct": None,
        "ejecucion_openflow_autorizada": False,
    }

    if (
        sum(demandas.values())
        < DEMANDA_MINIMA_BPS
    ):
        return {
            **base,
            "estado": "SIN_CARGA_SUFICIENTE",
            "targets_evaluados": 0,
            "pareja_preferida_modelo": None,
            "motivo_parada": "DEMANDA_INSUFICIENTE",
            "tiempo_busqueda_s": round(
                time.monotonic() - inicio, 6
            ),
        }

    # Identificar enlaces criticos y contribuyentes.
    prioritarios = []

    enlaces_ordenados = sorted(
        capacidades,
        key=lambda a: (
            -uso_fs[a],
            a,
        ),
    )

    for arco in enlaces_ordenados:
        contribuyentes = sorted(
            [
                p for p in activos
                if arco in arcos(fs[p])
            ],
            key=lambda p: (
                -demandas[p],
                p,
            ),
        )

        prioritarios.append({
            "origen": arco[0],
            "destino": arco[1],
            "utilizacion_modelada_pct": round(
                uso_fs[arco], 6
            ),
            "utilizacion_observada_pct": round(
                observadas.get(arco, 0), 6
            ),
            "comunicaciones_contribuyentes": [
                {
                    "origen": p[0],
                    "destino": p[1],
                    "demanda_bps": round(
                        demandas[p], 3
                    ),
                }
                for p in contribuyentes
            ],
        })

    # Caminos posibles sin limite K=5.
    contador = [0]
    opciones = {}
    rutas_por_par = {}

    for par in pares:
        if not demandas[par]:
            opciones[par] = [fs[par]]

        else:
            rutas = [
                [par[0], *camino, par[1]]
                for camino in enumerar_caminos(
                    grafo,
                    hosts[par[0]],
                    hosts[par[1]],
                    plazo_seguridad,
                    contador,
                )
            ]

            # Nunca perder la referencia FS.
            rutas.append(fs[par])

            opciones[par] = list(
                {
                    tuple(r): r
                    for r in rutas
                }.values()
            )

        nombre = (
            f"{par[0]}->{par[1]}"
        )

        rutas_por_par[nombre] = len(
            opciones[par]
        )

    alternativas = sum(
        max(0, len(opciones[p]) - 1)
        for p in activos
    )

    # PRESUPUESTO COMPUTACIONAL ADAPTATIVO.
    #
    # Urgencia: depende de la MLU de entrada.
    # Complejidad: alternativas efectivamente halladas.
    #
    # Formula provisional, pendiente de calibracion.
    urgencia = min(
        1.0,
        max(mlu_fs, mlu_observada) / 100.0,
    )

    complejidad = (
        1.0 - math.exp(-alternativas / 24.0)
    )

    fraccion = (
        0.55 * urgencia
        + 0.45 * complejidad
    )

    minimo = min(
        0.75,
        TIEMPO_MAX_S,
    )

    presupuesto_auto = min(
        TIEMPO_MAX_S,
        minimo
        + (TIEMPO_MAX_S - minimo) * fraccion,
    )

    plazo = min(
        plazo_seguridad,
        inicio + presupuesto_auto,
    )

    # El ancho depende de la complejidad descubierta.
    ancho_haz = min(
        32,
        max(
            2,
            math.ceil(
                math.sqrt(1 + alternativas)
            ),
        ),
    )

    caminos_truncados = (
        contador[0] >= EXPANSIONES_MAX
        or time.monotonic() >= plazo_seguridad
    )

    def evaluar(rutas, metodo, profundidad):
        cargas, usos, final = medir(
            rutas, demandas, capacidades
        )

        modificadas = [
            p for p in pares
            if rutas[p] != fs[p]
        ]

        diferencias = [
            comparar_rutas(
                p, fs[p], rutas[p]
            )
            for p in modificadas
        ]

        cambios = sum(
            len(d["diferencias_siguiente_salto"])
            for d in diferencias
        )

        # Transitions logicas: NO OpenFlow.
        variantes = []

        for modo, orden in (
            ("ASC", sorted(modificadas)),
            (
                "DESC",
                sorted(
                    modificadas,
                    reverse=True,
                ),
            ),
        ):
            parcial = dict(fs)
            serie = [mlu_fs]

            for par in orden:
                parcial[par] = rutas[par]

                mlu_parcial = medir(
                    parcial,
                    demandas,
                    capacidades,
                )[2]

                serie.append(
                    mlu_parcial
                )

            variantes.append({
                "orden": modo,
                "comunicaciones": [
                    f"{p[0]}->{p[1]}"
                    for p in orden
                ],
                "peak_modelada_pct": round(
                    max(serie), 6
                ),
                "serie_mlu_modelada_pct": [
                    round(v, 6)
                    for v in serie
                ],
                "validacion_openflow": "PENDIENTE",
            })

        variantes.sort(
            key=lambda v: (
                v["peak_modelada_pct"],
                v["orden"],
            )
        )

        elegida = variantes[0]

        return {
            "metodo": metodo,
            "profundidad": profundidad,
            "final_modelada_pct": round(
                final, 6
            ),
            "peak_modelada_pct": (
                elegida["peak_modelada_pct"]
            ),
            "saltos_cambiados": cambios,
            "rutas_modificadas": len(
                modificadas
            ),
            "comparacion_modelada_fs_pp": round(
                mlu_fs - final, 6
            ),
            "sobre_capacidad_modelada": (
                final > 100.0 + EPS
            ),
            "transitions_logicas": variantes,
            "transition_preferida_logica": (
                elegida["orden"]
            ),
            "configuracion": [
                {
                    "origen": p[0],
                    "destino": p[1],
                    "ruta": rutas[p],
                }
                for p in pares
            ],
            "diferencias_fs": diferencias,
            "carga_direcciones": [
                {
                    "origen": arco[0],
                    "destino": arco[1],
                    "carga_estimada_bps": round(
                        cargas[arco], 3
                    ),
                    "utilizacion_estimada_pct": round(
                        usos[arco], 6
                    ),
                }
                for arco in sorted(
                    capacidades
                )
            ],
            "_rutas": rutas,
            "_usos": usos,
        }

    # Referencia inicial.
    referencia = evaluar(
        dict(fs),
        "FS_REFERENCIA",
        0,
    )

    referencia["target_id"] = "T0000"

    evaluados = [referencia]
    visitados = {firma(fs, pares)}
    haz = [referencia]

    mejor = mlu_fs
    estancamiento = 0
    ampliado = False
    rondas = []

    motivo = "AGOTAMIENTO_DE_CANDIDATOS"

    instante_evaluaciones = (
        time.monotonic()
    )

    # BEAM SEARCH ADAPTATIVA.
    # No existe limite fijo de 1200 Targets.
    while haz:
        if time.monotonic() >= plazo:
            motivo = (
                "PRESUPUESTO_TIEMPO_ADAPTATIVO"
            )
            break

        fase = (
            "AMPLIADA"
            if ampliado
            else "ENLACES_CRITICOS"
        )

        nuevos = []

        for padre in haz:
            if time.monotonic() >= plazo:
                break

            rutas = padre["_rutas"]
            usos = padre["_usos"]

            maxima = max(
                usos.values(),
                default=0.0,
            )

            cuellos = {
                arco
                for arco, valor in usos.items()
                if abs(valor - maxima) <= EPS
            }

            afecta = [
                p for p in activos
                if any(
                    arco in cuellos
                    for arco in arcos(
                        rutas[p]
                    )
                )
            ]

            otros = [
                p for p in activos
                if p not in afecta
            ]

            orden = sorted(
                afecta,
                key=lambda p: (
                    -demandas[p],
                    p,
                ),
            )

            if ampliado:
                orden += sorted(
                    otros,
                    key=lambda p: (
                        -demandas[p],
                        p,
                    ),
                )

            for par in orden:
                for alternativa in opciones[par]:
                    if time.monotonic() >= plazo:
                        break

                    if alternativa == rutas[par]:
                        continue

                    candidato = dict(
                        rutas
                    )

                    candidato[par] = alternativa

                    clave = firma(
                        candidato, pares
                    )

                    if clave in visitados:
                        continue

                    visitados.add(
                        clave
                    )

                    nuevo = evaluar(
                        candidato,
                        fase,
                        padre["profundidad"] + 1,
                    )

                    nuevo["target_id"] = (
                        f"T{len(evaluados):05d}"
                    )

                    evaluados.append(
                        nuevo
                    )

                    nuevos.append(
                        nuevo
                    )

                    # Ceder tiempo al controlador OS-Ken.
                    if len(evaluados) % 32 == 0:
                        hub.sleep(0)

                if time.monotonic() >= plazo:
                    break

        if not nuevos:
            if not ampliado:
                ampliado = True

                rondas.append({
                    "fase": fase,
                    "nuevos": 0,
                    "accion": (
                        "AMPLIAR_COMUNICACIONES"
                    ),
                })

                continue

            motivo = (
                "SIN_NUEVAS_CONFIGURACIONES"
            )
            break

        nuevos.sort(
            key=lambda t: (
                t["final_modelada_pct"],
                t["rutas_modificadas"],
                t["saltos_cambiados"],
                t["target_id"],
            )
        )

        # Calcular la velocidad observada.
        transcurrido = max(
            1e-6,
            time.monotonic()
            - instante_evaluaciones,
        )

        velocidad_actual = max(
            1.0,
            (len(evaluados) - 1) / transcurrido,
        )

        # Estimar evaluaciones que caben en el
        # tiempo restante.
        restantes_estimadas = int(
            velocidad_actual
            * max(
                0.0,
                plazo - time.monotonic(),
            )
        )

        esfuerzo_por_padre = max(
            1,
            alternativas,
        )

        # Adaptar el ancho del haz segun CPU.
        ancho_efectivo = min(
            ancho_haz,
            max(
                2,
                restantes_estimadas
                // esfuerzo_por_padre,
            ),
        )

        haz = nuevos[:ancho_efectivo]

        mejor_ronda = nuevos[0][
            "final_modelada_pct"
        ]

        if mejor_ronda < mejor - EPS:
            mejor = mejor_ronda
            estancamiento = 0
        else:
            estancamiento += 1

        rondas.append({
            "fase": fase,
            "nuevos": len(nuevos),
            "mejor_mlu_modelada_pct": mejor_ronda,
            "mejor_mlu_historica_pct": mejor,
            "estancamiento_rondas": estancamiento,
            "evaluaciones_restantes_estimadas":
                restantes_estimadas,
            "ancho_haz_efectivo": ancho_efectivo,
        })

        if estancamiento >= 2:
            ampliado = True

        if ampliado and estancamiento >= 5:
            motivo = (
                "CONVERGENCIA_HEURISTICA_NO_CERTIFICADA"
            )
            break

    # Frontera Pareto entre Targets EXPLORADOS.
    candidatos = [
        t for t in evaluados
        if t["rutas_modificadas"] > 0
    ]

    candidatos.sort(
        key=lambda t: (
            t["final_modelada_pct"],
            t["peak_modelada_pct"],
            t["saltos_cambiados"],
            t["target_id"],
        )
    )

    frontera = []

    for candidato in candidatos:
        if time.monotonic() >= plazo_seguridad:
            motivo = (
                "LIMITE_SEGURIDAD_TOTAL"
            )
            break

        if any(
            domina(actual, candidato)
            for actual in frontera
        ):
            continue

        frontera = [
            actual
            for actual in frontera
            if not domina(
                candidato, actual
            )
        ]

        frontera.append(
            candidato
        )

    admisibles = [
        t for t in frontera
        if (
            not t["sobre_capacidad_modelada"]
            and t["final_modelada_pct"]
            < mlu_fs - EPS
        )
    ]

    ganador = min(
        admisibles,
        key=lambda t: (
            t["final_modelada_pct"],
            t["peak_modelada_pct"],
            t["saltos_cambiados"],
            t["target_id"],
        ),
        default=None,
    )

    duracion = (
        time.monotonic() - inicio
    )

    tiempo_evaluaciones = max(
        1e-9,
        time.monotonic()
        - instante_evaluaciones,
    )

    tasa_final = (
        len(evaluados)
        / tiempo_evaluaciones
    )

    # Retirar datos auxiliares internos.
    for target in evaluados:
        target.pop(
            "_rutas", None
        )

        target.pop(
            "_usos", None
        )

    respuesta = {
        **base,
        "estado": "DECISION_PRELIMINAR_MODELO",
        "metodo": (
            "BEAM_SEARCH_CUELLOS_BOTELLA_"
            "PRESUPUESTO_ADAPTATIVO"
        ),
        "presupuesto_calculado": {
            "tiempo_maximo_seguridad_s":
                TIEMPO_MAX_S,
            "tiempo_auto_asignado_s": round(
                presupuesto_auto, 6
            ),
            "utilizacion_maxima_entrada_pct": round(
                max(
                    mlu_fs,
                    mlu_observada,
                ), 6
            ),
            "comunicaciones_activas": len(
                activos
            ),
            "alternativas_descubiertas":
                alternativas,
            "indice_complejidad": round(
                complejidad, 6
            ),
            "indice_urgencia": round(
                urgencia, 6
            ),
            "ancho_haz_auto": ancho_haz,
            "evaluaciones_por_segundo_estimadas": round(
                tasa_final, 2
            ),
            "evaluaciones_realizadas": len(
                evaluados
            ),
        },
        "caminos_enumerados_por_comunicacion":
            rutas_por_par,
        "expansiones_de_caminos":
            contador[0],
        "exploracion_de_caminos_truncada":
            caminos_truncados,
        "enlaces_priorizados_fs":
            prioritarios,
        "rondas_busqueda": rondas,
        "motivo_parada": motivo,
        "tiempo_busqueda_s": round(
            duracion, 6
        ),
        "targets_evaluados": len(
            evaluados
        ),
        "candidatas_pareto": [
            t["target_id"]
            for t in frontera
        ],
        "hay_mejora_modelada": (
            ganador is not None
        ),
        "pareja_preferida_modelo": (
            {
                "target_id": ganador["target_id"],
                "transition_logica": (
                    ganador[
                        "transition_preferida_logica"
                    ]
                ),
                "final_mlu_modelada_pct": (
                    ganador[
                        "final_modelada_pct"
                    ]
                ),
                "peak_mlu_modelada_pct": (
                    ganador[
                        "peak_modelada_pct"
                    ]
                ),
                "mejora_modelada_fs_puntos_pct": (
                    ganador[
                        "comparacion_modelada_fs_pp"
                    ]
                ),
                "rutas_modificadas": (
                    ganador[
                        "rutas_modificadas"
                    ]
                ),
            }
            if ganador
            else None
        ),
        "limitaciones": [
            "Presupuesto adaptativo pendiente de calibracion",
            "Sin garantia del optimo global",
            "Targets y Transitions no instalados",
            "Peak MLU logico, no OpenFlow real",
            "Factibilidad y costo definitivo pendientes",
            "Captura FS/PS/RS no atomica",
            "Capacidades nominales; falta validar tc",
            "Mejora real requiere ejecutar y medir",
        ],
        "targets": evaluados,
    }

    if ganador is not None:
        respuesta["topologia_target_preferido"] = {
            "estado": "PROPUESTA_NO_INSTALADA",
            "enlace_fallado": sorted(
                fallo
            ),
            "enlaces_operativos": [
                sorted(e)
                for e in sorted(
                    enlaces - {fallo},
                    key=lambda e: tuple(
                        sorted(e)
                    ),
                )
            ],
            "rutas": ganador[
                "configuracion"
            ],
            "cargas_estimadas": ganador[
                "carga_direcciones"
            ],
        }

    return respuesta


class MotorFORT(app_manager.OSKenApp):
    OFP_VERSIONS = [
        ofproto_v1_3.OFP_VERSION
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(
            *args, **kwargs
        )

        # Evitar procesar ensayos antiguos.
        self.vistos = {
            p.name
            for p in ESTADOS.glob(
                "FORT_Estado_*.json"
            )
        }

        self.trabajador = hub.spawn(
            self.vigilar
        )

        print(
            "FORT MOTOR: presupuesto "
            "computacional ADAPTATIVO",
            flush=True,
        )

        print(
            "FORT MOTOR: ejecucion OpenFlow "
            "DESACTIVADA",
            flush=True,
        )

    def vigilar(self):
        while True:
            try:
                archivos = sorted(
                    ESTADOS.glob(
                        "FORT_Estado_*.json"
                    )
                )

                for archivo in archivos:
                    if archivo.name in self.vistos:
                        continue

                    try:
                        estado = leer(
                            archivo
                        )
                    except (
                        OSError,
                        ValueError,
                    ):
                        continue

                    self.vistos.add(
                        archivo.name
                    )

                    if estado.get("tipo") != (
                        "FORT_ESTADO_POST_FF_DINAMICO"
                    ):
                        continue

                    try:
                        respuesta = decidir_fort_dinamico(
                            estado
                        )

                        salida = (
                            DECISIONES
                            / archivo.name.replace(
                                "FORT_Estado_",
                                "FORT_Decision_",
                            )
                        )

                        guardar(
                            salida,
                            respuesta,
                        )

                        self.imprimir(
                            respuesta,
                            salida,
                        )

                    except Exception:
                        self.logger.exception(
                            "FORT: decision fallida en %s",
                            archivo,
                        )

            except Exception:
                self.logger.exception(
                    "FORT: supervisor de capturas"
                )

            hub.sleep(1)

    @staticmethod
    def imprimir(datos, archivo):
        print(
            "\n=== FORT: BUSQUEDA ADAPTATIVA ===",
            flush=True,
        )

        print(
            "Fallo:",
            "-".join(
                datos["fallo"]
            ).upper(),
            flush=True,
        )

        print(
            "MLU FF observada:",
            datos["mlu_fs_observada_pct"],
            "%",
            flush=True,
        )

        print(
            "MLU FF modelada:",
            datos["mlu_fs_modelada_pct"],
            "%",
            flush=True,
        )

        if datos["estado"] == (
            "SIN_CARGA_SUFICIENTE"
        ):
            print(
                "Sin carga: conservar FF",
                flush=True,
            )

        else:
            p = datos[
                "presupuesto_calculado"
            ]

            print(
                "Presupuesto AUTO:",
                p["tiempo_auto_asignado_s"],
                "s",
                flush=True,
            )

            print(
                "Velocidad medida:",
                p[
                    "evaluaciones_por_segundo_estimadas"
                ],
                "Targets/s",
                flush=True,
            )

            print(
                "Ancho de haz AUTO:",
                p["ancho_haz_auto"],
                flush=True,
            )

            print(
                "Targets evaluados:",
                datos["targets_evaluados"],
                flush=True,
            )

            print(
                "Alternativas descubiertas:",
                p["alternativas_descubiertas"],
                flush=True,
            )

            print(
                "Candidatos Pareto:",
                len(
                    datos["candidatas_pareto"]
                ),
                flush=True,
            )

            print(
                "Fin:",
                datos["motivo_parada"],
                "| Tiempo:",
                datos["tiempo_busqueda_s"],
                "s",
                flush=True,
            )

            print(
                "=== ENLACES CRITICOS EN FS ===",
                flush=True,
            )

            for e in datos[
                "enlaces_priorizados_fs"
            ][:3]:
                flujos = ", ".join(
                    f'{c["origen"]}->{c["destino"]}'
                    for c in e[
                        "comunicaciones_contribuyentes"
                    ]
                )

                print(
                    f'{e["origen"]}->{e["destino"]} '
                    f'| {e["utilizacion_modelada_pct"]}% '
                    f'| {flujos}',
                    flush=True,
                )

            preferido = datos[
                "pareja_preferida_modelo"
            ]

            if not preferido:
                print(
                    "Sin mejora modelada: conservar FF",
                    flush=True,
                )

            else:
                print(
                    "Target:",
                    preferido["target_id"],
                    flush=True,
                )

                print(
                    "Transition LOGICA:",
                    preferido["transition_logica"],
                    flush=True,
                )

                print(
                    "Final MLU MODELO:",
                    preferido[
                        "final_mlu_modelada_pct"
                    ],
                    "%",
                    flush=True,
                )

                print(
                    "Peak MLU MODELO:",
                    preferido[
                        "peak_mlu_modelada_pct"
                    ],
                    "%",
                    flush=True,
                )

                print(
                    "Mejora MODELO:",
                    preferido[
                        "mejora_modelada_fs_puntos_pct"
                    ],
                    "p.p.",
                    flush=True,
                )

                elegido = next(
                    t for t in datos["targets"]
                    if t["target_id"]
                    == preferido["target_id"]
                )

                print(
                    "=== RUTAS QUE CAMBIARIAN ===",
                    flush=True,
                )

                for d in elegido["diferencias_fs"]:
                    print(
                        f'{d["origen"]}->{d["destino"]}',
                        flush=True,
                    )

                    print(
                        " FS:",
                        " -> ".join(
                            d["ruta_fs"]
                        ),
                        flush=True,
                    )

                    print(
                        " Target:",
                        " -> ".join(
                            d["ruta_target"]
                        ),
                        flush=True,
                    )

        print(
            "Mejora REAL: PENDIENTE "
            "DE EJECUCION Y MEDICION",
            flush=True,
        )

        print(
            "OpenFlow: NO AUTORIZADO",
            flush=True,
        )

        print(
            "Archivo:",
            archivo,
            flush=True,
        )
