
#!/usr/bin/env python3
"""FORT: evaluacion preliminar dinamica Target-Transition (etapas 04-05).

Lee decisiones del MotorFORT y su captura OpenFlow correspondiente.
Reutiliza el comparador de rutas y la dominancia Pareto existentes.
NO construye mensajes OpenFlow ejecutables ni modifica OVS.
"""

import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

from os_ken.base import app_manager
from os_ken.lib import hub
from os_ken.ofproto import ofproto_v1_3

BASE = Path(__file__).resolve().parents[1]
CAPTURAS = BASE / "resultados/etapa06/fort_capturas_estado"
DECISIONES = BASE / "resultados/etapa06/fort_decisiones"
PLANES = BASE / "resultados/etapa06/fort_planes"

sys.path.insert(0, str(BASE / "herramientas"))

from CompararFSvsTargets import comparar_rutas
from SeleccionarPareja import domina, clave_prioridad


def leer(ruta):
    return json.loads(ruta.read_text(encoding="utf-8"))


def guardar(ruta, datos):
    ruta.parent.mkdir(parents=True, exist_ok=True)
    temporal = ruta.with_suffix(".json.tmp")
    temporal.write_text(
        json.dumps(datos, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporal.replace(ruta)


def exigir(condicion, mensaje):
    if not condicion:
        raise RuntimeError(mensaje)


def mapa_puertos(inventario):
    puertos = {}

    for e in inventario:
        a, b = e["nodo_a"], e["nodo_b"]

        for origen, destino, numero in (
            (a, b, e["puerto_a"]),
            (b, a, e["puerto_b"]),
        ):
            clave = (origen, destino)

            exigir(
                clave not in puertos,
                f"Puerto duplicado: {clave}",
            )

            puertos[clave] = int(numero)

    return puertos


def arcos(ruta):
    return zip(ruta[1:-1], ruta[2:-1])


def calcular_mlu(rutas, demandas, capacidad):
    carga = dict.fromkeys(capacidad, 0.0)

    for par, ruta in rutas.items():
        for arco in arcos(ruta):
            exigir(
                arco in carga,
                f"Arco inoperativo en {par}: {arco}",
            )

            carga[arco] += demandas[par]

    return max(
        (
            100.0 * carga[a] / capacidad[a]
            for a in carga
        ),
        default=0.0,
    )


def validar_ruta(ruta, par, mapa, enlaces):
    exigir(
        isinstance(ruta, list) and len(ruta) >= 3,
        f"Ruta incompleta: {par}",
    )

    exigir(
        ruta[0] == par[0] and ruta[-1] == par[1],
        f"Extremos invalidos: {par}",
    )

    exigir(
        len(ruta) == len(set(ruta)),
        f"Bucle: {par}",
    )

    exigir(
        all(
            (a, b) in mapa
            for a, b in zip(ruta, ruta[1:])
        ),
        f"Enlace sin puerto en inventario: {par}",
    )

    exigir(
        all(
            arco in enlaces
            for arco in arcos(ruta)
        ),
        f"Enlace no operativo: {par}",
    )


def planes_de_cambio(
    fs, target, puertos, capacidades, grupos
):
    """Plan preliminar. No autoriza mensajes OpenFlow."""

    diferencias = []
    bloqueos = []
    switches = set()

    flowmods = 0
    grupos_nuevos = 0
    barreras = 0

    for par in sorted(fs):
        if fs[par] == target[par]:
            continue

        viejo = fs[par]
        nuevo = target[par]

        dif = comparar_rutas(
            par, viejo, nuevo
        )

        ingreso = nuevo[1]

        if nuevo[2] == viejo[2]:
            bloqueos.append(
                f"{par[0]}->{par[1]}: "
                "primer salto compartido; "
                "requiere mecanismo adicional de activacion"
            )

        puerto_fs = puertos[
            (ingreso, viejo[2])
        ]

        puerto_nuevo = puertos[
            (ingreso, nuevo[2])
        ]

        grupos_ingreso = sorted(
            gid
            for sw, gid in grupos
            if sw == ingreso
        )

        # Identificar el sufijo comun para estimar
        # que tramo requiere preparacion.
        i = len(viejo) - 1
        j = len(nuevo) - 1

        while (
            i >= 0
            and j >= 0
            and viejo[i] == nuevo[j]
        ):
            i -= 1
            j -= 1

        comienzo = j + 1

        if (
            comienzo > 1
            and nuevo[comienzo].startswith("s")
        ):
            ultimo = comienzo
        else:
            ultimo = len(nuevo) - 2

        preparar = nuevo[2:ultimo + 1]

        switches.update(preparar)
        switches.add(ingreso)

        # Estimaciones basadas en la estructura
        # de operaciones del prototipo de Etapa 04.
        #
        # No equivalen a FlowMods verificados.
        adds = 2 * len(preparar)
        mods = 2

        grupo_ff = int(
            puerto_fs != puerto_nuevo
        )

        flowmods += adds + mods
        grupos_nuevos += grupo_ff
        barreras += len(preparar) + 2

        diferencias.append({
            "origen": par[0],
            "destino": par[1],
            "ruta_fs": viejo,
            "ruta_target": nuevo,
            "puerto_ingreso_fs": puerto_fs,
            "puerto_ingreso_target": puerto_nuevo,
            "grupos_ff_existentes_en_ingreso":
                grupos_ingreso,
            "tramo_a_preparar": preparar,
            "switches_afectados": sorted(
                {ingreso, *preparar}
            ),
            "diferencias_siguiente_salto":
                dif["diferencias_siguiente_salto"],
            "operaciones_ipv4_arp_estimadas":
                adds + mods,
            "grupo_ff_nuevo_estimado":
                grupo_ff,
            "estado": (
                "PROPUESTA_SIN_VALIDACION_OPENFLOW"
            ),
        })

    costo = {
        "mensajes_modificacion":
            flowmods + grupos_nuevos,
        "barreras": barreras,
        "verificaciones": len(diferencias),
        "switches_modificados": len(switches),
        "flowmod_estimados": flowmods,
        "groupmod_estimados": grupos_nuevos,
        "tipo": (
            "ESTIMACION_DE_OPERACIONES_NO_EJECUTABLE"
        ),
    }

    return diferencias, bloqueos, costo


def evaluar_una_pareja(
    tid, nombre, orden, fs, target,
    demandas, capacidades, cambios,
    bloqueos, costo, inicial, final
):
    actual = dict(fs)
    serie = [inicial]

    for par in orden:
        actual[par] = target[par]

        serie.append(
            calcular_mlu(
                actual, demandas, capacidades
            )
        )

    peak = max(serie)

    estructural = (
        not bloqueos
        and peak <= 100.0 + 1e-6
    )

    return {
        "target_id": tid,
        "transition_id": f"{tid}_{nombre}",
        "estrategia": nombre,
        "orden_activacion_logica": [
            f"{a}->{b}" for a, b in orden
        ],
        "final_mlu_pct": round(final, 6),
        "peak_mlu_pct": round(peak, 6),
        "incremento_peak_sobre_fs_pp":
            round(peak - inicial, 6),
        "serie_estados_logicos_mlu_pct": [
            round(x, 6) for x in serie
        ],
        **{
            k: costo[k]
            for k in (
                "mensajes_modificacion",
                "barreras",
                "verificaciones",
                "switches_modificados",
            )
        },
        "bloqueos": bloqueos,
        "admisibilidad_modelo": estructural,
        "seguridad_openflow_demostrada": False,
        "ejecutable": False,
        "estado": (
            "BLOQUEADA_MODELO"
            if not estructural
            else "PRELIMINAR_PENDIENTE_OPENFLOW"
        ),
    }


def construir_plan(decision, estado, inventario):
    """Evaluacion preliminar E04 + E05 con datos dinamicos."""

    fallo = frozenset(decision["fallo"])

    exigir(
        len(fallo) == 2
        and fallo == frozenset(
            estado["fallo"].split("-")
        ),
        "Fallo de decision y captura diferente",
    )

    exigir(
        decision["captura_origen_utc"]
        == estado["fecha_utc"],
        "La decision no corresponde a la captura",
    )

    exigir(
        decision["tipo"]
        == "FORT_DECISION_DINAMICA_GUIADA_POR_CARGA",
        "Formato de decision no admitido",
    )

    exigir(
        decision["estado"]
        == "DECISION_PRELIMINAR_MODELO",
        "Decision sin carga o incompleta",
    )

    fs = {}

    for c in estado["fs"]["comunicaciones"]:
        clave = (c["origen"], c["destino"])

        exigir(
            clave not in fs,
            "Duplicado FS",
        )

        fs[clave] = c["ruta_seleccionada"]

    exigir(
        len(fs) == estado["fs"]["cantidad"],
        "FS incompleto",
    )

    demandas = {}

    for d in estado["demandas"]["comunicaciones"]:
        clave = (d["origen"], d["destino"])

        exigir(
            clave not in demandas,
            "Demanda duplicada",
        )

        demandas[clave] = float(
            d["tasa_ipv4_observada_bps"]
        )

    exigir(
        set(demandas) == set(fs),
        "Demandas y FS diferentes",
    )

    capacidades = {}

    for e in estado["rs"]["direcciones"]:
        if not e["activo"]:
            continue

        clave = (e["origen"], e["destino"])

        exigir(
            clave not in capacidades,
            "Arco duplicado",
        )

        capacidades[clave] = float(
            e["capacidad_configurada_bps"]
        )

        exigir(
            math.isfinite(capacidades[clave])
            and capacidades[clave] > 0,
            "Capacidad invalida",
        )

    puertos = mapa_puertos(inventario)

    for par, ruta in fs.items():
        validar_ruta(
            ruta, par, puertos, capacidades
        )

    base_mlu = calcular_mlu(
        fs, demandas, capacidades
    )

    exigir(
        abs(
            base_mlu
            - float(decision["mlu_fs_modelada_pct"])
        ) <= 0.02,
        "MLU FS inconsistente con motor",
    )

    ids = decision["candidatas_pareto"]

    exigir(
        len(ids) == len(set(ids)),
        "Targets Pareto duplicados",
    )

    catalogo = {
        t["target_id"]: t
        for t in decision["targets"]
    }

    grupos = {
        (g["switch"], int(g["group_id"]))
        for g in estado["ps"]["grupos_ff"]
    }

    parejas = []
    por_target = []

    for tid in ids:
        exigir(
            tid in catalogo,
            f"Falta Target: {tid}",
        )

        t = catalogo[tid]
        rutas = {}

        for c in t["configuracion"]:
            par = (c["origen"], c["destino"])

            exigir(
                par not in rutas,
                f"Duplicado Target {tid}",
            )

            rutas[par] = c["ruta"]

        exigir(
            set(rutas) == set(fs),
            f"Target incompleto: {tid}",
        )

        for par, ruta in rutas.items():
            validar_ruta(
                ruta, par, puertos, capacidades
            )

        final = calcular_mlu(
            rutas, demandas, capacidades
        )

        exigir(
            abs(
                final
                - float(t["final_modelada_pct"])
            ) <= 0.02,
            f"Final MLU inconsistente: {tid}",
        )

        cambios, bloqueos, costo = (
            planes_de_cambio(
                fs,
                rutas,
                puertos,
                capacidades,
                grupos,
            )
        )

        modificadas = sorted(
            par
            for par in fs
            if fs[par] != rutas[par]
        )

        exigir(
            len(modificadas)
            == t["rutas_modificadas"],
            f"Cantidad de rutas inconsistente: {tid}",
        )

        estrategias = [
            ("TR01_ASC", modificadas)
        ]

        if len(modificadas) >= 2:
            estrategias.append((
                "TR02_DESC",
                list(reversed(modificadas)),
            ))

            estrategias.append((
                "TR03_PREPARAR_TODOS",
                modificadas,
            ))

        locales = [
            evaluar_una_pareja(
                tid,
                nombre,
                orden,
                fs,
                rutas,
                demandas,
                capacidades,
                cambios,
                bloqueos,
                costo,
                base_mlu,
                final,
            )
            for nombre, orden in estrategias
        ]

        parejas.extend(locales)

        por_target.append({
            "target_id": tid,
            "rutas_modificadas": len(modificadas),
            "final_mlu_pct": round(final, 6),
            "operaciones_cambio_estimadas": costo,
            "planes_por_comunicacion": cambios,
            "transitions_preliminares": [
                p["transition_id"] for p in locales
            ],
            "bloqueos": bloqueos,
        })

    elegibles = [
        p
        for p in parejas
        if (
            p["admisibilidad_modelo"]
            and p["final_mlu_pct"]
            < base_mlu - 1e-6
        )
    ]

    frente = [
        p
        for p in elegibles
        if not any(
            q is not p and domina(q, p)
            for q in elegibles
        )
    ]

    frente.sort(
        key=clave_prioridad
    )

    preferida = (
        frente[0] if frente else None
    )

    return {
        "tipo": (
            "FORT_PLANIFICACION_ETAPAS_04_05_PRELIMINAR"
        ),
        "generado_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "captura_origen_utc": estado["fecha_utc"],
        "enlace_fallado": sorted(fallo),
        "cantidad_targets_pareto": len(ids),
        "cantidad_parejas_modeladas": len(parejas),
        "cantidad_parejas_admisibles_modelo":
            len(elegibles),
        "frente_pareto_parejas": [
            p["transition_id"]
            for p in frente
        ],
        "mlufs_modelada_pct": round(
            base_mlu, 6
        ),
        "mlufs_observada_pct": (
            estado["rs"][
                "maxima_utilizacion_observada_pct"
            ]
        ),
        "pareja_preferida_preliminar": (
            {
                k: preferida[k]
                for k in (
                    "target_id",
                    "transition_id",
                    "estrategia",
                    "final_mlu_pct",
                    "peak_mlu_pct",
                    "mensajes_modificacion",
                    "barreras",
                    "verificaciones",
                    "switches_modificados",
                )
            }
            if preferida
            else None
        ),
        "pareja_definitivamente_factible": None,
        "ejecucion_openflow_autorizada": False,
        "razon_pendiente": (
            "La captura FORT aun no conserva "
            "prioridades, matches IP/ARP y acciones "
            "OpenFlow completas por salto. "
            "No se pueden validar FlowMod/GroupMod "
            "ni la proteccion extremo a extremo."
        ),
        "limitaciones": [
            "Las Transitions son ordenes logicos, "
            "no operaciones OpenFlow ejecutables.",
            "Peak MLU modela cambios de rutas completas, "
            "no estados transitorios OpenFlow.",
            "Los conteos de modificaciones y barreras "
            "son estimaciones del plan anterior.",
            "No se mide todavia la MLU posterior "
            "a instalar el Target.",
            "El primer salto compartido queda "
            "bloqueado preventivamente.",
        ],
        "targets": por_target,
        "parejas": parejas,
    }


class PlanificadorFORT(app_manager.OSKenApp):
    OFP_VERSIONS = [
        ofproto_v1_3.OFP_VERSION
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.vistas = {
            p.name
            for p in DECISIONES.glob(
                "FORT_Decision_*.json"
            )
        }

        self.trabajador = hub.spawn(
            self.vigilar
        )

        print(
            "FORT ETAPAS 04/05: "
            "evaluacion preliminar AUTOMATICA",
            flush=True,
        )

        print(
            "FORT ETAPAS 04/05: "
            "ejecucion OpenFlow BLOQUEADA",
            flush=True,
        )

    def vigilar(self):
        while True:
            try:
                archivos = sorted(
                    DECISIONES.glob(
                        "FORT_Decision_*.json"
                    )
                )

                for archivo in archivos:
                    if archivo.name in self.vistas:
                        continue

                    try:
                        decision = leer(archivo)
                    except (OSError, ValueError):
                        continue

                    if (
                        "captura_origen_utc"
                        not in decision
                    ):
                        self.vistas.add(archivo.name)
                        continue

                    captura = (
                        CAPTURAS
                        / archivo.name.replace(
                            "FORT_Decision_",
                            "FORT_Estado_",
                        )
                    )

                    if not captura.is_file():
                        continue

                    try:
                        estado = leer(captura)
                    except (OSError, ValueError):
                        continue

                    self.vistas.add(archivo.name)

                    if decision.get("estado") == (
                        "SIN_CARGA_SUFICIENTE"
                    ):
                        continue

                    try:
                        inventario = leer(
                            BASE
                            / "resultados/etapa01/"
                              "puertos_detectados.json"
                        )

                        resumen = construir_plan(
                            decision,
                            estado,
                            inventario,
                        )

                        salida = (
                            PLANES
                            / archivo.name.replace(
                                "FORT_Decision_",
                                "FORT_Plan_",
                            )
                        )

                        guardar(
                            salida, resumen
                        )

                        print(
                            "\n=== FORT: ETAPAS 04 + 05 "
                            "DINAMICAS ===",
                            flush=True,
                        )

                        print(
                            "Fallo:",
                            "-".join(
                                resumen["enlace_fallado"]
                            ).upper(),
                            flush=True,
                        )

                        print(
                            "Targets Pareto:",
                            resumen[
                                "cantidad_targets_pareto"
                            ],
                            flush=True,
                        )

                        print(
                            "Parejas modeladas:",
                            resumen[
                                "cantidad_parejas_modeladas"
                            ],
                            flush=True,
                        )

                        print(
                            "Parejas admisibles en modelo:",
                            resumen[
                                "cantidad_parejas_admisibles_modelo"
                            ],
                            flush=True,
                        )

                        print(
                            "Parejas Pareto:",
                            len(
                                resumen[
                                    "frente_pareto_parejas"
                                ]
                            ),
                            flush=True,
                        )

                        print(
                            "Pareja PRELIMINAR:",
                            resumen[
                                "pareja_preferida_preliminar"
                            ],
                            flush=True,
                        )

                        print(
                            "OpenFlow ejecutable: NO - "
                            "requiere reglas y acciones reales",
                            flush=True,
                        )

                        print(
                            "Archivo:",
                            salida,
                            flush=True,
                        )

                    except Exception:
                        self.logger.exception(
                            "FORT: fallo planificando %s",
                            archivo,
                        )

            except Exception:
                self.logger.exception(
                    "FORT: error al vigilar decisiones"
                )

            hub.sleep(1)
