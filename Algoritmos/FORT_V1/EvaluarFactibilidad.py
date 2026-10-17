
#!/usr/bin/env python3
"""Etapa 05 - A01: factibilidad estructural Target-Transition.

Evalua estados intermedios, rutas, dependencias y recursos.
No ejecuta OpenFlow ni certifica seguridad de produccion.
"""

import json
import math
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
E01 = BASE / "resultados/etapa01"
E02 = BASE / "resultados/etapa02"
E03 = BASE / "resultados/etapa03"
E04 = BASE / "resultados/etapa04"
E05 = BASE / "resultados/etapa05"


def exigir(condicion, mensaje):
    if not condicion:
        raise RuntimeError(mensaje)


def leer(ruta):
    exigir(ruta.is_file(), f"Archivo inexistente: {ruta}")
    return json.loads(ruta.read_text(encoding="utf-8"))


def guardar(ruta, datos):
    ruta.parent.mkdir(parents=True, exist_ok=True)
    temporal = ruta.with_suffix(".json.tmp")
    temporal.write_text(
        json.dumps(datos, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporal.replace(ruta)


def par(c):
    return f'{c["origen"]}->{c["destino"]}'


def rutas(comunicaciones, campo):
    resultado = {}

    for c in comunicaciones:
        clave = par(c)
        exigir(clave not in resultado, f"Ruta duplicada: {clave}")

        ruta = c[campo]
        exigir(
            isinstance(ruta, list) and len(ruta) >= 3,
            f"Ruta invalida: {clave}",
        )
        resultado[clave] = ruta

    return resultado


def inventario(datos):
    enlaces = {}

    for e in datos:
        a, b = e["nodo_a"], e["nodo_b"]
        pa, pb = int(e["puerto_a"]), int(e["puerto_b"])

        exigir(
            (a, b) not in enlaces
            and (b, a) not in enlaces,
            f"Enlace repetido: {a}-{b}",
        )

        enlaces[(a, b)] = (pa, pb)
        enlaces[(b, a)] = (pb, pa)

    return enlaces


def recursos_red(topologia, ps, rs, enlaces):
    switches = ps["switches"]
    exigir(isinstance(switches, dict), "Formato PS invalido")

    puertos_ps = {}

    for sw, datos in switches.items():
        puertos_ps[sw] = {
            int(p["numero"]): bool(p["activo"])
            for p in datos["puertos"]
        }

    arcos = set()

    for e in topologia["enlaces_operativos"]:
        a, b = e["extremo_a"], e["extremo_b"]

        exigir(
            (a, b) in enlaces
            and a in puertos_ps
            and b in puertos_ps,
            f"Enlace operativo desconocido: {a}-{b}",
        )

        exigir(
            (a, b) not in arcos
            and (b, a) not in arcos,
            f"Enlace operativo repetido: {a}-{b}",
        )

        pa, pb = enlaces[(a, b)]

        exigir(
            puertos_ps[a].get(pa) is True
            and puertos_ps[b].get(pb) is True,
            f"PS contradice topologia: {a}-{b}",
        )

        arcos.add((a, b))
        arcos.add((b, a))

    recursos = {}

    for r in rs["direcciones"]:
        clave = (r["origen"], r["destino"])

        exigir(
            clave not in recursos,
            f"RS duplicado: {clave}",
        )

        recursos[clave] = r

    for arco in arcos:
        exigir(arco in recursos, f"RS no contiene {arco}")

        recurso = recursos[arco]
        capacidad = float(recurso["capacidad_operativa_bps"])

        exigir(
            recurso["activo"]
            and math.isfinite(capacidad)
            and capacidad > 0,
            f"Capacidad RS invalida: {arco}",
        )

    return arcos, puertos_ps, recursos


def comprobar_ruta(clave, ruta, enlaces, arcos,
                   puertos_ps, recursos):
    errores = []

    extremos = clave.split("->")

    if (
        len(extremos) != 2
        or not isinstance(ruta, list)
        or len(ruta) < 3
    ):
        return ["Ruta mal formada"]

    if ruta[0] != extremos[0] or ruta[-1] != extremos[1]:
        errores.append("Extremos incompatibles")

    if len(ruta) != len(set(ruta)):
        errores.append("Ruta con ciclos")

    if any(n not in puertos_ps for n in ruta[1:-1]):
        errores.append("Nodo intermedio no es switch")

    for a, b in zip(ruta, ruta[1:]):
        if (a, b) not in enlaces:
            errores.append(f"Enlace inexistente: {a}->{b}")
            continue

        pa, pb = enlaces[(a, b)]

        for sw, puerto in ((a, pa), (b, pb)):
            if sw in puertos_ps:
                if puertos_ps[sw].get(puerto) is not True:
                    errores.append(
                        f"Puerto PS inactivo: {sw}:{puerto}"
                    )

        if a in puertos_ps and b in puertos_ps:
            if (a, b) not in arcos:
                errores.append(f"Arco no operativo: {a}->{b}")
            else:
                recurso = recursos[(a, b)]

                if (
                    not recurso["activo"]
                    or float(
                        recurso["capacidad_operativa_bps"]
                    ) <= 0
                ):
                    errores.append(
                        f"RS sin capacidad: {a}->{b}"
                    )

    return errores


def evaluar_transition(
    tr, estados_tr, fs, target,
    enlaces, arcos, puertos_ps, recursos
):
    problemas = []
    riesgos = []
    revisados = 0
    divergentes = 0

    def problema(texto):
        if len(problemas) < 20:
            problemas.append(texto)

    pasos = tr["pasos"]
    estados = estados_tr["estados"]

    if len(estados) != len(pasos) + 1:
        problema("Cantidad de estados diferente a pasos + 1")

    if estados_tr["transition_id"] != tr["transition_id"]:
        problema("Identificador de Transition inconsistente")

    modificadas = {
        par: camino
        for par, camino in target.items()
        if camino != fs[par]
    }

    if not modificadas:
        problema("Transition sin cambios de ruta")

    identificadores = [p["referencia_paso"] for p in pasos]

    if len(set(identificadores)) != len(identificadores):
        problema("Pasos duplicados")

    for i, estado in enumerate(estados):
        if estado["paso_global"] != i:
            problema(f"Indice de estado incorrecto: {i}")

        if i == 0:
            if estado["evento"] != "ESTADO_FS_INICIAL":
                problema("El estado inicial no es FS")
        elif i <= len(pasos):
            paso = pasos[i - 1]

            if (
                paso["orden_global"] != i
                or estado["paso_referencia"]
                != paso["referencia_paso"]
                or estado["evento"] != paso["categoria"]
            ):
                problema(f"Paso/estado incoherente: {i}")

        ip_target = set(
            estado["comunicaciones_ip_en_target"]
        )
        arp_target = set(
            estado["comunicaciones_arp_en_target"]
        )

        if not ip_target <= set(modificadas):
            problema(f"IP activa comunicacion ajena: {i}")

        if not arp_target <= set(modificadas):
            problema(f"ARP activa comunicacion ajena: {i}")

        divergencias = ip_target ^ arp_target

        if divergencias != set(
            estado["comunicaciones_ip_arp_divergentes"]
        ):
            problema(f"Divergencias inconsistentes: {i}")

        if divergencias:
            divergentes += 1

        detalle = {
            c["comunicacion"]: c
            for c in estado[
                "rutas_por_comunicacion_modificada"
            ]
        }

        if set(detalle) != set(modificadas):
            problema(
                f"Faltan comunicaciones en estado: {i}"
            )

        # Se modelan todas las comunicaciones: las que
        # no cambian permanecen en FS.
        for clave in fs:
            for protocolo, activadas in (
                ("IP", ip_target),
                ("ARP", arp_target),
            ):
                usa_target = clave in activadas

                camino = (
                    target[clave] if usa_target
                    else fs[clave]
                )

                errores = comprobar_ruta(
                    clave, camino,
                    enlaces, arcos,
                    puertos_ps, recursos,
                )

                for error in errores:
                    problema(
                        f"Estado {i} {clave} "
                        f"{protocolo}: {error}"
                    )

                revisados += 1

        for clave, d in detalle.items():
            esperado_ip = (
                "TARGET" if clave in ip_target else "FS"
            )
            esperado_arp = (
                "TARGET" if clave in arp_target else "FS"
            )

            if d["ruta_ip_modelada"] != esperado_ip:
                problema(
                    f"Ruta IP logica inconsistente: {i}"
                )

            if d["ruta_arp_modelada"] != esperado_arp:
                problema(
                    f"Ruta ARP logica inconsistente: {i}"
                )

    if estados:
        inicial = estados[0]
        final = estados[-1]

        if (
            inicial["comunicaciones_ip_en_target"]
            or inicial["comunicaciones_arp_en_target"]
        ):
            problema("Estado inicial diferente a FS")

        if (
            set(final["comunicaciones_ip_en_target"])
            != set(modificadas)
            or set(final["comunicaciones_arp_en_target"])
            != set(modificadas)
        ):
            problema("No se alcanza el Target logico")

        if final["comunicaciones_ip_arp_divergentes"]:
            problema("Divergencia IP/ARP en estado final")

    if divergentes:
        riesgos.append(
            "Estados transitorios con IP y ARP "
            "en configuraciones distintas"
        )

    riesgos.extend([
        "Proteccion FF extremo a extremo no certificada",
        "Conflictos con reglas, prioridades y grupos "
        "OVS actuales no verificados",
        "Instalacion y BarrierReply reales no comprobados",
        "Peak MLU y continuidad del trafico pendientes",
    ])

    estado = (
        "NO_APTA_ESTRUCTURALMENTE"
        if problemas
        else "PASA_ESTRUCTURA_PENDIENTE_SEGURIDAD"
    )

    return {
        "transition_id": tr["transition_id"],
        "estrategia": tr["estrategia"],
        "estado_evaluacion": estado,
        "estados_analizados": len(estados),
        "comprobaciones_ruta_protocolo": revisados,
        "estados_con_divergencia_ip_arp": divergentes,
        "problemas_estructurales": problemas,
        "riesgos_pendientes": riesgos,
        "factibilidad_definitiva_demostrada": False,
    }


def main():
    inicio = time.perf_counter()

    estado = leer(E02 / "EstadoPostFallo.json")
    fs_json = leer(E02 / "FS_postfallo.json")
    ps = leer(E02 / "PS_postfallo.json")
    rs = leer(E02 / "RS_postfallo.json")
    topologia = leer(E03 / "TopologiaPostFallo.json")
    targets_json = leer(E03 / "TargetsCandidatos.json")
    transiciones = leer(E04 / "TransitionsCandidatas.json")
    intermedios = leer(
        E04 / "EstadosIntermediosTransitions.json"
    )

    fallo = frozenset(estado["enlace_fallado"])

    exigir(
        frozenset(transiciones["enlace_fallado"]) == fallo
        and frozenset(intermedios["enlace_fallado"]) == fallo
        and frozenset(targets_json["enlace_fallado"]) == fallo,
        "Los archivos corresponden a fallos diferentes",
    )

    enlaces = inventario(
        leer(E01 / "puertos_detectados.json")
    )

    arcos, puertos_ps, recursos = recursos_red(
        topologia, ps, rs, enlaces
    )

    fs = rutas(
        fs_json["comunicaciones"],
        "ruta_seleccionada",
    )

    targets = {
        t["id"]: rutas(t["configuracion"], "ruta")
        for t in targets_json["targets"]
    }

    exigir(
        "T000" in targets
        and targets["T000"] == fs,
        "T000 no coincide con FS",
    )

    para_estados = {
        t["target_id"]: t
        for t in intermedios["targets"]
    }

    exigir(
        len(para_estados) == len(intermedios["targets"]),
        "Targets de estados intermedios duplicados",
    )

    resultados = []
    parejas = 0
    pasan = 0
    rechazadas = 0
    divergentes = 0

    for t in transiciones["targets"]:
        tid = t["target_id"]

        exigir(
            tid in targets and tid in para_estados,
            f"Target ausente: {tid}",
        )

        exigir(
            set(targets[tid]) == set(fs),
            f"Comunicaciones diferentes a FS: {tid}",
        )

        registro_estados = para_estados[tid]

        modelos = {
            x["transition_id"]: x
            for x in registro_estados["transitions"]
        }

        exigir(
            len(modelos)
            == len(registro_estados["transitions"]),
            f"Transitions duplicadas en {tid}",
        )

        exigir(
            set(modelos)
            == {
                x["transition_id"]
                for x in t["transitions"]
            },
            f"Transitions y estados no coinciden: {tid}",
        )

        evaluadas = []

        for tr in t["transitions"]:
            evaluacion = evaluar_transition(
                tr,
                modelos[tr["transition_id"]],
                fs,
                targets[tid],
                enlaces,
                arcos,
                puertos_ps,
                recursos,
            )

            evaluadas.append(evaluacion)
            parejas += 1

            divergentes += evaluacion[
                "estados_con_divergencia_ip_arp"
            ]

            if evaluacion["problemas_estructurales"]:
                rechazadas += 1
            else:
                pasan += 1

        resultados.append({
            "target_id": tid,
            "estado_original": t["estado_target"],
            "parejas_evaluadas": len(evaluadas),
            "evaluaciones": evaluadas,
        })

    exigir(
        parejas == transiciones["transitions_generadas"],
        "Cantidad de Transitions inconsistente",
    )

    duracion = time.perf_counter() - inicio

    salida = E05 / "FactibilidadPreliminar.json"

    guardar(salida, {
        "tipo": "FactibilidadEstructural_Preliminar",
        "generado_utc":
            datetime.now(timezone.utc).isoformat(),
        "enlace_fallado": sorted(fallo),
        "targets_analizados": len(resultados),
        "parejas_evaluadas": parejas,
        "parejas_que_pasan_estructura": pasan,
        "parejas_rechazadas_por_estructura": rechazadas,
        "parejas_con_seguridad_definitiva_demostrada": 0,
        "estados_con_ip_arp_divergentes": divergentes,
        "tiempo_evaluacion_s": round(duracion, 6),
        "modificaciones_ejecutadas_en_ovs": 0,
        "criterio": (
            "Validez topologica, puertos PS, existencia "
            "de capacidad RS y coherencia de los estados "
            "logicos. No certifica seguridad de ejecucion."
        ),
        "limitaciones": [
            "La capacidad RS se verifica, pero no se "
            "evalua aun congestion ni Peak MLU.",
            "No se suma RS observado a demandas del "
            "mismo trafico.",
            "FS, PS y RS fueron capturados "
            "secuencialmente durante una sesion piloto.",
            "No se verifica el estado OpenFlow actual "
            "al ejecutar este analisis.",
            "No se ha demostrado instalacion atomica "
            "ni preservacion de FF extremo a extremo.",
            "Las divergencias IP/ARP son estados "
            "logicos, no perdidas de paquetes medidas.",
        ],
        "targets": resultados,
    })

    ejemplo = next(
        (
            e for t in resultados
            if t["target_id"] == "T002"
            for e in t["evaluaciones"]
            if e["transition_id"] == "T002_TR01"
        ),
        None,
    )

    print("\n=== ETAPA 05 - A01: FACTIBILIDAD PRELIMINAR ===")
    print("Targets analizados:", len(resultados))
    print("Parejas Target-Transition evaluadas:", parejas)
    print("Pasan validaciones estructurales:", pasan)
    print("Rechazadas por problemas estructurales:", rechazadas)
    print("Estados con divergencia IP/ARP:", divergentes)
    print("Factibilidad definitiva demostrada: 0")

    if ejemplo:
        print("\n=== EJEMPLO T002_TR01 ===")
        print("Estados analizados:", ejemplo["estados_analizados"])
        print(
            "Comprobaciones ruta/protocolo:",
            ejemplo["comprobaciones_ruta_protocolo"],
        )
        print(
            "Divergencias IP/ARP:",
            ejemplo["estados_con_divergencia_ip_arp"],
        )
        print("Estado:", ejemplo["estado_evaluacion"])

    print(f"\nTiempo de evaluacion: {duracion:.6f} s")
    print("Modificaciones ejecutadas en OVS: 0")
    print("Seguridad final y Peak MLU: PENDIENTES")
    print("Archivo generado:", salida)


if __name__ == "__main__":
    main()
