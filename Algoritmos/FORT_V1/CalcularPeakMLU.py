#!/usr/bin/env python3
"""Etapa 05 - A03: Peak MLU modelada por Transition.

Las demandas son tasas enviadas observadas; las rutas intermedias
son modelos logicos. Este programa NO modifica OVS ni OS-Ken.
"""

import json
import math
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
E02 = BASE / "resultados/etapa02"
E03 = BASE / "resultados/etapa03"
E04 = BASE / "resultados/etapa04"
E05 = BASE / "resultados/etapa05"


def exigir(condicion, mensaje):
    if not condicion:
        raise RuntimeError(mensaje)


def leer(ruta):
    exigir(ruta.is_file(), f"No existe: {ruta}")
    return json.loads(ruta.read_text(encoding="utf-8"))


def guardar(ruta, datos):
    ruta.parent.mkdir(parents=True, exist_ok=True)
    temporal = ruta.with_suffix(".json.tmp")
    temporal.write_text(
        json.dumps(datos, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporal.replace(ruta)


def obtener_rutas(comunicaciones, campo):
    resultado = {}
    for c in comunicaciones:
        par = (c["origen"], c["destino"])
        ruta = c[campo]
        exigir(par not in resultado, f"Comunicacion duplicada: {par}")
        exigir(
            isinstance(ruta, list) and len(ruta) >= 3
            and all(isinstance(n, str) for n in ruta)
            and len(set(ruta)) == len(ruta)
            and ruta[0] == par[0] and ruta[-1] == par[1],
            f"Ruta invalida: {par}",
        )
        resultado[par] = ruta
    return resultado


def obtener_capacidades(rs, topologia, fallo):
    rs_por_arco = {}
    for d in rs["direcciones"]:
        arco = (d["origen"], d["destino"])
        exigir(arco not in rs_por_arco, f"Direccion RS duplicada: {arco}")
        rs_por_arco[arco] = d

    capacidades = {}
    for e in topologia["enlaces_operativos"]:
        a, b = e["extremo_a"], e["extremo_b"]
        exigir(frozenset((a, b)) != fallo, "Enlace fallado operativo")
        for origen, destino, campo in (
            (a, b, "capacidad_a_b_bps"),
            (b, a, "capacidad_b_a_bps"),
        ):
            arco = (origen, destino)
            exigir(arco not in capacidades, f"Arco repetido: {arco}")
            exigir(arco in rs_por_arco, f"Falta RS para {arco}")
            d = rs_por_arco[arco]
            capacidad = float(d["capacidad_operativa_bps"])
            exigir(
                d["activo"] and math.isfinite(capacidad)
                and capacidad > 0,
                f"Capacidad RS invalida: {arco}",
            )
            if campo in e:
                nominal = float(e[campo])
                exigir(
                    math.isclose(capacidad, nominal,
                                 rel_tol=0.001, abs_tol=1000),
                    f"RS y topologia difieren: {arco}",
                )
            capacidades[arco] = capacidad
    exigir(capacidades, "No hay enlaces operativos")
    return capacidades


def arcos_de_ruta(par, ruta, capacidades):
    internos = ruta[1:-1]
    exigir(
        all(n.startswith("s") for n in internos),
        f"Nodo intermedio no es switch en {par}",
    )
    arcos = []
    for a, b in zip(ruta, ruta[1:]):
        if a.startswith("s") and b.startswith("s"):
            exigir((a, b) in capacidades,
                   f"Arco no operativo {a}->{b} en {par}")
            arcos.append((a, b))
    return arcos


def demanda_por_comunicacion(datos, fs):
    tasas = defaultdict(float)
    ids = set()
    for flujo in datos["flujos"]:
        identificador = flujo["id"]
        par = (flujo["origen"], flujo["destino"])
        tasa = float(flujo["tasa_enviada_bps"])
        exigir(identificador not in ids, f"Flujo repetido: {identificador}")
        exigir(par in fs, f"Demanda ajena a FS: {par}")
        exigir(
            flujo["protocolo"].upper() in ("TCP", "UDP")
            and math.isfinite(tasa) and tasa >= 0,
            f"Demanda invalida: {identificador}",
        )
        ids.add(identificador)
        tasas[par] += tasa
    exigir(len(ids) == datos["cantidad_flujos"],
           "Cantidad de flujos distinta a la registrada")
    return dict(tasas), len(ids)


def calcular_estado(activadas_ip, fs_arcos, target_arcos,
                    tasas, capacidades):
    cargas = {arco: 0.0 for arco in capacidades}
    for par, tasa in tasas.items():
        camino = target_arcos[par] if par in activadas_ip else fs_arcos[par]
        for arco in camino:
            cargas[arco] += tasa
    utilizaciones = {
        arco: 100.0 * cargas[arco] / capacidad
        for arco, capacidad in capacidades.items()
    }
    pico = max(utilizaciones.values())
    criticos = [
        {"origen": a, "destino": b,
         "utilizacion_pct": round(utilizaciones[(a, b)], 4)}
        for a, b in sorted(capacidades)
        if math.isclose(utilizaciones[(a, b)], pico, abs_tol=1e-8)
    ]
    return pico, criticos, cargas


def mismo_porcentaje(a, b):
    return math.isclose(a, b, rel_tol=1e-6, abs_tol=0.005)


def main():
    inicio = time.perf_counter()
    estado = leer(E02 / "EstadoPostFallo.json")
    rs = leer(E02 / "RS_postfallo.json")
    fs_doc = leer(E02 / "FS_postfallo.json")
    topologia = leer(E03 / "TopologiaPostFallo.json")
    demandas = leer(E03 / "DemandasObservadas_iperf2.json")
    targets_doc = leer(E03 / "TargetsCandidatos.json")
    candidatas = leer(E04 / "TransitionsCandidatas.json")
    intermedios = leer(E04 / "EstadosIntermediosTransitions.json")
    final = leer(E05 / "FinalMLU.json")
    factibilidad = leer(E05 / "FactibilidadPreliminar.json")

    fallo = frozenset(estado["enlace_fallado"])
    for nombre, documento in (
        ("Demandas", demandas), ("Targets", targets_doc),
        ("Transitions", candidatas), ("Intermedios", intermedios),
        ("Final MLU", final), ("Factibilidad", factibilidad),
    ):
        exigir(frozenset(documento["enlace_fallado"]) == fallo,
               f"Fallo diferente en {nombre}")
    registros_rs = rs["enlaces_fallados_observados"]
    exigir(
        len(registros_rs) == 1 and
        frozenset((registros_rs[0]["extremo_a"],
                   registros_rs[0]["extremo_b"])) == fallo,
        "RS no corresponde al fallo evaluado",
    )

    capacidades = obtener_capacidades(rs, topologia, fallo)
    fs = obtener_rutas(fs_doc["comunicaciones"], "ruta_seleccionada")
    targets = {}
    for t in targets_doc["targets"]:
        tid = t["id"]
        exigir(tid not in targets, f"Target duplicado: {tid}")
        rutas = obtener_rutas(t["configuracion"], "ruta")
        exigir(set(rutas) == set(fs), f"Comunicaciones incompletas: {tid}")
        targets[tid] = rutas
    exigir(targets["T000"] == fs, "T000 no reproduce FS")
    tasas, cantidad_flujos = demanda_por_comunicacion(demandas, fs)

    fs_arcos = {
        par: arcos_de_ruta(par, ruta, capacidades)
        for par, ruta in fs.items()
    }
    targets_arcos = {
        tid: {
            par: arcos_de_ruta(par, ruta, capacidades)
            for par, ruta in rutas.items()
        }
        for tid, rutas in targets.items()
    }
    inicial, enlaces_fs, _ = calcular_estado(
        set(), fs_arcos, fs_arcos, tasas, capacidades
    )
    exigir(mismo_porcentaje(inicial, float(final["final_mlu_fs_pct"])),
           "MLU inicial distinta a Final MLU de FS")

    finales = {t["target_id"]: float(t["final_mlu_pct"])
               for t in final["targets"]}
    exigir(len(finales) == len(final["targets"])
           and set(finales) == set(targets),
           "Cobertura de Final MLU inconsistente")

    por_pareja_final = {p["transition_id"]: p
                        for p in final["parejas_target_transition"]}
    exigir(len(por_pareja_final) == final["parejas_evaluadas"],
           "Parejas Final MLU duplicadas")

    modelados = {t["target_id"]: t for t in intermedios["targets"]}
    exigir(len(modelados) == len(intermedios["targets"]),
           "Targets intermedios duplicados")
    por_factibilidad = {t["target_id"]: t
                        for t in factibilidad["targets"]}
    exigir(len(por_factibilidad) == len(factibilidad["targets"]),
           "Targets factibilidad duplicados")

    resultados = []
    cantidad_parejas = 0
    cantidad_estados = 0
    picos_sobre_fs = 0
    picos_sobre_final = 0
    picos_sobre_capacidad = 0
    transiciones_con_divergencias = 0
    peor_pico = None

    for t in candidatas["targets"]:
        tid = t["target_id"]
        exigir(tid in targets and tid in modelados and tid in por_factibilidad,
               f"Target sin artefactos: {tid}")
        modelos = {x["transition_id"]: x
                   for x in modelados[tid]["transitions"]}
        factibles = {x["transition_id"]: x
                     for x in por_factibilidad[tid]["evaluaciones"]}
        exigir(len(modelos) == len(modelados[tid]["transitions"])
               and len(factibles) == len(por_factibilidad[tid]["evaluaciones"]),
               f"Transitions repetidas: {tid}")
        exigir(set(modelos) == set(factibles) ==
               {x["transition_id"] for x in t["transitions"]},
               f"Transitions de fuentes distintas: {tid}")
        resultados_target = []
        modificadas = {
            f"{par[0]}->{par[1]}"
            for par in fs if fs[par] != targets[tid][par]
        }

        for tr in t["transitions"]:
            trid = tr["transition_id"]
            modelo = modelos[trid]
            estados = modelo["estados"]
            exigir(trid in por_pareja_final, f"Falta Final MLU: {trid}")
            exigir(por_pareja_final[trid]["target_id"] == tid,
                   f"Pareja de Final MLU distinta: {trid}")
            exigir(factibles[trid]["estado_evaluacion"] ==
                   "PASA_ESTRUCTURA_PENDIENTE_SEGURIDAD",
                   f"No supera estructura: {trid}")
            exigir(len(estados) == tr["cantidad_pasos"] + 1,
                   f"Estados incompletos: {trid}")
            exigir(modelo["cantidad_estados_incluido_fs"] == len(estados),
                   f"Resumen de estados inconsistente: {trid}")

            maximo = -1.0
            estado_pico = None
            arcos_pico = None
            estados_con_divergencia = 0
            serie = []
            for indice, e in enumerate(estados):
                exigir(e["paso_global"] == indice,
                       f"Orden de estados distinto: {trid}/{indice}")
                ip_strings = set(e["comunicaciones_ip_en_target"])
                arp_strings = set(e["comunicaciones_arp_en_target"])
                exigir(ip_strings <= modificadas and arp_strings <= modificadas,
                       f"Activacion ajena a Target: {trid}/{indice}")
                exigir(set(e["comunicaciones_ip_arp_divergentes"]) ==
                       ip_strings ^ arp_strings,
                       f"Divergencia incoherente: {trid}/{indice}")
                if ip_strings != arp_strings:
                    estados_con_divergencia += 1
                ip_pares = set()
                for s in ip_strings:
                    partes = s.split("->")
                    exigir(len(partes) == 2 and tuple(partes) in fs,
                           f"Comunicacion inesperada: {s}")
                    ip_pares.add(tuple(partes))
                valor, criticos, _ = calcular_estado(
                    ip_pares, fs_arcos, targets_arcos[tid], tasas, capacidades
                )
                serie.append({
                    "estado_id": e["estado_id"],
                    "paso_global": indice,
                    "mlu_estimada_pct": round(valor, 4),
                    "ip_arp_divergentes": bool(ip_strings ^ arp_strings),
                })
                if valor > maximo + 1e-8:
                    maximo, estado_pico, arcos_pico = valor, e, criticos

            exigir(not estados[0]["comunicaciones_ip_en_target"]
                   and not estados[0]["comunicaciones_arp_en_target"],
                   f"Estado inicial no es FS: {trid}")
            exigir(set(estados[-1]["comunicaciones_ip_en_target"]) ==
                   modificadas,
                   f"Estado final IP no coincide con Target: {trid}")
            exigir(set(estados[-1]["comunicaciones_arp_en_target"]) ==
                   modificadas,
                   f"Estado final ARP no coincide con Target: {trid}")
            final_calculado = serie[-1]["mlu_estimada_pct"]
            exigir(mismo_porcentaje(inicial, serie[0]["mlu_estimada_pct"]),
                   f"MLU inicial incorrecta: {trid}")
            exigir(mismo_porcentaje(final_calculado, finales[tid])
                   and mismo_porcentaje(final_calculado,
                                       float(por_pareja_final[trid]["final_mlu_pct"])),
                   f"MLU final no coincide con A02: {trid}")
            exigir(maximo + 0.005 >= max(inicial, finales[tid]),
                   f"Peak MLU menor que extremos: {trid}")
            exigir(estados_con_divergencia ==
                   modelo["estados_con_ip_arp_divergentes"],
                   f"Divergencias A05 inconsistentes: {trid}")

            if maximo > inicial + 0.005:
                picos_sobre_fs += 1
            if maximo > finales[tid] + 0.005:
                picos_sobre_final += 1
            if maximo > 100.0 + 0.005:
                picos_sobre_capacidad += 1
            if estados_con_divergencia:
                transiciones_con_divergencias += 1

            registro = {
                "target_id": tid,
                "transition_id": trid,
                "estrategia": tr["estrategia"],
                "cantidad_estados": len(estados),
                "mlu_fs_pct": round(inicial, 4),
                "final_mlu_pct": round(finales[tid], 4),
                "peak_mlu_estimada_pct": round(maximo, 4),
                "incremento_pico_sobre_fs_pp": round(maximo - inicial, 4),
                "incremento_pico_sobre_final_pp": round(maximo - finales[tid], 4),
                "paso_del_pico": estado_pico["paso_global"],
                "estado_del_pico": estado_pico["estado_id"],
                "enlaces_criticos_pico": arcos_pico,
                "estados_con_ip_arp_divergentes": estados_con_divergencia,
                "supera_capacidad_modelada": maximo > 100.0 + 0.005,
                "factibilidad_definitiva_demostrada": False,
                "serie_estados": serie,
            }
            resultados_target.append(registro)
            cantidad_parejas += 1
            cantidad_estados += len(estados)
            if peor_pico is None or maximo > peor_pico["peak_mlu_estimada_pct"]:
                peor_pico = registro

        resultados.append({
            "target_id": tid,
            "cantidad_transitions": len(resultados_target),
            "transitions": resultados_target,
        })

    exigir(cantidad_parejas == candidatas["transitions_generadas"]
           == final["parejas_evaluadas"],
           "Cantidad de parejas inconsistente")
    exigir(cantidad_estados ==
           intermedios["estados_registrados_incluyendo_iniciales"],
           "Cantidad total de estados no coincide con A05")
    duracion = time.perf_counter() - inicio
    salida = E05 / "PeakMLU.json"
    guardar(salida, {
        "tipo": "PeakMLU_Estimada_Piloto",
        "generado_utc": datetime.now(timezone.utc).isoformat(),
        "enlace_fallado": sorted(fallo),
        "flujos_observados": cantidad_flujos,
        "direcciones_operativas": len(capacidades),
        "mlu_fs_pct": round(inicial, 4),
        "enlaces_criticos_fs": enlaces_fs,
        "targets_analizados": len(resultados),
        "parejas_evaluadas": cantidad_parejas,
        "estados_evaluados_incluyendo_fs": cantidad_estados,
        "parejas_con_peak_superior_a_fs": picos_sobre_fs,
        "parejas_con_peak_superior_a_final_mlu": picos_sobre_final,
        "parejas_con_peak_sobre_100_pct": picos_sobre_capacidad,
        "parejas_con_estados_ip_arp_divergentes": transiciones_con_divergencias,
        "mayor_peak_identificada": (
            {"target_id": peor_pico["target_id"],
             "transition_id": peor_pico["transition_id"],
             "peak_mlu_pct": peor_pico["peak_mlu_estimada_pct"]}
            if peor_pico else None
        ),
        "tiempo_calculo_s": round(duracion, 6),
        "modificaciones_ejecutadas_en_ovs": 0,
        "limitaciones": [
            "Peak MLU es una estimacion a partir de demandas enviadas observadas.",
            "Cada FlowMod se trata como conmutacion logica instantanea; no es una captura del datapath.",
            "No se incorporan retransmisiones, overhead, trafico de fondo ni efectos de colas.",
            "La MLU IP no representa por si sola seguridad de ARP ni de Fast Failover.",
            "No se verificaron instalacion real, BarrierReply ni proteccion extremo a extremo.",
            "RS se usa como capacidad; no se suma a la demanda del mismo trafico.",
        ],
        "targets": resultados,
    })

    print("\n=== ETAPA 05 - A03: PEAK MLU ===")
    print("Fallo:", " - ".join(n.upper() for n in sorted(fallo)))
    print("Flujos observados:", cantidad_flujos)
    print("Direcciones operativas:", len(capacidades))
    print("Parejas Target-Transition:", cantidad_parejas)
    print("Estados evaluados (incluyen FS inicial):", cantidad_estados)
    print("MLU inicial FS:", round(inicial, 4), "%")
    print("Parejas con Peak superior a FS:", picos_sobre_fs)
    print("Parejas con Peak superior a Final MLU:", picos_sobre_final)
    print("Parejas con Peak sobre 100%:", picos_sobre_capacidad)

    t002 = next((t for t in resultados if t["target_id"] == "T002"), None)
    if t002 and t002["transitions"]:
        print("\n=== EJEMPLO T002: ALTERNATIVAS ===")
        for r in t002["transitions"]:
            print(r["transition_id"], "| Final:", r["final_mlu_pct"],
                  "% | Peak:", r["peak_mlu_estimada_pct"],
                  "% | Paso pico:", r["paso_del_pico"])

    t013 = next((t for t in resultados if t["target_id"] == "T013"), None)
    if t013 and t013["transitions"]:
        print("\n=== REFERENCIA T013 ===")
        for r in t013["transitions"]:
            print(r["transition_id"], "| Final:", r["final_mlu_pct"],
                  "% | Peak:", r["peak_mlu_estimada_pct"], "%")

    print(f"\nTiempo de calculo: {duracion:.6f} s")
    print("Modificaciones ejecutadas en OVS: 0")
    print("Factibilidad definitiva: PENDIENTE")
    print("Archivo generado:", salida)


if __name__ == "__main__":
    main()
