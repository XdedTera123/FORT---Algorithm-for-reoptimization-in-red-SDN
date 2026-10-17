#!/usr/bin/env python3
"""Etapa 05 - A04: costo estructural de Transitions propuestas.

Solo analiza artefactos existentes. No envia mensajes a OVS u OS-Ken.
No estima tiempos, dinero, bytes del canal de control ni CPU.
"""

import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
E04 = BASE / "resultados/etapa04"
E05 = BASE / "resultados/etapa05"

OPENFLOW = (
    "FlowMod_ADD_PROPUESTO",
    "FlowMod_MODIFY_STRICT_PROPUESTO",
    "GroupMod_ADD_PROPUESTO",
)
BARRERA = "BarrierRequest_PROPUESTO"
VERIFICACION = "VERIFICACION_PENDIENTE"
CATEGORIAS = set(OPENFLOW) | {BARRERA, VERIFICACION}


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


def por_target(datos):
    targets = {t["target_id"]: t for t in datos["targets"]}
    exigir(len(targets) == len(datos["targets"]), "Targets duplicados")
    return targets


def por_comunicacion(planes, tid):
    resultado = {}
    for plan in planes:
        clave = f'{plan["origen"]}->{plan["destino"]}'
        exigir(clave not in resultado, f"Plan duplicado: {tid}/{clave}")
        resultado[clave] = plan
    return resultado


def catalogo_target(tid, original_a02, original_a03):
    planes_a02 = por_comunicacion(original_a02["planes"], tid)
    planes_a03 = por_comunicacion(original_a03["planes"], tid)
    exigir(set(planes_a02) == set(planes_a03), f"Planes A02/A03 difieren: {tid}")

    operaciones = {}
    pasos = {}
    dependencias = []
    for comunicacion in planes_a02:
        p02 = planes_a02[comunicacion]
        p03 = planes_a03[comunicacion]
        exigir(
            p03["estado"] == "ORDENADO_NO_VALIDADO"
            and p02["estado_plan"] == "PROPUESTA_REQUIERE_VALIDACION",
            f"Plan bloqueado dentro de una Transition: {tid}/{comunicacion}",
        )
        for op in p02["operaciones"]:
            oid = op["id"]
            exigir(oid not in operaciones, f"Operacion repetida: {oid}")
            operaciones[oid] = (comunicacion, op)
        for paso in p03["pasos_ordenados"]:
            pid = paso["id"]
            exigir(pid not in pasos, f"Paso repetido: {pid}")
            pasos[pid] = (comunicacion, paso)
        dependencias.extend(p03["dependencias"])

    exigir(
        len(operaciones) == original_a02["cantidad_operaciones_propuestas"],
        f"Cantidad de operaciones A02 inconsistente: {tid}",
    )
    return operaciones, pasos, dependencias, len(planes_a02)


def evaluar_transition(tr, operaciones, pasos, dependencias, comunicaciones):
    nombre = tr["transition_id"]
    secuencia = tr["pasos"]
    exigir(
        len(secuencia) == tr["cantidad_pasos"],
        f"Cantidad de pasos incorrecta: {nombre}",
    )
    vistos = set()
    posiciones = {}
    conteo = Counter()
    por_switch = defaultdict(Counter)
    switches_modificados = set()

    for indice, paso in enumerate(secuencia, start=1):
        pid = paso["referencia_paso"]
        exigir(
            paso["orden_global"] == indice
            and pid in pasos
            and pid not in vistos,
            f"Paso invalido o duplicado: {nombre}/{pid}",
        )
        vistos.add(pid)
        posiciones[pid] = indice
        comunicacion, original = pasos[pid]
        categoria = original["categoria"]
        switch = original["switch"]
        exigir(
            paso["comunicacion"] == comunicacion
            and paso["categoria"] == categoria
            and paso["switch"] == switch,
            f"Paso no coincide con A03: {nombre}/{pid}",
        )
        exigir(categoria in CATEGORIAS, f"Categoria desconocida: {categoria}")
        conteo[categoria] += 1
        por_switch[switch][categoria] += 1

        if categoria in OPENFLOW:
            exigir(pid in operaciones, f"Operacion no existe en A02: {pid}")
            par, op = operaciones[pid]
            exigir(
                par == comunicacion
                and op["comando"] == categoria
                and op["switch"] == switch,
                f"Operacion no coincide con A02: {pid}",
            )
            switches_modificados.add(switch)
        else:
            exigir(pid not in operaciones, f"Paso no OpenFlow figura como operacion: {pid}")

    exigir(vistos == set(pasos), f"Pasos A03 incompletos: {nombre}")
    for dep in dependencias:
        exigir(
            posiciones[dep["antes"]] < posiciones[dep["despues"]],
            f"Dependencia incumplida: {nombre}",
        )

    ejecutables = sum(conteo[t] for t in OPENFLOW)
    barreras = conteo[BARRERA]
    verificaciones = conteo[VERIFICACION]
    exigir(
        ejecutables == tr["cantidad_operaciones_openflow"]
        and ejecutables == len(operaciones)
        and barreras == tr["cantidad_barreras"]
        and ejecutables + barreras + verificaciones == len(secuencia),
        f"Costo y catalogos difieren: {nombre}",
    )

    return {
        "transition_id": nombre,
        "estrategia": tr["estrategia"],
        "comunicaciones_modificadas": comunicaciones,
        "flowmod_add": conteo["FlowMod_ADD_PROPUESTO"],
        "flowmod_modify_strict": conteo["FlowMod_MODIFY_STRICT_PROPUESTO"],
        "groupmod_add": conteo["GroupMod_ADD_PROPUESTO"],
        "total_mensajes_modificacion_propuestos": ejecutables,
        "barrier_request_propuestos": barreras,
        "verificaciones_planificadas": verificaciones,
        "total_pasos_logicos": len(secuencia),
        "switches_con_modificaciones": sorted(switches_modificados),
        "cantidad_switches_con_modificaciones": len(switches_modificados),
        "desglose_por_switch": [
            {
                "switch": sw,
                "flowmod_add": categorias["FlowMod_ADD_PROPUESTO"],
                "flowmod_modify_strict": categorias["FlowMod_MODIFY_STRICT_PROPUESTO"],
                "groupmod_add": categorias["GroupMod_ADD_PROPUESTO"],
                "barrier_request": categorias[BARRERA],
                "verificaciones": categorias[VERIFICACION],
            }
            for sw, categorias in sorted(por_switch.items())
        ],
        "costo_vectorial_sin_pesos": {
            "mensajes_modificacion": ejecutables,
            "barreras": barreras,
            "verificaciones": verificaciones,
            "switches_modificados": len(switches_modificados),
        },
        "costo_temporal_medido": None,
        "costo_monetario_medido": None,
        "ejecutada_en_ovs": False,
    }


def main():
    inicio = time.perf_counter()
    a02 = leer(E04 / "OperacionesOpenFlowPropuestas.json")
    a03 = leer(E04 / "DependenciasOpenFlow.json")
    a04 = leer(E04 / "TransitionsCandidatas.json")

    exigir(
        a02["enlace_fallado"] == a03["enlace_fallado"] == a04["enlace_fallado"],
        "Los artefactos corresponden a fallos diferentes",
    )
    por02, por03, por04 = por_target(a02), por_target(a03), por_target(a04)
    exigir(set(por02) == set(por03) == set(por04), "Targets A02/A03/A04 distintos")

    resultados = []
    registros = []
    distintos_por_target = 0
    for tid in sorted(por04):
        original = por04[tid]
        alternativas = original["transitions"]
        costos = []
        if alternativas:
            operaciones, pasos, deps, comunicaciones = catalogo_target(
                tid, por02[tid], por03[tid]
            )
            vistos = set()
            for tr in alternativas:
                exigir(tr["transition_id"] not in vistos, "Transition repetida")
                vistos.add(tr["transition_id"])
                costo = evaluar_transition(tr, operaciones, pasos, deps, comunicaciones)
                costos.append(costo)
                registros.append({"target_id": tid, **costo})
        exigir(
            len(costos) == original["cantidad_transitions"],
            f"Numero de Transitions incoherente: {tid}",
        )
        perfiles = {
            tuple(c["costo_vectorial_sin_pesos"].values())
            for c in costos
        }
        if len(perfiles) > 1:
            distintos_por_target += 1
        resultados.append({
            "target_id": tid,
            "transitions_evaluadas": len(costos),
            "perfiles_costo_distintos": len(perfiles),
            "costos": costos,
        })

    exigir(
        len(registros) == a04["transitions_generadas"],
        "No se evaluaron todas las Transitions",
    )
    exigir(
        sum(t["transitions_evaluadas"] for t in resultados) == len(registros),
        "Resumen de costo inconsistente",
    )

    salida = E05 / "CostoReconfiguracion.json"
    duracion = time.perf_counter() - inicio
    guardar(salida, {
        "tipo": "CostoReconfiguracion_Estructural_Piloto",
        "generado_utc": datetime.now(timezone.utc).isoformat(),
        "enlace_fallado": a04["enlace_fallado"],
        "targets_analizados": len(resultados),
        "parejas_evaluadas": len(registros),
        "targets_con_distinto_costo_segun_orden": distintos_por_target,
        "tiempo_calculo_s": round(duracion, 6),
        "modificaciones_ejecutadas_en_ovs": 0,
        "criterio": "Vector de costo sin pesos: FlowMod, GroupMod, barreras, verificaciones y switches afectados.",
        "limitaciones": [
            "No equivale a tiempo de instalacion, costo monetario ni uso real de CPU.",
            "BarrierRequest y verificaciones son solicitudes planificadas, no respuestas medidas.",
            "Las operaciones de limpieza o rollback aun no estan catalogadas.",
            "La misma coleccion de operaciones tiene igual costo de conteo independientemente del orden.",
            "Ninguna Transition esta certificada como segura o ejecutada.",
        ],
        "targets": resultados,
    })

    ejemplos = {r["transition_id"]: r for r in registros}
    print("\n=== ETAPA 05 - A04: COSTO DE RECONFIGURACION ===")
    print("Targets analizados:", len(resultados))
    print("Parejas evaluadas:", len(registros))
    print("Targets con costo diferente segun orden:", distintos_por_target)

    for tid in ("T002_TR01", "T013_TR01"):
        if tid in ejemplos:
            c = ejemplos[tid]
            print(f"\n=== {tid} ===")
            print("FlowMod ADD:", c["flowmod_add"])
            print("FlowMod MODIFY_STRICT:", c["flowmod_modify_strict"])
            print("GroupMod ADD:", c["groupmod_add"])
            print("Mensajes de modificacion:", c["total_mensajes_modificacion_propuestos"])
            print("Barreras propuestas:", c["barrier_request_propuestos"])
            print("Verificaciones propuestas:", c["verificaciones_planificadas"])
            print("Pasos totales:", c["total_pasos_logicos"])
            print("Switches afectados:", ", ".join(c["switches_con_modificaciones"]))

    print(f"\nTiempo de calculo: {duracion:.6f} s")
    print("Modificaciones ejecutadas en OVS: 0")
    print("Costo real temporal y monetario: NO MEDIDO")
    print("Archivo generado:", salida)


if __name__ == "__main__":
    main()
