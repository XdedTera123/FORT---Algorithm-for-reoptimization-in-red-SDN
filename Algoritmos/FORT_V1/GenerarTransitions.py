
#!/usr/bin/env python3
"""Etapa 04 A04: Transitions alternativas no ejecutables por Target."""

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
E04 = BASE / "resultados/etapa04"


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


def validar_plan(plan, original):
    etiqueta = f'{plan["origen"]}->{plan["destino"]}'

    exigir(
        (plan["origen"], plan["destino"])
        == (original["origen"], original["destino"]),
        f"Plan A02/A03 diferente: {etiqueta}",
    )

    pasos = plan["pasos_ordenados"]
    ids = [p["id"] for p in pasos]

    exigir(
        len(ids) == len(set(ids)),
        f"IDs repetidos en {etiqueta}",
    )

    posiciones = {
        identificador: i
        for i, identificador in enumerate(ids)
    }

    for d in plan["dependencias"]:
        a, b = d["antes"], d["despues"]

        exigir(
            a in posiciones
            and b in posiciones
            and posiciones[a] < posiciones[b],
            f"Dependencia incumplida: {a} -> {b}",
        )

    originales = {
        o["id"] for o in original["operaciones"]
    }

    incluidos = {
        p["referencia_operacion"]
        for p in pasos
        if "referencia_operacion" in p
    }

    exigir(
        incluidos == originales,
        f"Operaciones A02/A03 distintas: {etiqueta}",
    )

    exigir(
        len(originales) == original["cantidad_operaciones"]
        and len(incluidos)
        == plan["cantidad_operaciones_openflow"],
        f"Cantidad de operaciones incorrecta: {etiqueta}",
    )

    exigir(
        len(pasos) == plan["cantidad_pasos"],
        f"Cantidad de pasos incorrecta: {etiqueta}",
    )

    if plan["estado"] == "BLOQUEADO":
        exigir(
            original["estado_plan"].startswith("BLOQUEADO"),
            f"Bloqueo inconsistente: {etiqueta}",
        )

    else:
        exigir(
            plan["estado"] == "ORDENADO_NO_VALIDADO",
            f"Estado desconocido: {etiqueta}",
        )

        exigir(
            original["estado_plan"]
            == "PROPUESTA_REQUIERE_VALIDACION",
            f"Estado A02 incompatible: {etiqueta}",
        )

        activaciones = sum(
            p["categoria"]
            == "FlowMod_MODIFY_STRICT_PROPUESTO"
            for p in pasos
        )

        exigir(
            activaciones == 2,
            f"Activaciones inesperadas: {etiqueta}",
        )

    return pasos


def conflictos_estructurales(planes):
    """Detecta duplicaciones basicas entre planes del mismo Target."""

    reglas = {}
    activaciones = {}
    grupos = {}
    vlans = {}
    conflictos = []
    switches_por_plan = []

    for plan in planes:
        par = f'{plan["origen"]}->{plan["destino"]}'
        switches = set()
        vlan = plan.get("vlan_provisional")

        if vlan is not None:
            if vlan in vlans:
                conflictos.append(
                    f"VLAN {vlan} repetida entre "
                    f"{par} y {vlans[vlan]}"
                )
            vlans[vlan] = par

        for op in plan["operaciones"]:
            sw = op["switch"]
            switches.add(sw)
            comando = op["comando"]

            if comando == "FlowMod_ADD_PROPUESTO":
                clave = (
                    sw,
                    op.get("tabla"),
                    op.get("prioridad_provisional"),
                    json.dumps(
                        op.get("match"),
                        sort_keys=True,
                    ),
                )

                if clave in reglas and reglas[clave] != par:
                    conflictos.append(
                        f"FlowMod con match repetido en {sw}"
                    )

                reglas[clave] = par

            elif comando == "FlowMod_MODIFY_STRICT_PROPUESTO":
                clave = (
                    sw,
                    json.dumps(
                        op.get("match_objetivo"),
                        sort_keys=True,
                    ),
                )

                if (
                    clave in activaciones
                    and activaciones[clave] != par
                ):
                    conflictos.append(
                        f"Activacion duplicada en {sw}"
                    )

                activaciones[clave] = par

            elif comando == "GroupMod_ADD_PROPUESTO":
                clave = (
                    sw,
                    int(op["group_id_provisional"]),
                )

                if clave in grupos:
                    conflictos.append(
                        f"GroupMod duplicado: {clave}"
                    )

                grupos[clave] = par

            else:
                conflictos.append(
                    f"Comando no reconocido: {comando}"
                )

        switches_por_plan.append(switches)

    compartidos = []

    if len(switches_por_plan) >= 2:
        compartidos = sorted(
            set.intersection(*switches_por_plan)
        )

    return sorted(set(conflictos)), compartidos


def construir_variantes(planes):
    """Genera ordenes globales preservando cada DAG local."""

    ordenados = sorted(
        planes,
        key=lambda p: (p["origen"], p["destino"]),
    )

    def nombre(p):
        return f'{p["origen"]}->{p["destino"]}'

    def secuencial(orden):
        return [
            (nombre(p), paso)
            for p in orden
            for paso in p["pasos_ordenados"]
        ]

    candidatos = [
        ("SECUENCIAL_ASC", secuencial(ordenados))
    ]

    if len(ordenados) >= 2:
        candidatos.append((
            "SECUENCIAL_DESC",
            secuencial(list(reversed(ordenados))),
        ))

        preparaciones = []
        activaciones = []

        for p in ordenados:
            pasos = p["pasos_ordenados"]

            indices = [
                i for i, paso in enumerate(pasos)
                if paso["categoria"]
                == "FlowMod_MODIFY_STRICT_PROPUESTO"
            ]

            exigir(
                bool(indices),
                f"No hay activacion en {nombre(p)}",
            )

            corte = indices[0]

            preparaciones.extend(
                (nombre(p), paso)
                for paso in pasos[:corte]
            )

            activaciones.extend(
                (nombre(p), paso)
                for paso in pasos[corte:]
            )

        candidatos.append((
            "PREPARAR_TODOS_LUEGO_ACTIVAR",
            preparaciones + activaciones,
        ))

    distintas = []
    firmas = set()

    for estrategia, pasos in candidatos:
        firma = tuple(
            paso["id"] for _, paso in pasos
        )

        if firma in firmas:
            continue

        firmas.add(firma)

        posiciones = {
            paso["id"]: i
            for i, (_, paso) in enumerate(pasos)
        }

        exigir(
            len(posiciones) == len(pasos),
            "IDs duplicados entre comunicaciones",
        )

        for p in planes:
            locales = p["pasos_ordenados"]

            indices = [
                posiciones[paso["id"]]
                for paso in locales
            ]

            exigir(
                indices == sorted(indices),
                "Se altero el orden local de A03",
            )

            for d in p["dependencias"]:
                exigir(
                    posiciones[d["antes"]]
                    < posiciones[d["despues"]],
                    f"Dependencia incumplida: {estrategia}",
                )

        distintas.append((estrategia, pasos))

    return distintas


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--max-transitions",
        type=int,
        default=3,
    )

    args = parser.parse_args()

    exigir(
        1 <= args.max_transitions <= 3,
        "El presupuesto piloto debe estar entre 1 y 3",
    )

    inicio = time.perf_counter()

    dependencias = leer(
        E04 / "DependenciasOpenFlow.json"
    )

    operaciones = leer(
        E04 / "OperacionesOpenFlowPropuestas.json"
    )

    exigir(
        dependencias["enlace_fallado"]
        == operaciones["enlace_fallado"],
        "Los registros corresponden a fallos distintos",
    )

    por_id = {
        t["target_id"]: t
        for t in operaciones["targets"]
    }

    exigir(
        len(por_id) == len(operaciones["targets"]),
        "Targets A02 duplicados",
    )

    exigir(
        set(por_id)
        == {
            t["target_id"]
            for t in dependencias["targets"]
        },
        "Targets A02 y A03 diferentes",
    )

    resultados = []
    total_transitions = 0
    bloqueados = 0
    sin_cambios = 0
    conflictos_globales = 0

    for target in dependencias["targets"]:
        tid = target["target_id"]
        original = por_id[tid]

        planes = target["planes"]

        originales = {
            (p["origen"], p["destino"]): p
            for p in original["planes"]
        }

        exigir(
            len(originales) == len(original["planes"])
            and len(planes) == len(originales),
            f"Planes inconsistentes: {tid}",
        )

        for plan in planes:
            clave = (plan["origen"], plan["destino"])

            exigir(
                clave in originales,
                f"Plan ausente de A02: {tid}/{clave}",
            )

            validar_plan(plan, originales[clave])

        conflictos, compartidos = conflictos_estructurales(
            list(originales.values())
        )

        if not planes:
            exigir(
                tid == "T000",
                f"Target sin cambios inesperado: {tid}",
            )

            sin_cambios += 1
            estado = "REFERENCIA_FS_SIN_CAMBIOS"
            variantes = []

        elif any(
            p["estado"] == "BLOQUEADO"
            for p in planes
        ):
            bloqueados += 1
            estado = "BLOQUEADO_POR_PLAN_LOCAL"
            variantes = []

        elif conflictos:
            conflictos_globales += 1
            estado = "BLOQUEADO_POR_CONFLICTO_ESTRUCTURAL"
            variantes = []

        else:
            estado = "CANDIDATAS_NO_VALIDADAS"

            variantes = construir_variantes(
                planes
            )[:args.max_transitions]

        transitions = []

        for numero, (estrategia, pasos) in enumerate(
            variantes, start=1
        ):
            transitions.append({
                "transition_id": f"{tid}_TR{numero:02d}",
                "estrategia": estrategia,
                "estado": "PROPUESTA_NO_EJECUTABLE",
                "cantidad_pasos": len(pasos),
                "cantidad_operaciones_openflow": sum(
                    paso["categoria"].startswith(
                        ("FlowMod_", "GroupMod_")
                    )
                    for _, paso in pasos
                ),
                "cantidad_barreras": sum(
                    paso["categoria"]
                    == "BarrierRequest_PROPUESTO"
                    for _, paso in pasos
                ),
                "pasos": [
                    {
                        "orden_global": i,
                        "comunicacion": par,
                        "referencia_paso": paso["id"],
                        "categoria": paso["categoria"],
                        "switch": paso["switch"],
                        "condicion_de_avance": (
                            "esperar BarrierReply del switch"
                            if paso["categoria"]
                            == "BarrierRequest_PROPUESTO"
                            else "pendiente de validacion en OS-Ken"
                        ),
                    }
                    for i, (par, paso) in enumerate(
                        pasos, start=1
                    )
                ],
            })

        total_transitions += len(transitions)

        resultados.append({
            "target_id": tid,
            "estado_target": estado,
            "cantidad_planes": len(planes),
            "cantidad_planes_bloqueados": sum(
                p["estado"] == "BLOQUEADO"
                for p in planes
            ),
            "switches_compartidos_por_todos_los_planes":
                compartidos,
            "conflictos_estructurales_detectados":
                conflictos,
            "cantidad_transitions": len(transitions),
            "transitions": transitions,
        })

    exigir(
        len(resultados)
        == dependencias["targets_analizados"],
        "Numero de Targets inconsistente",
    )

    duracion = time.perf_counter() - inicio

    archivo = E04 / "TransitionsCandidatas.json"

    guardar(archivo, {
        "tipo": "TransitionsCandidatas_NoEjecutables",
        "generado_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "enlace_fallado":
            dependencias["enlace_fallado"],
        "targets_analizados": len(resultados),
        "targets_referencia_sin_cambios": sin_cambios,
        "targets_bloqueados_por_plan": bloqueados,
        "targets_bloqueados_por_conflicto_estructural":
            conflictos_globales,
        "transitions_generadas": total_transitions,
        "presupuesto_maximo_por_target":
            args.max_transitions,
        "tiempo_generacion_s": round(duracion, 6),
        "modificaciones_ejecutadas_en_ovs": 0,
        "limitaciones": [
            "Las secuencias son propuestas no ejecutables.",
            "No se garantiza ausencia de conflictos "
            "contra las reglas reales de OVS.",
            "No se ha validado proteccion extremo a extremo.",
            "No se ha calculado Peak MLU.",
            "No se han evaluado estados intermedios.",
            "Cada BarrierRequest requiere confirmar "
            "su correspondiente BarrierReply.",
            "Los Targets bloqueados no producen Transitions.",
            "Las alternativas de un Target no deben "
            "ejecutarse simultaneamente.",
        ],
        "targets": resultados,
    })

    ejemplo = next(
        (
            t for t in resultados
            if t["target_id"] == "T002"
        ),
        None,
    )

    print("\n=== ETAPA 04 - A04: MULTIPLES TRANSITIONS ===")
    print("Targets analizados:", len(resultados))
    print("Targets bloqueados por plan local:", bloqueados)
    print(
        "Targets con conflicto estructural:",
        conflictos_globales,
    )
    print("Referencia FS sin cambios:", sin_cambios)
    print(
        "Transitions candidatas generadas:",
        total_transitions,
    )

    if ejemplo:
        print("\n=== EJEMPLO T002 ===")
        print("Planes:", ejemplo["cantidad_planes"])
        print(
            "Switches compartidos:",
            ", ".join(
                ejemplo[
                    "switches_compartidos_por_todos_los_planes"
                ]
            ) or "NINGUNO",
        )

        for transition in ejemplo["transitions"]:
            print(
                transition["transition_id"],
                "|", transition["estrategia"],
                "| pasos:", transition["cantidad_pasos"],
            )

    print(f"\nTiempo de generacion: {duracion:.6f} s")
    print("Modificaciones ejecutadas en OVS: 0")
    print("Factibilidad y Peak MLU: PENDIENTES")
    print("Archivo generado:", archivo)


if __name__ == "__main__":
    main()
