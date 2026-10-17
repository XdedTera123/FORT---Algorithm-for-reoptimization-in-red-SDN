
#!/usr/bin/env python3
"""Etapa 05 - A02: calcular Final MLU por Target y pareja.

Utiliza cargas estimadas con demandas observadas y capacidades RS.
No modifica OVS ni certifica la seguridad de las Transitions.
"""

import json
import math
import time
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
    exigir(ruta.is_file(), f"Falta archivo: {ruta}")
    return json.loads(ruta.read_text(encoding="utf-8"))


def guardar(ruta, datos):
    ruta.parent.mkdir(parents=True, exist_ok=True)
    temporal = ruta.with_suffix(".json.tmp")
    temporal.write_text(
        json.dumps(datos, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporal.replace(ruta)


def validar_fallo(datos, fallo, nombre):
    exigir(
        frozenset(datos["enlace_fallado"]) == fallo,
        f"Fallo inconsistente en {nombre}",
    )


def recursos_rs(rs, topologia):
    recursos = {}

    for r in rs["direcciones"]:
        clave = (r["origen"], r["destino"])

        exigir(
            clave not in recursos,
            f"Direccion RS duplicada: {clave}",
        )
        recursos[clave] = r

    arcos = set()

    for enlace in topologia["enlaces_operativos"]:
        a = enlace["extremo_a"]
        b = enlace["extremo_b"]

        exigir(
            (a, b) not in arcos
            and (b, a) not in arcos,
            f"Enlace repetido: {a}-{b}",
        )

        arcos.add((a, b))
        arcos.add((b, a))

    for arco in arcos:
        exigir(
            arco in recursos,
            f"Direccion ausente de RS: {arco}",
        )

        recurso = recursos[arco]
        capacidad = float(
            recurso["capacidad_operativa_bps"]
        )

        exigir(
            recurso["activo"]
            and math.isfinite(capacidad)
            and capacidad > 0,
            f"Capacidad RS invalida: {arco}",
        )

    return recursos, arcos


def evaluar_target(target, recursos, arcos):
    registros = target["enlaces_dirigidos"]
    vistos = set()
    utilizaciones = []

    for enlace in registros:
        arco = (enlace["origen"], enlace["destino"])

        exigir(
            arco in arcos and arco not in vistos,
            f"Arco desconocido o duplicado: {arco}",
        )

        vistos.add(arco)

        carga = float(enlace["carga_estimada_bps"])
        capacidad_modelo = float(enlace["capacidad_bps"])
        capacidad_rs = float(
            recursos[arco]["capacidad_operativa_bps"]
        )

        exigir(
            math.isfinite(carga)
            and carga >= 0
            and math.isfinite(capacidad_modelo)
            and capacidad_modelo > 0,
            f"Valores invalidos en {arco}",
        )

        exigir(
            math.isclose(
                capacidad_modelo,
                capacidad_rs,
                rel_tol=0.001,
                abs_tol=1000,
            ),
            f"Capacidad estimador/RS diferente en {arco}",
        )

        utilizacion = (
            100.0 * carga / capacidad_rs
        )

        declarada = float(
            enlace["utilizacion_estimada_pct"]
        )

        exigir(
            math.isfinite(declarada)
            and math.isclose(
                utilizacion,
                declarada,
                rel_tol=1e-5,
                abs_tol=0.001,
            ),
            f"Utilizacion inconsistente en {arco}",
        )

        utilizaciones.append({
            "origen": arco[0],
            "destino": arco[1],
            "carga_estimada_bps": carga,
            "capacidad_rs_bps": capacidad_rs,
            "utilizacion_pct": utilizacion,
        })

    exigir(
        vistos == arcos,
        f"Cobertura de enlaces incompleta: "
        f"{target['target_id']}",
    )

    mlu = max(
        e["utilizacion_pct"]
        for e in utilizaciones
    )

    criticos = [
        {
            "origen": e["origen"],
            "destino": e["destino"],
            "utilizacion_pct": round(
                e["utilizacion_pct"], 4
            ),
        }
        for e in utilizaciones
        if math.isclose(
            e["utilizacion_pct"],
            mlu,
            abs_tol=1e-7,
        )
    ]

    return {
        "target_id": target["target_id"],
        "final_mlu_pct": round(mlu, 4),
        "enlaces_criticos": criticos,
        "direcciones_evaluadas": len(utilizaciones),
    }


def comparar(valor, referencia):
    if math.isclose(
        valor, referencia, abs_tol=0.0001
    ):
        return "IGUAL_A_FS"

    if valor < referencia:
        return "MEJORA_FS"

    return "EMPEORA_FS"


def main():
    inicio = time.perf_counter()

    estado = leer(E02 / "EstadoPostFallo.json")
    rs = leer(E02 / "RS_postfallo.json")

    topologia = leer(
        E03 / "TopologiaPostFallo.json"
    )
    estimacion = leer(
        E03 / "EstimacionCargaTargets.json"
    )
    propuestas = leer(
        E03 / "TargetsCandidatos.json"
    )
    filtrados = leer(
        E03 / "TargetsFiltrados.json"
    )
    transitions = leer(
        E04 / "TransitionsCandidatas.json"
    )
    factibilidad = leer(
        E05 / "FactibilidadPreliminar.json"
    )

    fallo = frozenset(estado["enlace_fallado"])

    for nombre, datos in (
        ("Estimacion", estimacion),
        ("Targets", propuestas),
        ("Filtrado", filtrados),
        ("Transitions", transitions),
        ("Factibilidad", factibilidad),
    ):
        validar_fallo(datos, fallo, nombre)

    enlaces_fallados_rs = rs[
        "enlaces_fallados_observados"
    ]

    exigir(
        len(enlaces_fallados_rs) == 1
        and frozenset((
            enlaces_fallados_rs[0]["extremo_a"],
            enlaces_fallados_rs[0]["extremo_b"],
        )) == fallo,
        "RS registra otro enlace fallado",
    )

    recursos, arcos = recursos_rs(
        rs, topologia
    )

    targets_estimados = estimacion["targets"]

    evaluaciones = {
        t["target_id"]: evaluar_target(
            t, recursos, arcos
        )
        for t in targets_estimados
    }

    exigir(
        len(evaluaciones) == len(targets_estimados),
        "Estimaciones de Targets duplicadas",
    )

    ids_targets = {
        t["id"] for t in propuestas["targets"]
    }

    exigir(
        len(ids_targets) == propuestas["cantidad_targets"]
        and ids_targets == set(evaluaciones),
        "Targets y estimaciones diferentes",
    )

    exigir(
        "T000" in evaluaciones,
        "Falta referencia FS T000",
    )

    referencia = evaluaciones["T000"][
        "final_mlu_pct"
    ]

    registrados_fs = [
        t for t in filtrados["admitidos"]
        if t["target_id"] == "T000"
    ]

    exigir(
        len(registrados_fs) == 1
        and math.isclose(
            referencia,
            float(registrados_fs[0][
                "mlu_final_estimada_pct"
            ]),
            abs_tol=0.001,
        ),
        "Final MLU de FS inconsistente con Etapa 03",
    )

    resultados_targets = []

    for identificador in sorted(evaluaciones):
        e = evaluaciones[identificador].copy()

        e["comparacion_con_fs"] = comparar(
            e["final_mlu_pct"], referencia
        )

        e["diferencia_fs_puntos_pct"] = round(
            e["final_mlu_pct"] - referencia, 4
        )

        resultados_targets.append(e)

    # Relacionar cada Transition con su Target.
    por_target_transition = {
        t["target_id"]: t
        for t in transitions["targets"]
    }

    por_target_factibilidad = {
        t["target_id"]: t
        for t in factibilidad["targets"]
    }

    exigir(
        len(por_target_transition)
        == len(transitions["targets"])
        and len(por_target_factibilidad)
        == len(factibilidad["targets"])
        and set(por_target_transition)
        == set(por_target_factibilidad)
        == ids_targets,
        "Cobertura de Targets inconsistente",
    )

    parejas = []

    for tid in sorted(ids_targets):
        alternativas = por_target_transition[tid][
            "transitions"
        ]

        evaluadas = {
            x["transition_id"]: x
            for x in por_target_factibilidad[tid][
                "evaluaciones"
            ]
        }

        exigir(
            len(evaluadas)
            == len(por_target_factibilidad[tid][
                "evaluaciones"
            ]),
            f"Factibilidades duplicadas: {tid}",
        )

        exigir(
            set(evaluadas)
            == {
                tr["transition_id"]
                for tr in alternativas
            },
            f"Transitions sin factibilidad: {tid}",
        )

        for tr in alternativas:
            evaluacion = evaluadas[
                tr["transition_id"]
            ]

            final_mlu = evaluaciones[tid][
                "final_mlu_pct"
            ]

            parejas.append({
                "target_id": tid,
                "transition_id": tr["transition_id"],
                "estrategia": tr["estrategia"],
                "final_mlu_pct": final_mlu,
                "comparacion_con_fs": comparar(
                    final_mlu, referencia
                ),
                "diferencia_fs_puntos_pct": round(
                    final_mlu - referencia, 4
                ),
                "factibilidad_preliminar":
                    evaluacion["estado_evaluacion"],
                "seguridad_definitiva_demostrada":
                    evaluacion[
                        "factibilidad_definitiva_demostrada"
                    ],
            })

    exigir(
        len(parejas)
        == transitions["transitions_generadas"]
        == factibilidad["parejas_evaluadas"],
        "Cantidad de parejas inconsistente",
    )

    parejas_estructurales = [
        p for p in parejas
        if p["factibilidad_preliminar"]
        == "PASA_ESTRUCTURA_PENDIENTE_SEGURIDAD"
    ]

    exigir(
        len(parejas_estructurales)
        == factibilidad[
            "parejas_que_pasan_estructura"
        ],
        "Factibilidad estructural inconsistente",
    )

    mejor_general = min(
        resultados_targets,
        key=lambda t: (
            t["final_mlu_pct"],
            t["target_id"],
        ),
    )

    mejor_pareja = (
        min(
            parejas_estructurales,
            key=lambda p: (
                p["final_mlu_pct"],
                p["target_id"],
                p["transition_id"],
            ),
        )
        if parejas_estructurales
        else None
    )

    conteos = {
        estado: sum(
            t["comparacion_con_fs"] == estado
            for t in resultados_targets
        )
        for estado in (
            "MEJORA_FS",
            "IGUAL_A_FS",
            "EMPEORA_FS",
        )
    }

    duracion = time.perf_counter() - inicio

    salida = E05 / "FinalMLU.json"

    guardar(salida, {
        "tipo": "FinalMLU_Estimada_Piloto",
        "generado_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "enlace_fallado": sorted(fallo),
        "referencia_fs": "T000",
        "final_mlu_fs_pct": referencia,
        "targets_evaluados": len(resultados_targets),
        "targets_mejoran_fs": conteos["MEJORA_FS"],
        "targets_igualan_fs": conteos["IGUAL_A_FS"],
        "targets_empeoran_fs": conteos["EMPEORA_FS"],
        "parejas_evaluadas": len(parejas),
        "parejas_pasan_estructura":
            len(parejas_estructurales),
        "mejor_target_por_final_mlu":
            mejor_general["target_id"],
        "mejor_pareja_con_validacion_estructural":
            mejor_pareja,
        "tiempo_calculo_s": round(duracion, 6),
        "modificaciones_ejecutadas_en_ovs": 0,
        "limitaciones": [
            "Final MLU modelada con demandas enviadas "
            "observadas y capacidades RS.",
            "No es una medicion directa del Target "
            "instalado en OVS.",
            "Las Transitions de un mismo Target "
            "comparten Final MLU, pero pueden tener "
            "distinto Peak MLU y costo.",
            "Superar la estructura no demuestra "
            "seguridad definitiva.",
            "No se han evaluado Peak MLU ni "
            "costos de reconfiguracion.",
        ],
        "targets": resultados_targets,
        "parejas_target_transition": parejas,
    })

    print("\n=== ETAPA 05 - A02: FINAL MLU ===")
    print("Fallo:", " - ".join(
        s.upper() for s in sorted(fallo)
    ))
    print("Targets evaluados:", len(resultados_targets))
    print("Parejas evaluadas:", len(parejas))
    print("Final MLU FS:", referencia, "%")
    print("Targets que mejoran FS:", conteos["MEJORA_FS"])
    print("Targets que igualan FS:", conteos["IGUAL_A_FS"])
    print("Targets que empeoran FS:", conteos["EMPEORA_FS"])
    print(
        "Mejor Target global:",
        mejor_general["target_id"],
        "|", mejor_general["final_mlu_pct"], "%",
    )

    if mejor_pareja:
        print(
            "Mejor pareja con validacion estructural:",
            mejor_pareja["target_id"],
            "+", mejor_pareja["transition_id"],
            "|", mejor_pareja["final_mlu_pct"], "%",
        )
    else:
        print(
            "Mejor pareja con validacion estructural: "
            "NINGUNA"
        )

    print("\n=== REFERENCIA T013 ===")

    t013 = evaluaciones.get("T013")

    if t013:
        parejas_t013 = [
            p for p in parejas
            if p["target_id"] == "T013"
        ]

        print("Final MLU:", t013["final_mlu_pct"], "%")
        print("Transitions candidatas:", len(parejas_t013))

    print(f"\nTiempo de calculo: {duracion:.6f} s")
    print("Modificaciones ejecutadas en OVS: 0")
    print("Peak MLU y costo: PENDIENTES")
    print("Archivo generado:", salida)


if __name__ == "__main__":
    main()
