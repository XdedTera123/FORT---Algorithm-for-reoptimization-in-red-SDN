#!/usr/bin/env python3
"""Etapa 05 A05: seleccion preliminar Pareto Target-Transition.

Solo lee resultados del prototipo y genera JSON. No modifica OVS.
La preferencia lexicografica es una politica explicita de priorizacion,
no una demostracion de seguridad o un optimo universal.
"""

import json
import math
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
E04 = BASE / "resultados/etapa04"
E05 = BASE / "resultados/etapa05"

CRITERIOS = (
    "final_mlu_pct",
    "peak_mlu_pct",
    "mensajes_modificacion",
    "barreras",
    "verificaciones",
    "switches_modificados",
)


def exigir(condicion, mensaje):
    if not condicion:
        raise RuntimeError(mensaje)


def leer(ruta):
    exigir(ruta.is_file(), f"No existe: {ruta}")
    return json.loads(ruta.read_text(encoding="utf-8"))


def guardar(ruta, datos):
    ruta.parent.mkdir(parents=True, exist_ok=True)
    tmp = ruta.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(datos, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    tmp.replace(ruta)


def indexar(lista, nombre, campo="transition_id"):
    indice = {}
    for objeto in lista:
        llave = objeto[campo]
        exigir(llave not in indice, f"Duplicado en {nombre}: {llave}")
        indice[llave] = objeto
    return indice


def aplanar(datos, campo_lista):
    """Propaga el Target desde su contenedor sin inventar un identificador."""
    resultado = []
    for t in datos["targets"]:
        for elemento in t[campo_lista]:
            previo = elemento.get("target_id")
            exigir(
                previo is None or previo == t["target_id"],
                f"Target anidado inconsistente: {previo}",
            )
            resultado.append({**elemento, "target_id": t["target_id"]})
    return resultado


def comprobar_numero(valor, nombre):
    exigir(
        isinstance(valor, (int, float))
        and not isinstance(valor, bool)
        and math.isfinite(float(valor))
        and float(valor) >= 0,
        f"Metrica invalida: {nombre}",
    )
    return float(valor)


def igual(a, b):
    return math.isclose(float(a), float(b), rel_tol=1e-6, abs_tol=0.002)


def domina(a, b):
    """a domina b si no empeora ningun criterio y mejora alguno."""
    tolerancias = {
        "final_mlu_pct": 0.002,
        "peak_mlu_pct": 0.002,
    }
    no_peor = all(
        a[k] <= b[k] + tolerancias.get(k, 0)
        for k in CRITERIOS
    )
    mejora_alguno = any(
        a[k] < b[k] - tolerancias.get(k, 0)
        for k in CRITERIOS
    )
    return no_peor and mejora_alguno


def clave_prioridad(p):
    return tuple(p[k] for k in CRITERIOS) + (
        p["target_id"], p["transition_id"]
    )


def main():
    inicio = time.perf_counter()

    final = leer(E05 / "FinalMLU.json")
    peak = leer(E05 / "PeakMLU.json")
    costo = leer(E05 / "CostoReconfiguracion.json")
    factibilidad = leer(E05 / "FactibilidadPreliminar.json")
    transitions = leer(E04 / "TransitionsCandidatas.json")

    fallo = frozenset(final["enlace_fallado"])
    exigir(len(fallo) == 2, "Fallo inicial no valido")

    for nombre, datos in (
        ("Peak", peak),
        ("Costo", costo),
        ("Factibilidad", factibilidad),
        ("Transitions", transitions),
    ):
        exigir(
            frozenset(datos["enlace_fallado"]) == fallo,
            f"Fallo diferente en {nombre}",
        )

    fs = comprobar_numero(final["final_mlu_fs_pct"], "MLU FS")
    exigir(igual(peak["mlu_fs_pct"], fs), "MLU FS difiere en Peak")

    finales = indexar(
        final["parejas_target_transition"], "FinalMLU"
    )
    picos = indexar(aplanar(peak, "transitions"), "PeakMLU")
    costos = indexar(aplanar(costo, "costos"), "Costo")
    fact = indexar(
        aplanar(factibilidad, "evaluaciones"), "Factibilidad"
    )
    catalogo = indexar(
        aplanar(transitions, "transitions"), "Transitions"
    )

    ids = set(finales)
    exigir(
        ids == set(picos) == set(costos) == set(fact) == set(catalogo),
        "Faltan parejas o existen identificadores incompatibles",
    )
    exigir(
        len(ids) == final["parejas_evaluadas"]
        == peak["parejas_evaluadas"]
        == costo["parejas_evaluadas"]
        == factibilidad["parejas_evaluadas"]
        == transitions["transitions_generadas"],
        "Las cantidades de parejas no coinciden",
    )

    resultados = []
    for tid in sorted(ids):
        f = finales[tid]
        p = picos[tid]
        c = costos[tid]
        v = fact[tid]
        t = catalogo[tid]

        exigir(
            tid == f["transition_id"] == p["transition_id"]
            == c["transition_id"] == v["transition_id"]
            == t["transition_id"],
            f"Identificador no coincide: {tid}",
        )
        exigir(
            f["target_id"] == p["target_id"]
            == t["target_id"],
            f"Target no coincide: {tid}",
        )
        exigir(
            f["estrategia"] == p["estrategia"]
            == c["estrategia"] == t["estrategia"],
            f"Estrategia no coincide: {tid}",
        )

        final_mlu = comprobar_numero(
            f["final_mlu_pct"], f"Final {tid}"
        )
        peak_mlu = comprobar_numero(
            p["peak_mlu_estimada_pct"], f"Peak {tid}"
        )

        exigir(
            igual(final_mlu, p["final_mlu_pct"]),
            f"Final MLU inconsistente: {tid}",
        )
        exigir(
            igual(fs, p["mlu_fs_pct"]),
            f"FS inconsistente: {tid}",
        )
        exigir(
            peak_mlu >= max(fs, final_mlu) - 0.002,
            f"Peak inferior al inicio/final: {tid}",
        )

        costo_vector = c["costo_vectorial_sin_pesos"]
        vector = {
            "mensajes_modificacion": int(
                costo_vector["mensajes_modificacion"]
            ),
            "barreras": int(costo_vector["barreras"]),
            "verificaciones": int(costo_vector["verificaciones"]),
            "switches_modificados": int(
                costo_vector["switches_modificados"]
            ),
        }
        for clave, numero in vector.items():
            exigir(numero >= 0, f"Costo negativo: {tid}/{clave}")

        exigir(
            vector["mensajes_modificacion"]
            == c["total_mensajes_modificacion_propuestos"]
            == t["cantidad_operaciones_openflow"],
            f"Mensajes de modificacion inconsistentes: {tid}",
        )
        exigir(
            vector["barreras"]
            == c["barrier_request_propuestos"]
            == t["cantidad_barreras"],
            f"Barreras inconsistentes: {tid}",
        )
        exigir(
            vector["verificaciones"]
            == c["verificaciones_planificadas"],
            f"Verificaciones inconsistentes: {tid}",
        )
        exigir(
            vector["switches_modificados"]
            == c["cantidad_switches_con_modificaciones"],
            f"Switches de costo inconsistentes: {tid}",
        )

        divergentes = int(p["estados_con_ip_arp_divergentes"])
        exigir(
            divergentes == v["estados_con_divergencia_ip_arp"],
            f"Divergencias IP/ARP inconsistentes: {tid}",
        )

        estructural = (
            v["estado_evaluacion"]
            == "PASA_ESTRUCTURA_PENDIENTE_SEGURIDAD"
            and not v["problemas_estructurales"]
        )
        capacidad = (
            peak_mlu <= 100.0 + 0.002
            and p["supera_capacidad_modelada"] is False
        )
        elegible_modelo = estructural and capacidad
        exigir(
            f["factibilidad_preliminar"] == v["estado_evaluacion"],
            f"Factibilidad de Final MLU distinta: {tid}",
        )
        exigir(
            f["seguridad_definitiva_demostrada"] is False
            and v["factibilidad_definitiva_demostrada"] is False
            and p["factibilidad_definitiva_demostrada"] is False,
            f"Revisar evidencia de seguridad en {tid}: este selector "
            "solo admite evaluaciones piloto no certificadas",
        )

        resultados.append({
            "target_id": f["target_id"],
            "transition_id": tid,
            "estrategia": f["estrategia"],
            "final_mlu_pct": round(final_mlu, 4),
            "peak_mlu_pct": round(peak_mlu, 4),
            "incremento_peak_sobre_fs_pp": round(peak_mlu - fs, 4),
            **vector,
            "estados_ip_arp_divergentes": divergentes,
            "pasa_validacion_estructural": estructural,
            "no_supera_capacidad_modelada": capacidad,
            "elegible_para_comparacion_preliminar": elegible_modelo,
            "seguridad_definitiva_demostrada": False,
            "en_frente_pareto": False,
            "dominada_por": [],
        })

    elegibles = [
        r for r in resultados
        if r["elegible_para_comparacion_preliminar"]
    ]

    frente = []
    for x in elegibles:
        dominantes = [
            y["transition_id"] for y in elegibles
            if y["transition_id"] != x["transition_id"]
            and domina(y, x)
        ]
        x["dominada_por"] = dominantes
        if not dominantes:
            x["en_frente_pareto"] = True
            frente.append(x)

    frente.sort(key=clave_prioridad)
    preferida = frente[0] if frente else None

    # Comparaciones por conteos y utilizacion; no equivalen a seguridad.
    resumen = {
        "tipo": "SeleccionPareja_Pareto_Preliminar",
        "generado_utc": datetime.now(timezone.utc).isoformat(),
        "enlace_fallado": sorted(fallo),
        "referencia_fs": "T000",
        "mlu_fs_pct": fs,
        "parejas_evaluadas": len(resultados),
        "parejas_elegibles_preliminarmente": len(elegibles),
        "parejas_excluidas_modelo": len(resultados) - len(elegibles),
        "cantidad_frente_pareto": len(frente),
        "criterios_pareto_minimizar": list(CRITERIOS),
        "criterio_desempate_preliminar": (
            "Preferencia lexicografica explicita: Final MLU, "
            "Peak MLU, mensajes, barreras, verificaciones, switches. "
            "No es una suma ponderada ni un optimo absoluto."
        ),
        "pareja_preferida_modelo": (
            {
                k: preferida[k]
                for k in (
                    "target_id", "transition_id", "estrategia",
                    "final_mlu_pct", "peak_mlu_pct", *CRITERIOS[2:],
                    "estados_ip_arp_divergentes",
                )
            }
            if preferida else None
        ),
        "pareja_definitivamente_factible_seleccionada": None,
        "razon_sin_seleccion_definitiva": (
            "Ninguna pareja cuenta con ejecucion real en OS-Ken, "
            "verificacion de reglas/conflictos en OVS y proteccion "
            "extremo a extremo demostrada."
        ),
        "frente_pareto": [
            {
                "target_id": r["target_id"],
                "transition_id": r["transition_id"],
                **{k: r[k] for k in CRITERIOS},
                "estados_ip_arp_divergentes":
                    r["estados_ip_arp_divergentes"],
            }
            for r in frente
        ],
        "limitaciones": [
            "Se comparan solo las Transitions candidatas generadas, "
            "no todo el espacio posible de soluciones.",
            "Final MLU y Peak MLU son estimaciones basadas en demandas "
            "observadas del piloto, no mediciones de una reconfiguracion.",
            "Los costos son conteos de operaciones, no tiempos ni dinero.",
            "Las divergencias IP/ARP se registran como riesgos pendientes; "
            "no se convierten arbitrariamente en pesos de utilidad.",
            "La preferencia es provisional; no constituye autorizacion "
            "para aplicar FlowMod ni GroupMod.",
        ],
        "parejas": resultados,
        "tiempo_seleccion_s": round(time.perf_counter() - inicio, 6),
        "modificaciones_ejecutadas_en_ovs": 0,
    }

    salida = E05 / "SeleccionPareja.json"
    guardar(salida, resumen)

    print("\n=== ETAPA 05 - A05: SELECCION TARGET-TRANSITION ===")
    print("Fallo:", " - ".join(x.upper() for x in sorted(fallo)))
    print("Parejas evaluadas:", len(resultados))
    print("Parejas elegibles preliminarmente:", len(elegibles))
    print("Parejas excluidas en el modelo:", len(resultados) - len(elegibles))
    print("Parejas no dominadas (Pareto):", len(frente))
    print("Final MLU FS:", fs, "%")

    print("\n=== FRENTE DE PARETO (PRIMERAS 10) ===")
    for p in frente[:10]:
        print(
            p["transition_id"],
            "| Final:", p["final_mlu_pct"], "%",
            "| Peak:", p["peak_mlu_pct"], "%",
            "| Mensajes:", p["mensajes_modificacion"],
            "| Barreras:", p["barreras"],
        )

    print("\n=== PREFERENCIA PRELIMINAR ===")
    if preferida:
        print("Target:", preferida["target_id"])
        print("Transition:", preferida["transition_id"])
        print("Final MLU:", preferida["final_mlu_pct"], "%")
        print("Peak MLU:", preferida["peak_mlu_pct"], "%")
        print("Mensajes:", preferida["mensajes_modificacion"])
        print("Estados IP/ARP divergentes:", preferida["estados_ip_arp_divergentes"])
    else:
        print("No hay parejas elegibles en el modelo")

    print("Factibilidad definitiva demostrada: NO")
    print("Pareja definitivamente seleccionada: NINGUNA")
    print("Modificaciones ejecutadas en OVS: 0")
    print("Tiempo de seleccion: %.6f s" % resumen["tiempo_seleccion_s"])
    print("Archivo generado:", salida)


if __name__ == "__main__":
    main()
