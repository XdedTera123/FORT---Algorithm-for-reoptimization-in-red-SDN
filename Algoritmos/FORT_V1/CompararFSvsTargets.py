
#!/usr/bin/env python3
"""Etapa 04 - A01: comparar las rutas FS con todos los Targets."""

import json
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
ETAPA02 = BASE / "resultados/etapa02"
ETAPA03 = BASE / "resultados/etapa03"
ETAPA04 = BASE / "resultados/etapa04"


def exigir(condicion, mensaje):
    if not condicion:
        raise RuntimeError(mensaje)


def leer(ruta):
    exigir(ruta.is_file(), f"Archivo no encontrado: {ruta}")
    return json.loads(ruta.read_text(encoding="utf-8"))


def obtener_rutas(comunicaciones, campo, origen_datos):
    rutas = {}

    for c in comunicaciones:
        par = (c["origen"], c["destino"])
        ruta = c.get(campo)

        exigir(
            isinstance(ruta, list)
            and len(ruta) >= 3
            and all(isinstance(n, str) for n in ruta),
            f"Ruta invalida en {origen_datos}: {par}",
        )

        exigir(
            ruta[0] == par[0]
            and ruta[-1] == par[1]
            and len(ruta) == len(set(ruta)),
            f"Extremos o ciclos invalidos en {origen_datos}: {par}",
        )

        exigir(
            par not in rutas,
            f"Comunicacion duplicada en {origen_datos}: {par}",
        )

        rutas[par] = tuple(ruta)

    return rutas


def arcos(ruta):
    return list(zip(ruta, ruta[1:]))


def siguientes_saltos(ruta):
    return {
        nodo: ruta[i + 1]
        for i, nodo in enumerate(ruta[:-1])
        if nodo.startswith("s")
    }


def comparar_rutas(par, ruta_fs, ruta_target):
    antiguos = arcos(ruta_fs)
    nuevos = arcos(ruta_target)

    retirados = [
        list(arco) for arco in antiguos
        if arco not in nuevos
    ]
    agregados = [
        list(arco) for arco in nuevos
        if arco not in antiguos
    ]

    saltos_fs = siguientes_saltos(ruta_fs)
    saltos_target = siguientes_saltos(ruta_target)

    switches = sorted(
        set(saltos_fs) | set(saltos_target),
        key=lambda n: (int(n[1:]) if n[1:].isdigit() else 999, n),
    )

    diferencias_salto = []

    for sw in switches:
        anterior = saltos_fs.get(sw)
        propuesto = saltos_target.get(sw)

        if anterior == propuesto:
            continue

        if anterior is None:
            tipo = "INCORPORADO_A_RUTA"
        elif propuesto is None:
            tipo = "RETIRADO_DE_RUTA"
        else:
            tipo = "SIGUIENTE_SALTO_MODIFICADO"

        diferencias_salto.append({
            "switch": sw,
            "tipo": tipo,
            "siguiente_salto_fs": anterior,
            "siguiente_salto_target": propuesto,
        })

    return {
        "origen": par[0],
        "destino": par[1],
        "ruta_fs": list(ruta_fs),
        "ruta_target": list(ruta_target),
        "arcos_retirados": retirados,
        "arcos_agregados": agregados,
        "diferencias_siguiente_salto": diferencias_salto,
        "cantidad_arcos_retirados": len(retirados),
        "cantidad_arcos_agregados": len(agregados),
    }


def main():
    inicio = time.perf_counter()

    fs = leer(ETAPA02 / "FS_postfallo.json")
    estado = leer(ETAPA02 / "EstadoPostFallo.json")
    candidatos = leer(ETAPA03 / "TargetsCandidatos.json")
    filtrados = leer(ETAPA03 / "TargetsFiltrados.json")

    fallo = frozenset(estado["enlace_fallado"])

    exigir(
        frozenset(candidatos["enlace_fallado"]) == fallo
        and frozenset(filtrados["enlace_fallado"]) == fallo,
        "Los archivos no corresponden al mismo fallo",
    )

    fallos_fs = fs["enlaces_fallados_observados"]

    exigir(
        len(fallos_fs) == 1
        and frozenset((
            fallos_fs[0]["extremo_a"],
            fallos_fs[0]["extremo_b"],
        )) == fallo,
        "FS corresponde a otro fallo",
    )

    rutas_fs = obtener_rutas(
        fs["comunicaciones"],
        "ruta_seleccionada",
        "FS",
    )

    exigir(
        len(rutas_fs) == fs["cantidad_comunicaciones"],
        "La cantidad de rutas FS no coincide",
    )

    targets = candidatos["targets"]
    identificadores = [t["id"] for t in targets]

    exigir(
        len(identificadores) == len(set(identificadores))
        and len(targets) == candidatos["cantidad_targets"],
        "Targets duplicados o cantidad inconsistente",
    )

    por_id = {t["id"]: t for t in targets}
    exigir("T000" in por_id, "No existe T000")

    rutas_t000 = obtener_rutas(
        por_id["T000"]["configuracion"],
        "ruta",
        "T000",
    )

    exigir(
        rutas_t000 == rutas_fs,
        "T000 no coincide con las rutas FS observadas",
    )

    admitidos = {
        t["target_id"] for t in filtrados["admitidos"]
    }
    descartados = {
        t["target_id"] for t in filtrados["descartados"]
    }

    exigir(
        not (admitidos & descartados)
        and admitidos | descartados == set(identificadores)
        and len(admitidos) == filtrados["cantidad_admitidos"]
        and len(descartados) == filtrados["cantidad_descartados"],
        "Resultados del filtrado inconsistentes",
    )

    exigir(
        "T000" in admitidos,
        "La referencia FS no fue admitida",
    )

    resultados = []
    total_cambios = 0
    sin_cambios = 0
    un_cambio = 0
    varios_cambios = 0

    for target in targets:
        identificador = target["id"]

        if identificador not in admitidos:
            continue

        rutas_target = obtener_rutas(
            target["configuracion"],
            "ruta",
            identificador,
        )

        exigir(
            set(rutas_target) == set(rutas_fs),
            f"Comunicaciones distintas a FS en {identificador}",
        )

        cambios = []

        for par in sorted(rutas_fs):
            anterior = rutas_fs[par]
            nueva = rutas_target[par]

            if anterior != nueva:
                cambios.append(
                    comparar_rutas(par, anterior, nueva)
                )

        exigir(
            len(cambios) == target["cantidad_rutas_modificadas"],
            f"Numero de cambios inconsistente: {identificador}",
        )

        cantidad = len(cambios)
        total_cambios += cantidad

        if cantidad == 0:
            sin_cambios += 1
        elif cantidad == 1:
            un_cambio += 1
        else:
            varios_cambios += 1

        resultados.append({
            "target_id": identificador,
            "es_referencia_fs": identificador == "T000",
            "cantidad_comunicaciones": len(rutas_target),
            "cantidad_rutas_modificadas": cantidad,
            "cambios": cambios,
        })

    tiempo = time.perf_counter() - inicio

    salida = {
        "tipo": "ComparacionFSvsTargets",
        "generado_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "enlace_fallado": sorted(fallo),
        "referencia_fs": "T000",
        "rutas_fs_verificadas": len(rutas_fs),
        "cantidad_targets_originales": len(targets),
        "cantidad_targets_comparados": len(resultados),
        "targets_sin_cambios": sin_cambios,
        "targets_con_un_cambio": un_cambio,
        "targets_con_varios_cambios": varios_cambios,
        "total_rutas_modificadas_entre_targets":
            total_cambios,
        "tiempo_comparacion_s": round(tiempo, 6),
        "fuentes": {
            "fs": "resultados/etapa02/FS_postfallo.json",
            "targets":
                "resultados/etapa03/TargetsCandidatos.json",
            "filtrado":
                "resultados/etapa03/TargetsFiltrados.json",
        },
        "nota": (
            "Las diferencias de siguientes saltos son "
            "logicas. No representan todavia operaciones "
            "FlowMod ni GroupMod. Se deben considerar "
            "Fast Failover, VLAN y dependencias en las "
            "siguientes actividades."
        ),
        "targets": resultados,
    }

    ETAPA04.mkdir(parents=True, exist_ok=True)

    destino = ETAPA04 / "DiferenciasFSTargets.json"
    temporal = destino.with_suffix(".json.tmp")

    temporal.write_text(
        json.dumps(
            salida, indent=2, ensure_ascii=False
        ) + "\n",
        encoding="utf-8",
    )
    temporal.replace(destino)

    ejemplo = next(
        (t for t in resultados if t["target_id"] == "T001"),
        None,
    )

    print("\n=== ETAPA 04 - A01: COMPARACION FS VS TARGETS ===")
    print("Fallo:", " - ".join(x.upper() for x in sorted(fallo)))
    print("Rutas FS verificadas:", len(rutas_fs))
    print("Targets comparados:", len(resultados))
    print("Targets sin cambios:", sin_cambios)
    print("Targets con un cambio:", un_cambio)
    print("Targets con varios cambios:", varios_cambios)
    print("Total de diferencias de ruta:", total_cambios)

    if ejemplo:
        print("\n=== EJEMPLO T001 ===")
        for cambio in ejemplo["cambios"]:
            print(
                cambio["origen"], "->", cambio["destino"]
            )
            print("FS:", " -> ".join(cambio["ruta_fs"]))
            print(
                "TARGET:",
                " -> ".join(cambio["ruta_target"]),
            )
            print(
                "Switches con diferencia de siguiente salto:",
                ", ".join(
                    d["switch"]
                    for d in cambio["diferencias_siguiente_salto"]
                ),
            )

    print(f"\nTiempo de comparacion: {tiempo:.6f} s")
    print("Operaciones OpenFlow: PENDIENTES")
    print("Archivo generado:", destino)


if __name__ == "__main__":
    main()
