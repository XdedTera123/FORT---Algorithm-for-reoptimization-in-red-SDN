
#!/usr/bin/env python3
"""Etapa 03 - Actividad 03: Targets con busqueda acotada."""

import argparse
import hashlib
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path

from CalcularCaminos import (
    construir_grafo,
    verificar_estado_actual,
)

BASE = Path(__file__).resolve().parents[1]
DIR = BASE / "resultados/etapa03"
SALIDA = DIR / "TargetsCandidatos.json"


def cargar(nombre):
    return json.loads(Path(nombre).read_text(encoding="utf-8"))


def exigir(condicion, mensaje):
    if not condicion:
        raise RuntimeError(mensaje)


def preparar_datos(topologia, estado, caminos):
    grafo = construir_grafo(topologia)
    verificar_estado_actual(topologia)

    fallo = frozenset(estado["enlace_fallado"])
    fallos_topologia = {
        frozenset((e["extremo_a"], e["extremo_b"]))
        for e in topologia["enlaces_caidos"]
    }

    exigir(
        fallos_topologia == {fallo}
        and frozenset(caminos["enlace_fallado"]) == fallo,
        "Los archivos pertenecen a fallos diferentes"
    )

    hosts = {
        h["nombre"]: h["switch"]
        for h in topologia["hosts"]
    }

    pares_esperados = {
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
        set(fs) == pares_esperados
        and len(estado["estado"]["FS"]["comunicaciones"])
        == len(pares_esperados),
        "FS incompleto o duplicado"
    )

    datos = {}

    for entrada in caminos["comunicaciones"]:
        par = (entrada["origen"], entrada["destino"])

        exigir(
            par in pares_esperados and par not in datos,
            f"Comunicacion invalida: {par}"
        )

        exigir(
            entrada["ruta_fs_referencia"] == fs[par],
            f"Referencia FS diferente: {par}"
        )

        referencia = None
        alternativas = []
        rutas_vistas = set()
        ids_vistos = set()

        for candidato in entrada["candidatos"]:
            ruta = candidato["ruta"]
            switches = ruta[1:-1]

            exigir(
                ruta[0] == par[0]
                and ruta[-1] == par[1]
                and switches[0] == hosts[par[0]]
                and switches[-1] == hosts[par[1]],
                f"Extremos incorrectos: {par}"
            )

            exigir(
                len(switches) == len(set(switches))
                and all(
                    b in grafo[a]
                    for a, b in zip(switches, switches[1:])
                ),
                f"Ruta invalida: {par}"
            )

            firma_ruta = tuple(ruta)
            identificador = candidato["id"]

            exigir(
                firma_ruta not in rutas_vistas
                and identificador not in ids_vistos,
                f"Candidato duplicado: {par}"
            )

            rutas_vistas.add(firma_ruta)
            ids_vistos.add(identificador)

            es_fs = ruta == fs[par]

            exigir(
                candidato["es_ruta_fs"] == es_fs,
                f"Indicador FS inconsistente: {par}"
            )

            if es_fs:
                exigir(
                    referencia is None,
                    f"Dos rutas FS para {par}"
                )
                referencia = candidato
            else:
                alternativas.append(candidato)

        exigir(
            referencia is not None,
            f"Falta ruta FS: {par}"
        )

        datos[par] = {
            "referencia": referencia,
            "alternativas": alternativas
        }

    exigir(
        set(datos) == pares_esperados,
        "Faltan comunicaciones"
    )

    exigir(
        caminos["cantidad_comunicaciones"] == len(datos)
        and caminos["cantidad_candidatos"] == sum(
            1 + len(v["alternativas"])
            for v in datos.values()
        ),
        "Totales de candidatos inconsistentes"
    )

    return datos, sorted(fallo)


def generar(datos, presupuesto, semilla, tiempo_limite,
            propuestas_por_target):
    azar = random.Random(semilla)
    pares = sorted(datos)

    modificables = [
        p for p in pares
        if datos[p]["alternativas"]
    ]

    exigir(
        bool(modificables),
        "No existen rutas alternativas disponibles"
    )

    # Diversificar la cantidad de comunicaciones modificadas.
    niveles = list(dict.fromkeys(
        min(n, len(modificables))
        for n in (1, 2, 3, 5, 8, len(modificables))
    ))

    vistos = set()
    firmas = []
    targets = []
    frecuencia_cambios = {p: 0 for p in pares}

    def firma(cambios):
        return tuple(
            cambios.get(p, datos[p]["referencia"])["id"]
            for p in pares
        )

    def guardar(cambios, estrategia):
        identificadores = firma(cambios)

        if identificadores in vistos:
            return False

        vistos.add(identificadores)
        firmas.append(identificadores)

        configuracion = []
        modificadas = []

        for p in pares:
            referencia = datos[p]["referencia"]
            elegido = cambios.get(p, referencia)
            diferente = elegido["ruta"] != referencia["ruta"]

            configuracion.append({
                "origen": p[0],
                "destino": p[1],
                "camino_id": elegido["id"],
                "ruta": elegido["ruta"],
                "es_ruta_fs": not diferente
            })

            if diferente:
                frecuencia_cambios[p] += 1
                modificadas.append({
                    "origen": p[0],
                    "destino": p[1],
                    "ruta_fs": referencia["ruta"],
                    "ruta_target": elegido["ruta"]
                })

        huella = hashlib.sha256(
            json.dumps(
                identificadores,
                separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()

        targets.append({
            "id": f"T{len(targets):03d}",
            "estrategia_generacion": estrategia,
            "hash_configuracion": huella,
            "cantidad_comunicaciones": len(pares),
            "cantidad_rutas_modificadas": len(modificadas),
            "comunicaciones_modificadas": modificadas,
            "configuracion": configuracion
        })
        return True

    guardar({}, "referencia_FS")

    inicio = time.perf_counter()

    for indice in range(1, presupuesto):
        if time.perf_counter() - inicio >= tiempo_limite:
            break

        cantidad = niveles[(indice - 1) % len(niveles)]
        propuestas = []

        for _ in range(propuestas_por_target):
            if time.perf_counter() - inicio >= tiempo_limite:
                break

            seleccion = azar.sample(modificables, cantidad)

            cambios = {
                p: azar.choice(datos[p]["alternativas"])
                for p in seleccion
            }

            identificadores = firma(cambios)

            if identificadores in vistos:
                continue

            # Diversidad respecto de Targets ya conservados.
            distancia = min(
                sum(a != b for a, b in zip(
                    identificadores, anterior
                ))
                for anterior in firmas
            )

            # Favorecer comunicaciones menos exploradas
            # cuando haya empate en diversidad.
            cobertura = sum(
                1 / (1 + frecuencia_cambios[p])
                for p in cambios
            )

            propuestas.append(
                (distancia, cobertura, cambios)
            )

        if not propuestas:
            continue

        mejor = max(
            propuestas,
            key=lambda x: (x[0], x[1])
        )

        guardar(
            mejor[2],
            f"diversificada_{cantidad}_cambios"
        )

    tiempo_real = time.perf_counter() - inicio
    return targets, tiempo_real, niveles


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-targets", type=int, default=40)
    parser.add_argument("--semilla", type=int, default=2026)
    parser.add_argument("--max-segundos", type=float, default=30)
    parser.add_argument(
        "--propuestas-por-target", type=int, default=24
    )
    args = parser.parse_args()

    exigir(args.max_targets >= 2, "Presupuesto invalido")
    exigir(args.max_segundos > 0, "Tiempo limite invalido")
    exigir(
        args.propuestas_por_target >= 1,
        "Numero de propuestas invalido"
    )

    topologia = cargar(DIR / "TopologiaPostFallo.json")
    estado = cargar(
        BASE / "resultados/etapa02/EstadoPostFallo.json"
    )
    caminos = cargar(DIR / "CaminosCandidatos.json")

    datos, fallo = preparar_datos(
        topologia, estado, caminos
    )

    targets, segundos, niveles = generar(
        datos,
        args.max_targets,
        args.semilla,
        args.max_segundos,
        args.propuestas_por_target
    )

    individuales = sum(
        t["cantidad_rutas_modificadas"] == 1
        for t in targets
    )
    multiples = sum(
        t["cantidad_rutas_modificadas"] > 1
        for t in targets
    )

    resultado = {
        "tipo": "Targets_Candidatos_PostFallo",
        "generado_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "enlace_fallado": fallo,
        "captura_origen_simultanea": estado[
            "validacion"
        ]["captura_simultanea"],
        "metodo": "Busqueda acotada y diversificada",
        "semilla": args.semilla,
        "presupuesto_targets": args.max_targets,
        "tiempo_limite_s": args.max_segundos,
        "propuestas_por_target": args.propuestas_por_target,
        "niveles_cambios": niveles,
        "tiempo_generacion_s": round(segundos, 6),
        "presupuesto_completado": (
            len(targets) == args.max_targets
        ),
        "cantidad_comunicaciones_por_target": len(datos),
        "cantidad_targets": len(targets),
        "targets": targets,
        "nota": (
            "Alternativas topologicas. Aun no se han "
            "evaluado demanda, MLU, proteccion ni "
            "factibilidad de transicion."
        )
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

    print("\n=== TARGETS - BUSQUEDA ACOTADA ===")
    print("Fallo:", " - ".join(s.upper() for s in fallo))
    print("Comunicaciones:", len(datos))
    print("Presupuesto:", args.max_targets)
    print("Targets generados:", len(targets))
    print("Referencia FS:", targets[0]["id"])
    print("Targets con 1 cambio:", individuales)
    print("Targets con varios cambios:", multiples)
    print("Duplicados conservados: 0")
    print(f"Tiempo de generacion: {segundos:.6f} s")
    print(
        "Presupuesto completado:",
        "SI" if len(targets) == args.max_targets else "NO"
    )
    print("Estado OVS: VERIFICADO")
    print("Estimacion de carga: PENDIENTE")
    print("Archivo generado:", SALIDA)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError) as error:
        raise SystemExit(f"ERROR: {error}")
