
#!/usr/bin/env python3
"""Etapa 03 - Actividad 02: caminos candidatos post-fallo."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from ActualizarTopologia import puertos_ovs

BASE = Path(__file__).resolve().parents[1]
DIR = BASE / "resultados/etapa03"
ENTRADA = DIR / "TopologiaPostFallo.json"
ESTADO = BASE / "resultados/etapa02/EstadoPostFallo.json"
SALIDA = DIR / "CaminosCandidatos.json"


def cargar(ruta):
    return json.loads(ruta.read_text(encoding="utf-8"))


def exigir(condicion, mensaje):
    if not condicion:
        raise RuntimeError(mensaje)


def construir_grafo(topologia):
    switches = set(topologia["switches"])

    exigir(
        set(topologia["adyacencia"]) == switches,
        "Lista de switches inconsistente"
    )

    grafo = {
        sw: set(vecinos)
        for sw, vecinos in topologia["adyacencia"].items()
    }

    for sw, vecinos in grafo.items():
        for vecino in vecinos:
            exigir(
                vecino in switches
                and vecino != sw
                and sw in grafo[vecino],
                f"Adyacencia invalida: {sw}-{vecino}"
            )

    enlaces_grafo = {
        frozenset((a, b))
        for a, vecinos in grafo.items()
        for b in vecinos
    }

    enlaces_registrados = {
        frozenset((e["extremo_a"], e["extremo_b"]))
        for e in topologia["enlaces_operativos"]
    }

    exigir(
        enlaces_grafo == enlaces_registrados,
        "El grafo no coincide con los enlaces operativos"
    )

    return grafo


def verificar_estado_actual(topologia):
    estados = {
        sw: puertos_ovs(sw)
        for sw in topologia["switches"]
    }

    enlaces = (
        topologia["enlaces_operativos"]
        + topologia["enlaces_caidos"]
    )

    for enlace in enlaces:
        for extremo in ("a", "b"):
            switch = enlace[f"extremo_{extremo}"]
            puerto = int(enlace[f"puerto_{extremo}"])
            esperado = enlace[f"activo_{extremo}"]

            observado = estados[switch].get(puerto)

            exigir(
                observado is not None
                and observado == esperado,
                "La topologia registrada ya no coincide "
                f"con Open vSwitch: {switch}:{puerto}"
            )


def caminos_simples(grafo, inicio, destino):
    """Enumera caminos sin repetir switches."""
    encontrados = []
    pila = [(inicio, [inicio])]

    while pila:
        actual, camino = pila.pop()

        if actual == destino:
            encontrados.append(camino)
            continue

        for vecino in sorted(grafo[actual], reverse=True):
            if vecino not in camino:
                pila.append(
                    (vecino, camino + [vecino])
                )

    return sorted(
        encontrados,
        key=lambda camino: (len(camino), camino)
    )


def seleccionar_candidatos(todos, ruta_fs, limite):
    exigir(
        ruta_fs in todos,
        "La ruta FS no aparece en el grafo operativo"
    )

    seleccion = todos[:limite]

    # Conservar FS incluso si no esta entre los
    # caminos mas cortos.
    if ruta_fs not in seleccion:
        seleccion[-1] = ruta_fs

    return sorted(
        seleccion,
        key=lambda camino: (len(camino), camino)
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--max-caminos",
        type=int,
        default=5,
        help="Maximo de alternativas por comunicacion"
    )
    args = parser.parse_args()

    exigir(
        args.max_caminos >= 2,
        "Se requieren al menos 2 candidatos permitidos"
    )

    topologia = cargar(ENTRADA)
    estado = cargar(ESTADO)

    grafo = construir_grafo(topologia)
    verificar_estado_actual(topologia)

    fallo = frozenset(estado["enlace_fallado"])

    fallos_topologia = {
        frozenset((e["extremo_a"], e["extremo_b"]))
        for e in topologia["enlaces_caidos"]
    }

    exigir(
        fallos_topologia == {fallo},
        "El fallo de la topologia no coincide "
        "con EstadoPostFallo.json"
    )

    hosts = {
        h["nombre"]: h["switch"]
        for h in topologia["hosts"]
    }

    fs = estado["estado"]["FS"]

    comunicaciones = []
    pares_observados = set()
    total_caminos = 0

    for flujo in fs["comunicaciones"]:
        origen = flujo["origen"]
        destino = flujo["destino"]
        par = (origen, destino)

        exigir(
            origen in hosts
            and destino in hosts
            and origen != destino
            and par not in pares_observados,
            f"Comunicacion invalida: {par}"
        )

        pares_observados.add(par)

        ruta_fs = flujo["ruta_seleccionada"]

        exigir(
            ruta_fs[0] == origen
            and ruta_fs[-1] == destino
            and ruta_fs[1] == hosts[origen]
            and ruta_fs[-2] == hosts[destino],
            f"Ruta FS invalida: {par}"
        )

        ruta_switches = ruta_fs[1:-1]

        todos = caminos_simples(
            grafo,
            hosts[origen],
            hosts[destino]
        )

        exigir(
            bool(todos),
            f"No existe camino para {par}"
        )

        candidatos = seleccionar_candidatos(
            todos,
            ruta_switches,
            args.max_caminos
        )

        registros = []

        for indice, camino in enumerate(candidatos, 1):
            registros.append({
                "id": f"{origen}_{destino}_c{indice:02d}",
                "ruta": [origen] + camino + [destino],
                "saltos_entre_switches": len(camino) - 1,
                "es_ruta_fs": camino == ruta_switches,
            })

        exigir(
            sum(c["es_ruta_fs"] for c in registros) == 1,
            f"La ruta FS no se conservo: {par}"
        )

        comunicaciones.append({
            "origen": origen,
            "destino": destino,
            "ruta_fs_referencia": ruta_fs,
            "cantidad_caminos_encontrados": len(todos),
            "candidatos": registros,
        })

        total_caminos += len(registros)

    esperados = {
        (a, b)
        for a in hosts
        for b in hosts
        if a != b
    }

    exigir(
        pares_observados == esperados,
        "Faltan comunicaciones"
    )

    resultado = {
        "tipo": "Caminos_Candidatos_PostFallo",
        "generado_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "topologia_origen": str(ENTRADA),
        "estado_origen": str(ESTADO),
        "captura_origen_simultanea": topologia[
            "captura_origen_simultanea"
        ],
        "enlace_fallado": sorted(fallo),
        "criterio_orden": "Menor numero de saltos",
        "max_caminos_por_comunicacion": args.max_caminos,
        "cantidad_comunicaciones": len(comunicaciones),
        "cantidad_candidatos": total_caminos,
        "comunicaciones": comunicaciones,
    }

    SALIDA.parent.mkdir(parents=True, exist_ok=True)
    temporal = SALIDA.with_suffix(".json.tmp")

    temporal.write_text(
        json.dumps(resultado, indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8"
    )
    temporal.replace(SALIDA)

    print("\n=== CAMINOS CANDIDATOS POST-FALLO ===")
    print("Enlace fallado:", " - ".join(
        sw.upper() for sw in sorted(fallo)
    ))
    print("Comunicaciones:", len(comunicaciones))
    print("Candidatos calculados:", total_caminos)
    print("Limite por comunicacion:", args.max_caminos)

    for comunicacion in comunicaciones:
        print(
            f'{comunicacion["origen"].upper()} -> '
            f'{comunicacion["destino"].upper()}: '
            f'{len(comunicacion["candidatos"])} candidatos'
        )

    print("Rutas FS conservadas:", len(comunicaciones))
    print("Estado de puertos OVS: VERIFICADO")
    print("Archivo generado:", SALIDA)


if __name__ == "__main__":
    try:
        main()
    except (
        RuntimeError,
        ValueError,
        KeyError,
        OSError
    ) as error:
        raise SystemExit(f"ERROR: {error}")
