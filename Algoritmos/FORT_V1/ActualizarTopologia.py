
#!/usr/bin/env python3
"""Etapa 03 - Actividad 01: grafo operativo post-fallo."""

import json
import re
import subprocess
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SALIDA = BASE / "resultados/etapa03/TopologiaPostFallo.json"


def cargar(ruta):
    return json.loads(ruta.read_text(encoding="utf-8"))


def comprobar(condicion, mensaje):
    if not condicion:
        raise RuntimeError(mensaje)


def puertos_ovs(switch):
    texto = subprocess.check_output(
        [
            "ovs-ofctl", "-O", "OpenFlow13",
            "dump-ports-desc", switch
        ],
        text=True
    )

    cabeceras = list(re.finditer(
        r"(?m)^\s*(\d+)\(([^)]+)\):", texto
    ))
    estados = {}

    for i, cabecera in enumerate(cabeceras):
        fin = (
            cabeceras[i + 1].start()
            if i + 1 < len(cabeceras)
            else len(texto)
        )

        bloque = texto[cabecera.end():fin]
        config = re.search(
            r"(?m)^\s*config:\s*(.+)$", bloque
        )
        estado = re.search(
            r"(?m)^\s*state:\s*(.+)$", bloque
        )

        comprobar(
            config is not None and estado is not None,
            f"Estado de puerto incompleto: {switch}"
        )

        estados[int(cabecera[1])] = (
            "PORT_DOWN" not in config[1]
            and "LINK_DOWN" not in estado[1]
        )

    comprobar(
        bool(estados),
        f"No hay puertos observables en {switch}"
    )
    return estados


def componentes_conectadas(switches, adyacencia):
    pendientes = set(switches)
    componentes = []

    while pendientes:
        inicio = min(pendientes)
        cola = deque([inicio])
        pendientes.remove(inicio)
        componente = []

        while cola:
            actual = cola.popleft()
            componente.append(actual)

            for vecino in adyacencia[actual]:
                if vecino in pendientes:
                    pendientes.remove(vecino)
                    cola.append(vecino)

        componentes.append(sorted(componente))

    return componentes


def main():
    escenario = cargar(
        BASE / "config/escenario.json"
    )
    inventario = cargar(
        BASE / "resultados/etapa01/puertos_detectados.json"
    )
    estado = cargar(
        BASE / "resultados/etapa02/EstadoPostFallo.json"
    )

    switches = sorted(escenario["switches"])
    conjunto_switches = set(switches)

    enlaces_configurados = {
        frozenset(e)
        for e in escenario["enlaces"]
    }

    comprobar(
        len(enlaces_configurados) == len(escenario["enlaces"]),
        "Enlaces duplicados en el escenario"
    )

    indice_puertos = {}

    for enlace in inventario:
        a = enlace["nodo_a"]
        b = enlace["nodo_b"]

        if a not in conjunto_switches or b not in conjunto_switches:
            continue

        clave = frozenset((a, b))

        comprobar(
            clave not in indice_puertos,
            f"Enlace duplicado en inventario: {a}-{b}"
        )
        indice_puertos[clave] = enlace

    comprobar(
        set(indice_puertos) == enlaces_configurados,
        "Inventario de puertos distinto a la topologia"
    )

    # Datos observados del switch, no rutas predefinidas.
    puertos = {
        sw: puertos_ovs(sw)
        for sw in switches
    }

    rs = estado["estado"]["RS"]
    fs = estado["estado"]["FS"]

    recursos = {
        (d["origen"], d["destino"]): d
        for d in rs["direcciones"]
    }

    adyacencia = {sw: set() for sw in switches}
    operativos = []
    caidos = []

    for a, b in escenario["enlaces"]:
        clave = frozenset((a, b))
        enlace = indice_puertos[clave]

        if enlace["nodo_a"] == a:
            pa = int(enlace["puerto_a"])
            pb = int(enlace["puerto_b"])
        else:
            pa = int(enlace["puerto_b"])
            pb = int(enlace["puerto_a"])

        comprobar(
            pa in puertos[a] and pb in puertos[b],
            f"Puerto no encontrado: {a}-{b}"
        )

        activo_a = puertos[a][pa]
        activo_b = puertos[b][pb]
        activo = activo_a and activo_b

        recurso_ab = recursos[(a, b)]
        recurso_ba = recursos[(b, a)]

        comprobar(
            recurso_ab["activo"] == activo_a
            and recurso_ba["activo"] == activo_b,
            f"RS no coincide con el estado actual: {a}-{b}"
        )

        registro = {
            "extremo_a": a,
            "extremo_b": b,
            "puerto_a": pa,
            "puerto_b": pb,
            "activo_a": activo_a,
            "activo_b": activo_b,
            "capacidad_a_b_bps": recurso_ab[
                "capacidad_configurada_bps"
            ],
            "capacidad_b_a_bps": recurso_ba[
                "capacidad_configurada_bps"
            ],
        }

        if activo:
            operativos.append(registro)
            adyacencia[a].add(b)
            adyacencia[b].add(a)
        else:
            caidos.append(registro)

    fallos_actuales = {
        frozenset((e["extremo_a"], e["extremo_b"]))
        for e in caidos
    }

    fallo_registrado = frozenset(
        estado["enlace_fallado"]
    )

    comprobar(
        len(fallos_actuales) == 1
        and fallos_actuales == {fallo_registrado},
        "El fallo actual no coincide con EstadoPostFallo.json"
    )

    # Comprobar que FS no usa enlaces fuera de servicio.
    enlaces_activos = {
        frozenset((e["extremo_a"], e["extremo_b"]))
        for e in operativos
    }

    for flujo in fs["comunicaciones"]:
        ruta = flujo["ruta_seleccionada"]

        for a, b in zip(ruta, ruta[1:]):
            if a in conjunto_switches and b in conjunto_switches:
                comprobar(
                    frozenset((a, b)) in enlaces_activos,
                    f"FS usa enlace inactivo: {a}-{b}"
                )

    componentes = componentes_conectadas(
        switches, adyacencia
    )

    resultado = {
        "tipo": "Topologia_Operativa_PostFallo",
        "generado_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "fuente": (
            "Escenario SDN, inventario de puertos, "
            "EstadoPostFallo y estado actual OpenFlow"
        ),
        "captura_origen_simultanea": estado[
            "validacion"
        ]["captura_simultanea"],
        "switches": switches,
        "hosts": escenario["hosts"],
        "enlaces_configurados": len(enlaces_configurados),
        "enlaces_operativos": operativos,
        "enlaces_caidos": caidos,
        "adyacencia": {
            sw: sorted(vecinos)
            for sw, vecinos in adyacencia.items()
        },
        "componentes_conectadas": componentes,
        "red_conectada": len(componentes) == 1,
        "rutas_fs_verificadas": len(fs["comunicaciones"]),
    }

    SALIDA.parent.mkdir(parents=True, exist_ok=True)
    temporal = SALIDA.with_suffix(".json.tmp")
    temporal.write_text(
        json.dumps(resultado, indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8"
    )
    temporal.replace(SALIDA)

    print("\n=== TOPOLOGIA POST-FALLO ===")
    print("Switches:", len(switches))
    print("Enlaces configurados:", len(enlaces_configurados))
    print("Enlaces operativos:", len(operativos))

    for enlace in caidos:
        print(
            "Enlace excluido:",
            enlace["extremo_a"].upper(),
            "-",
            enlace["extremo_b"].upper()
        )

    print(
        "Red conectada:",
        "SI" if len(componentes) == 1 else "NO"
    )
    print("Componentes:", componentes)
    print(
        "Rutas FS compatibles:",
        len(fs["comunicaciones"])
    )
    print(
        "Captura origen simultanea:",
        estado["validacion"]["captura_simultanea"]
    )
    print("Archivo generado:", SALIDA)


if __name__ == "__main__":
    try:
        main()
    except (
        RuntimeError, ValueError, KeyError,
        OSError, subprocess.CalledProcessError
    ) as error:
        raise SystemExit(f"ERROR: {error}")
