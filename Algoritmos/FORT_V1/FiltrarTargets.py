
#!/usr/bin/env python3
"""Etapa 03 - Actividad 05: filtrado preliminar FS, PS y RS."""

import json
import math
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
E01 = BASE / "resultados/etapa01"
E02 = BASE / "resultados/etapa02"
E03 = BASE / "resultados/etapa03"


def exigir(condicion, mensaje):
    if not condicion:
        raise RuntimeError(mensaje)


def leer(ruta):
    exigir(ruta.is_file(), f"No existe: {ruta}")
    return json.loads(ruta.read_text(encoding="utf-8"))


def guardar(ruta, datos):
    temporal = ruta.with_suffix(".json.tmp")
    temporal.write_text(
        json.dumps(datos, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporal.replace(ruta)


def obtener_fallo(datos):
    if "enlace_fallado" in datos:
        nodos = datos["enlace_fallado"]
    else:
        enlaces = datos.get("enlaces_fallados_observados", [])
        exigir(len(enlaces) == 1, "Fallo ausente o multiple")
        nodos = [
            enlaces[0]["extremo_a"],
            enlaces[0]["extremo_b"],
        ]

    exigir(len(nodos) == 2, "Fallo mal definido")
    return frozenset(nodos)


def obtener_inventario(datos):
    puertos = {}

    for e in datos:
        a, b = e["nodo_a"], e["nodo_b"]
        pa, pb = int(e["puerto_a"]), int(e["puerto_b"])

        exigir(
            (a, b) not in puertos and (b, a) not in puertos,
            f"Enlace duplicado: {a}-{b}",
        )

        puertos[(a, b)] = (pa, pb)
        puertos[(b, a)] = (pb, pa)

    return puertos


def obtener_ps(ps):
    switches = ps["switches"]

    exigir(
        isinstance(switches, dict),
        "Se esperaba PS con switches identificados por nombre",
    )

    puertos = {}
    total_grupos = 0
    grupos_respaldo = 0

    for nombre, datos in switches.items():
        puertos[nombre] = {}

        for p in datos["puertos"]:
            numero = int(p["numero"])
            exigir(
                numero not in puertos[nombre],
                f"Puerto repetido: {nombre}:{numero}",
            )
            puertos[nombre][numero] = bool(p["activo"])

        for grupo in datos.get("grupos_fast_failover", []):
            exigir(
                grupo["tipo"] == "ff",
                f"Grupo no FF en {nombre}",
            )

            total_grupos += 1

            seleccionado = grupo.get(
                "bucket_seleccionado_inferido"
            )

            if seleccionado is None:
                continue

            buckets = {
                int(b["indice"]): b
                for b in grupo["buckets"]
            }

            indice = int(seleccionado)

            exigir(
                indice in buckets,
                f"Bucket inexistente en {nombre}",
            )
            exigir(
                buckets[indice]["puerto_activo"],
                f"Bucket seleccionado inactivo en {nombre}",
            )

            if indice > 0:
                grupos_respaldo += 1

    exigir(total_grupos > 0, "PS no contiene grupos FF")

    return puertos, total_grupos, grupos_respaldo


def obtener_rutas_fs(fs):
    """Leer las rutas efectivas observadas por RegistrarFS."""
    comunicaciones = fs["comunicaciones"]

    exigir(
        isinstance(comunicaciones, list),
        "Comunicaciones FS no son una lista",
    )

    rutas = {}

    for c in comunicaciones:
        clave = (c["origen"], c["destino"])
        ruta = c.get("ruta_seleccionada")

        exigir(
            isinstance(ruta, list)
            and len(ruta) >= 3
            and all(isinstance(n, str) for n in ruta),
            f"FS sin ruta_seleccionada valida: {clave}",
        )

        exigir(
            clave not in rutas,
            f"Comunicacion FS duplicada: {clave}",
        )

        exigir(
            ruta[0] == clave[0] and ruta[-1] == clave[1],
            f"Extremos FS incorrectos: {clave}",
        )

        rutas[clave] = tuple(ruta)

    exigir(
        len(rutas) == fs["cantidad_comunicaciones"],
        "Cantidad de rutas FS inconsistente",
    )

    return rutas


def obtener_arcos(topologia, inventario, ps_puertos, fallo):
    switches = set(ps_puertos)

    enlaces_configurados = {
        frozenset((a, b))
        for a, b in inventario
        if a in switches and b in switches
    }

    operativos = set()

    for e in topologia["enlaces_operativos"]:
        a, b = e["extremo_a"], e["extremo_b"]
        enlace = frozenset((a, b))

        exigir(
            enlace in enlaces_configurados,
            f"Enlace operativo no inventariado: {a}-{b}",
        )
        exigir(
            enlace not in operativos,
            f"Enlace operativo duplicado: {a}-{b}",
        )

        operativos.add(enlace)

    excluidos = enlaces_configurados - operativos

    exigir(
        excluidos == {fallo},
        "Topologia no excluye exactamente el fallo registrado",
    )

    arcos = set()

    for enlace in operativos:
        a, b = tuple(enlace)
        pa, pb = inventario[(a, b)]

        exigir(
            ps_puertos[a].get(pa) is True
            and ps_puertos[b].get(pb) is True,
            f"PS contradice el enlace operativo {a}-{b}",
        )

        arcos.add((a, b))
        arcos.add((b, a))

    a, b = tuple(fallo)
    pa, pb = inventario[(a, b)]

    exigir(
        ps_puertos[a].get(pa) is False
        and ps_puertos[b].get(pb) is False,
        "PS no registra ambos extremos del fallo inactivos",
    )

    return arcos


def obtener_rs(rs, arcos):
    recursos = {}

    for d in rs["direcciones"]:
        clave = (d["origen"], d["destino"])

        exigir(
            clave not in recursos,
            f"Direccion RS duplicada: {clave}",
        )

        recursos[clave] = d

    for arco in arcos:
        exigir(arco in recursos, f"RS sin direccion {arco}")

        d = recursos[arco]
        capacidad = float(d["capacidad_operativa_bps"])

        exigir(
            d["activo"]
            and math.isfinite(capacidad)
            and capacidad > 0,
            f"Recurso RS no operativo: {arco}",
        )

    return recursos


def validar_ruta(origen, destino, ruta, inventario,
                 puertos_ps, arcos):
    errores = []

    if not isinstance(ruta, list) or len(ruta) < 3:
        return ["Ruta inexistente o incompleta"]

    if ruta[0] != origen or ruta[-1] != destino:
        errores.append("Extremos incorrectos")

    if len(ruta) != len(set(ruta)):
        errores.append("Ruta con ciclos")

    switches = set(puertos_ps)

    if any(n not in switches for n in ruta[1:-1]):
        errores.append("Nodo intermedio no es switch")

    for a, b in zip(ruta, ruta[1:]):
        if (a, b) not in inventario:
            errores.append(f"Enlace inexistente {a}->{b}")
            continue

        pa, pb = inventario[(a, b)]

        if a in switches and puertos_ps[a].get(pa) is not True:
            errores.append(f"Puerto PS inactivo {a}:{pa}")

        if b in switches and puertos_ps[b].get(pb) is not True:
            errores.append(f"Puerto PS inactivo {b}:{pb}")

        if a in switches and b in switches:
            if (a, b) not in arcos:
                errores.append(f"Arco post-fallo invalido {a}->{b}")

    return errores


def main():
    estado = leer(E02 / "EstadoPostFallo.json")
    fs = leer(E02 / "FS_postfallo.json")
    ps = leer(E02 / "PS_postfallo.json")
    rs = leer(E02 / "RS_postfallo.json")
    topologia = leer(E03 / "TopologiaPostFallo.json")
    inventario = obtener_inventario(
        leer(E01 / "puertos_detectados.json")
    )
    propuestas = leer(E03 / "TargetsCandidatos.json")
    estimacion = leer(E03 / "EstimacionCargaTargets.json")
    demandas = leer(E03 / "DemandasObservadas_iperf2.json")

    fallo = obtener_fallo(estado)

    for nombre, datos in (
        ("FS", fs),
        ("PS", ps),
        ("RS", rs),
        ("Targets", propuestas),
        ("Estimacion", estimacion),
        ("Demandas", demandas),
    ):
        exigir(
            obtener_fallo(datos) == fallo,
            f"Fallo inconsistente en {nombre}",
        )

    puertos_ps, total_ff, respaldo_ff = obtener_ps(ps)
    rutas_fs = obtener_rutas_fs(fs)

    arcos = obtener_arcos(
        topologia, inventario, puertos_ps, fallo
    )
    recursos = obtener_rs(rs, arcos)

    targets = propuestas["targets"]
    cargas = estimacion["targets"]

    exigir(
        len(targets) == propuestas["cantidad_targets"]
        and len(cargas) == estimacion["cantidad_targets"],
        "Cantidad de Targets inconsistente",
    )

    por_id = {t["id"]: t for t in targets}
    cargas_por_id = {t["target_id"]: t for t in cargas}

    exigir(
        len(por_id) == len(targets)
        and len(cargas_por_id) == len(cargas)
        and set(por_id) == set(cargas_por_id),
        "IDs de Targets o cargas inconsistentes",
    )

    exigir("T000" in por_id, "Falta referencia FS T000")

    rutas_t000 = {
        (c["origen"], c["destino"]): tuple(c["ruta"])
        for c in por_id["T000"]["configuracion"]
    }

    exigir(
        len(rutas_t000)
        == len(por_id["T000"]["configuracion"]),
        "T000 tiene comunicaciones duplicadas",
    )

    exigir(
        all(
            c["es_ruta_fs"]
            for c in por_id["T000"]["configuracion"]
        ),
        "T000 no esta identificado completamente como FS",
    )

    # Validacion directa y obligatoria.
    exigir(
        rutas_t000 == rutas_fs,
        "T000 NO coincide con las rutas observadas en FS",
    )

    tasas_por_id = {}
    demandas_por_par = {}

    for f in demandas["flujos"]:
        clave = (f["origen"], f["destino"])
        identificador = f["id"]
        tasa = float(f["tasa_enviada_bps"])

        exigir(
            clave not in demandas_por_par
            and identificador not in tasas_por_id
            and math.isfinite(tasa)
            and tasa >= 0,
            f"Demanda invalida: {identificador}",
        )

        demandas_por_par[clave] = tasa
        tasas_por_id[identificador] = tasa

    exigir(
        len(tasas_por_id) == demandas["cantidad_flujos"],
        "Cantidad de demandas inconsistente",
    )

    tasas_estimador = {
        f["id"]: float(f["tasa_enviada_bps"])
        for f in estimacion["flujos_medidos"]
    }

    exigir(
        tasas_por_id.keys() == tasas_estimador.keys(),
        "Los flujos de la estimacion y las demandas difieren",
    )

    for identificador, tasa in tasas_por_id.items():
        exigir(
            math.isclose(
                tasa, tasas_estimador[identificador],
                rel_tol=1e-6, abs_tol=1000,
            ),
            f"Demanda desactualizada: {identificador}",
        )

    admitidos = []
    descartados = []
    mlu_fs = None

    for target in targets:
        identificador = target["id"]
        errores = []
        rutas = {}
        carga_recalculada = defaultdict(float)

        for c in target["configuracion"]:
            clave = (c["origen"], c["destino"])
            ruta = c["ruta"]

            if clave in rutas:
                errores.append(f"Comunicacion duplicada: {clave}")
                continue

            rutas[clave] = tuple(ruta)

            for error in validar_ruta(
                clave[0], clave[1], ruta,
                inventario, puertos_ps, arcos,
            ):
                errores.append(f"{clave}: {error}")

            tasa = demandas_por_par.get(clave, 0.0)

            for a, b in zip(ruta, ruta[1:]):
                if a in puertos_ps and b in puertos_ps:
                    carga_recalculada[(a, b)] += tasa

        if set(rutas) != set(rutas_fs):
            errores.append("Comunicaciones diferentes a FS")

        cambios = sum(
            rutas.get(clave) != camino
            for clave, camino in rutas_fs.items()
        )

        if cambios != target["cantidad_rutas_modificadas"]:
            errores.append("Cantidad de rutas modificadas incorrecta")

        enlaces = cargas_por_id[identificador]["enlaces_dirigidos"]
        arcos_estimados = set()
        mlu = 0.0

        for e in enlaces:
            arco = (e["origen"], e["destino"])

            if arco in arcos_estimados:
                errores.append(f"Arco duplicado: {arco}")
                continue

            arcos_estimados.add(arco)

            if arco not in arcos:
                errores.append(f"Arco no operativo: {arco}")
                continue

            capacidad_rs = float(
                recursos[arco]["capacidad_operativa_bps"]
            )
            capacidad_modelo = float(e["capacidad_bps"])
            carga = float(e["carga_estimada_bps"])

            if not (
                math.isfinite(capacidad_modelo)
                and math.isfinite(carga)
                and capacidad_modelo > 0
                and carga >= 0
            ):
                errores.append(f"Datos numericos invalidos: {arco}")
                continue

            if not math.isclose(
                capacidad_rs, capacidad_modelo,
                rel_tol=0.001, abs_tol=1000,
            ):
                errores.append(f"Capacidad RS incompatible: {arco}")

            if not math.isclose(
                carga, carga_recalculada[arco],
                rel_tol=1e-6, abs_tol=1000,
            ):
                errores.append(
                    f"Carga incompatible con demandas: {arco}"
                )

            capacidad = min(capacidad_rs, capacidad_modelo)
            utilizacion = 100 * carga / capacidad
            mlu = max(mlu, utilizacion)

            if carga > capacidad + 1000:
                errores.append(
                    f"Capacidad excedida {arco}: "
                    f"{utilizacion:.2f}%"
                )

        if arcos_estimados != arcos:
            errores.append("Estimacion no cubre todos los arcos")

        registro = {
            "target_id": identificador,
            "rutas_modificadas": cambios,
            "mlu_final_estimada_pct": round(mlu, 4),
            "motivos": sorted(set(errores)),
        }

        if identificador == "T000":
            mlu_fs = round(mlu, 4)

        if errores:
            registro["estado"] = "DESCARTADO"
            descartados.append(registro)
        else:
            registro["estado"] = "ADMITIDO_PRELIMINAR"
            admitidos.append(registro)

    exigir(mlu_fs is not None, "No se calculo MLU de T000")

    resultado = {
        "tipo": "FiltradoTargets_Preliminar",
        "generado_utc": datetime.now(timezone.utc).isoformat(),
        "enlace_fallado": sorted(fallo),
        "referencia_fs": "T000",
        "rutas_fs_comparadas_directamente": True,
        "rutas_fs_verificadas": len(rutas_fs),
        "grupos_ff_registrados_ps": total_ff,
        "grupos_con_respaldo_inferido_ps": respaldo_ff,
        "direcciones_operativas": len(arcos),
        "maxima_utilizacion_observada_rs_pct":
            rs["maxima_utilizacion_observada_pct"],
        "mlu_fs_estimada_pct": mlu_fs,
        "cantidad_targets": len(targets),
        "cantidad_admitidos": len(admitidos),
        "cantidad_descartados": len(descartados),
        "admitidos": admitidos,
        "descartados": descartados,
        "limitaciones": [
            "Filtrado preliminar de rutas y capacidad",
            "Protecciones PS verificadas a nivel de grupos "
            "observados y disponibilidad de puertos",
            "No se garantiza todavia la preservacion de "
            "Fast Failover durante una Transition",
            "Carga de Targets estimada a partir de demandas "
            "piloto; no observada directamente",
            "RS observado no se suma a la carga proyectada "
            "para evitar contar dos veces el mismo trafico",
            "FS, PS y RS son capturas secuenciales",
            "Peak MLU, dependencias OpenFlow y costo de "
            "reconfiguracion pendientes",
        ],
    }

    salida = E03 / "TargetsFiltrados.json"
    guardar(salida, resultado)

    print("\n=== FILTRADO PRELIMINAR DE TARGETS ===")
    print("Fallo:", " - ".join(x.upper() for x in sorted(fallo)))
    print("Referencia FS: T000")
    print("Rutas comparadas directamente con FS: SI")
    print("Rutas FS verificadas:", len(rutas_fs))
    print("Grupos Fast Failover PS:", total_ff)
    print("Grupos con respaldo inferido:", respaldo_ff)
    print("Direcciones operativas RS:", len(arcos))
    print("Targets evaluados:", len(targets))
    print("Targets admitidos:", len(admitidos))
    print("Targets descartados:", len(descartados))
    print("MLU estimada de FS:", mlu_fs, "%")

    if descartados:
        print("\n=== MOTIVOS DE DESCARTE ===")
        for t in descartados:
            print(t["target_id"], "|", "; ".join(t["motivos"]))

    print("Factibilidad de Transitions: PENDIENTE")
    print("Archivo generado:", salida)


if __name__ == "__main__":
    main()
