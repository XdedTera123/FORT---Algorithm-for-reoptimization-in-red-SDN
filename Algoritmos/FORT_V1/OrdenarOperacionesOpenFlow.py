
#!/usr/bin/env python3
"""Etapa 04 - A03: dependencias y orden propuesto de OpenFlow.

No ejecuta FlowMod, GroupMod ni BarrierRequest.
Los planes bloqueados no reciben operaciones de activacion.
"""

import json
import time
from collections import defaultdict
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


def ordenar_grafo(nodos, dependencias):
    sucesores = defaultdict(list)
    grados = {identificador: 0 for identificador in nodos}

    for d in dependencias:
        a, b = d["antes"], d["despues"]

        exigir(
            a in nodos and b in nodos and a != b,
            f"Dependencia invalida: {a} -> {b}",
        )

        sucesores[a].append(b)
        grados[b] += 1

    pendientes = [
        n for n in nodos if grados[n] == 0
    ]
    resultado = []

    while pendientes:
        actual = pendientes.pop(0)
        resultado.append(actual)

        for siguiente in sucesores[actual]:
            grados[siguiente] -= 1

            if grados[siguiente] == 0:
                pendientes.append(siguiente)

    exigir(
        len(resultado) == len(nodos),
        "Se detecto un ciclo en las dependencias",
    )

    return resultado


def construir_plan(tid, plan):
    prefijo = (
        f'{tid}_{plan["origen"]}_{plan["destino"]}'
    )

    operaciones = plan["operaciones"]
    nodos = {}
    dependencias = []
    pares = set()

    def agregar_nodo(identificador, categoria, switch, **extra):
        exigir(
            identificador not in nodos,
            f"Nodo repetido: {identificador}",
        )

        nodos[identificador] = {
            "id": identificador,
            "categoria": categoria,
            "switch": switch,
            **extra,
        }

    def depender(antes, despues, motivo):
        clave = (antes, despues)

        if clave in pares:
            return

        pares.add(clave)
        dependencias.append({
            "antes": antes,
            "despues": despues,
            "motivo": motivo,
        })

    preparaciones = defaultdict(list)
    grupos = []
    activaciones = []

    for op in operaciones:
        oid = op["id"]
        comando = op["comando"]
        sw = op["switch"]

        agregar_nodo(
            oid, comando, sw,
            referencia_operacion=oid,
            fase=op["fase_propuesta"],
        )

        if comando == "FlowMod_ADD_PROPUESTO":
            exigir(
                op["fase_propuesta"] == "PREPARACION",
                f"Preparacion invalida: {oid}",
            )
            preparaciones[sw].append(oid)

        elif comando == "GroupMod_ADD_PROPUESTO":
            grupos.append(oid)

        elif comando == "FlowMod_MODIFY_STRICT_PROPUESTO":
            activaciones.append(oid)

        else:
            raise RuntimeError(
                f"Operacion no contemplada: {comando}"
            )

    ruta = plan["ruta_target"]
    posicion = {n: i for i, n in enumerate(ruta)}

    exigir(
        len(posicion) == len(ruta),
        f"Ruta con nodos repetidos en {tid}",
    )

    for sw in preparaciones:
        exigir(
            sw in posicion,
            f"Preparacion fuera de ruta: {sw}",
        )

    # Procesar primero los switches mas cercanos al
    # destino, antes de preparar los del origen.
    switches = sorted(
        preparaciones,
        key=lambda sw: posicion[sw],
        reverse=True,
    )

    ultima_barrera = None
    cantidad_barreras = 0

    for sw in switches:
        for oid in preparaciones[sw]:
            if ultima_barrera is not None:
                depender(
                    ultima_barrera,
                    oid,
                    "Preparar el tramo posterior antes "
                    "del tramo anterior",
                )

        bid = f"{prefijo}_B_PREP_{sw}"

        agregar_nodo(
            bid,
            "BarrierRequest_PROPUESTO",
            sw,
            fase="SINCRONIZACION_PREPARACION",
        )
        cantidad_barreras += 1

        for oid in preparaciones[sw]:
            depender(
                oid, bid,
                "Esperar procesamiento de FlowMod "
                "de preparacion",
            )

        ultima_barrera = bid

    bloqueado = (
        plan["estado_plan"]
        == "BLOQUEADO_PRIMER_SALTO_COMPARTIDO"
    )

    if bloqueado:
        exigir(
            not grupos and not activaciones,
            f"Un plan bloqueado contiene activaciones: {tid}",
        )

        estado = "BLOQUEADO"
        razon = (
            "El primer salto Target y FS comparte puerto; "
            "no existe una activacion FF independiente "
            "propuesta para esta comunicacion."
        )

    else:
        exigir(
            plan["estado_plan"]
            == "PROPUESTA_REQUIERE_VALIDACION",
            f"Estado de plan desconocido: {tid}",
        )

        exigir(
            len(grupos) == 1
            and len(activaciones) == 2,
            f"Grupo/activaciones inconsistentes: {tid}",
        )

        grupo = grupos[0]
        ingreso = nodos[grupo]["switch"]

        if ultima_barrera:
            depender(
                ultima_barrera, grupo,
                "Toda la ruta nueva debe prepararse "
                "antes del grupo FF",
            )

        barrier_grupo = f"{prefijo}_B_GRUPO"

        agregar_nodo(
            barrier_grupo,
            "BarrierRequest_PROPUESTO",
            ingreso,
            fase="SINCRONIZACION_GRUPO",
        )
        cantidad_barreras += 1

        depender(
            grupo, barrier_grupo,
            "Confirmar procesamiento de GroupMod "
            "antes de activar el Target",
        )

        for oid in activaciones:
            exigir(
                nodos[oid]["switch"] == ingreso,
                "Activacion fuera del switch de ingreso",
            )

            depender(
                barrier_grupo, oid,
                "El grupo FF debe existir antes "
                "de referenciarlo",
            )

        barrier_final = f"{prefijo}_B_ACTIVACION"

        agregar_nodo(
            barrier_final,
            "BarrierRequest_PROPUESTO",
            ingreso,
            fase="SINCRONIZACION_ACTIVACION",
        )
        cantidad_barreras += 1

        for oid in activaciones:
            depender(
                oid, barrier_final,
                "Procesar las modificaciones IP/ARP",
            )

        verificar = f"{prefijo}_VERIFICACION"

        agregar_nodo(
            verificar,
            "VERIFICACION_PENDIENTE",
            ingreso,
            fase="VERIFICACION_POST_ACTIVACION",
        )

        depender(
            barrier_final, verificar,
            "Verificar reglas y camino despues "
            "de procesar la activacion",
        )

        estado = "ORDENADO_NO_VALIDADO"
        razon = None

    orden = ordenar_grafo(nodos, dependencias)

    pasos = []

    for numero, identificador in enumerate(orden, start=1):
        pasos.append({
            "orden": numero,
            **nodos[identificador],
        })

    exigir(
        sum(
            paso["referencia_operacion"] in {
                op["id"] for op in operaciones
            }
            for paso in pasos
            if "referencia_operacion" in paso
        ) == len(operaciones),
        "No se ordenaron todas las operaciones",
    )

    return {
        "origen": plan["origen"],
        "destino": plan["destino"],
        "estado": estado,
        "motivo_bloqueo": razon,
        "cantidad_operaciones_openflow":
            len(operaciones),
        "cantidad_barreras_propuestas":
            cantidad_barreras,
        "cantidad_pasos": len(pasos),
        "dependencias": dependencias,
        "pasos_ordenados": pasos,
        "advertencias": [
            "Orden logico, no ejecucion OpenFlow.",
            "Las barreras solo sincronizan el "
            "procesamiento de mensajes.",
            "IP y ARP no se modifican atomicamente "
            "mediante dos FlowMod separados.",
            "Faltan verificar matches reales, conflictos "
            "y proteccion extremo a extremo.",
        ],
    }


def main():
    inicio = time.perf_counter()

    datos = leer(
        E04 / "OperacionesOpenFlowPropuestas.json"
    )

    exigir(
        datos["ejecutado_en_ovs"] is False,
        "Se esperaba un catalogo no ejecutado",
    )

    resultados = []
    total_operaciones = 0
    total_barreras = 0
    total_dependencias = 0
    total_bloqueados = 0
    targets_con_bloqueos = 0
    targets_sin_bloqueos = 0

    for target in datos["targets"]:
        planes = []

        for plan in target["planes"]:
            ordenado = construir_plan(
                target["target_id"], plan
            )

            total_operaciones += (
                ordenado["cantidad_operaciones_openflow"]
            )
            total_barreras += (
                ordenado["cantidad_barreras_propuestas"]
            )
            total_dependencias += len(
                ordenado["dependencias"]
            )

            if ordenado["estado"] == "BLOQUEADO":
                total_bloqueados += 1

            planes.append(ordenado)

        bloqueos = sum(
            p["estado"] == "BLOQUEADO"
            for p in planes
        )

        if bloqueos:
            targets_con_bloqueos += 1
        else:
            targets_sin_bloqueos += 1

        resultados.append({
            "target_id": target["target_id"],
            "cantidad_planes": len(planes),
            "planes_bloqueados": bloqueos,
            "estado_target": (
                "CON_BLOQUEOS"
                if bloqueos else "SIN_BLOQUEOS_LOCALES"
            ),
            "planes": planes,
        })

    exigir(
        len(resultados) == datos["targets_analizados"],
        "Numero de Targets inconsistente",
    )
    exigir(
        total_operaciones == datos["operaciones_propuestas"],
        "Se perdieron operaciones del catalogo",
    )
    exigir(
        total_bloqueados
        == datos["planes_sin_respaldo_inicial_independiente"],
        "Los bloqueos no coinciden con A02",
    )

    tiempo = time.perf_counter() - inicio

    salida = E04 / "DependenciasOpenFlow.json"

    guardar(salida, {
        "tipo": "DependenciasOpenFlow_Propuestas",
        "generado_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "enlace_fallado": datos["enlace_fallado"],
        "fuente": "resultados/etapa04/"
                  "OperacionesOpenFlowPropuestas.json",
        "targets_analizados": len(resultados),
        "operaciones_openflow_ordenadas": total_operaciones,
        "barreras_propuestas": total_barreras,
        "dependencias_generadas": total_dependencias,
        "planes_bloqueados": total_bloqueados,
        "targets_con_bloqueos": targets_con_bloqueos,
        "targets_sin_bloqueos_locales": targets_sin_bloqueos,
        "tiempo_generacion_s": round(tiempo, 6),
        "modificaciones_ejecutadas_en_ovs": 0,
        "limitaciones": [
            "Los DAG son por comunicacion, no una "
            "transicion global ejecutable por Target.",
            "Aun no se validan conflictos entre planes "
            "del mismo Target.",
            "No se garantiza seguridad, continuidad "
            "ni proteccion extremo a extremo.",
            "Las barreras son propuestas no ejecutadas.",
            "No se evaluan estados intermedios ni Peak MLU.",
        ],
        "targets": resultados,
    })

    ejemplo = next(
        (x for x in resultados if x["target_id"] == "T001"),
        None,
    )

    print("\n=== ETAPA 04 - A03: DEPENDENCIAS OPENFLOW ===")
    print("Targets analizados:", len(resultados))
    print("Operaciones ordenadas:", total_operaciones)
    print("Barreras propuestas:", total_barreras)
    print("Dependencias generadas:", total_dependencias)
    print("Planes bloqueados:", total_bloqueados)
    print("Targets con bloqueos:", targets_con_bloqueos)
    print(
        "Targets sin bloqueos locales:",
        targets_sin_bloqueos,
    )

    if ejemplo and ejemplo["planes"]:
        print("\n=== ORDEN PROPUESTO T001 ===")

        for paso in ejemplo["planes"][0]["pasos_ordenados"]:
            print(
                f'{paso["orden"]:02d}',
                "|", paso["categoria"],
                "|", paso["switch"],
            )

    print(f"\nTiempo de generacion: {tiempo:.6f} s")
    print("Modificaciones ejecutadas en OVS: 0")
    print("Seguridad global: PENDIENTE")
    print("Archivo generado:", salida)


if __name__ == "__main__":
    main()
