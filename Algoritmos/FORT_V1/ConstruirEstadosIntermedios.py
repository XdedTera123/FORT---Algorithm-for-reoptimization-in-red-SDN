
#!/usr/bin/env python3
"""Etapa 04 - A05: estados intermedios logicos de Transitions.

Genera una instantanea inicial y otra por cada paso.
No ejecuta operaciones OpenFlow ni mide el datapath.
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
E02 = BASE / "resultados/etapa02"
E03 = BASE / "resultados/etapa03"
E04 = BASE / "resultados/etapa04"


def exigir(condicion, mensaje):
    if not condicion:
        raise RuntimeError(mensaje)


def leer(ruta):
    exigir(ruta.is_file(), f"No existe: {ruta}")
    return json.loads(ruta.read_text(encoding="utf-8"))


def guardar(ruta, datos):
    ruta.parent.mkdir(parents=True, exist_ok=True)
    temporal = ruta.with_suffix(".json.tmp")
    temporal.write_text(
        json.dumps(datos, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporal.replace(ruta)


def clave_comunicacion(origen, destino):
    return f"{origen}->{destino}"


def rutas_de_lista(comunicaciones, campo):
    resultado = {}

    for c in comunicaciones:
        par = clave_comunicacion(c["origen"], c["destino"])
        ruta = c[campo]

        exigir(
            par not in resultado,
            f"Comunicacion duplicada: {par}",
        )

        exigir(
            isinstance(ruta, list) and len(ruta) >= 3,
            f"Ruta invalida: {par}",
        )

        resultado[par] = ruta

    return resultado


def indexar_planificacion(datos):
    resultado = {}

    for t in datos["targets"]:
        tid = t["target_id"]

        exigir(
            tid not in resultado,
            f"Target repetido: {tid}",
        )

        planes = {}

        for p in t["planes"]:
            par = clave_comunicacion(
                p["origen"], p["destino"]
            )

            exigir(
                par not in planes,
                f"Plan repetido: {tid}/{par}",
            )

            planes[par] = p

        resultado[tid] = planes

    return resultado


def catalogar_pasos(tid, planes_a03, planes_a02):
    pasos = {}
    operaciones = {}

    for par, plan in planes_a03.items():
        exigir(
            par in planes_a02,
            f"Falta A02 para {tid}/{par}",
        )

        propuesto = planes_a02[par]

        exigir(
            plan["estado"] == "ORDENADO_NO_VALIDADO",
            f"Plan bloqueado: {tid}/{par}",
        )

        exigir(
            propuesto["estado_plan"]
            == "PROPUESTA_REQUIERE_VALIDACION",
            f"Plan A02 bloqueado: {tid}/{par}",
        )

        for p in plan["pasos_ordenados"]:
            identificador = p["id"]

            exigir(
                identificador not in pasos,
                f"Paso duplicado: {identificador}",
            )

            pasos[identificador] = (par, p)

        for op in propuesto["operaciones"]:
            identificador = op["id"]

            exigir(
                identificador not in operaciones,
                f"Operacion duplicada: {identificador}",
            )

            operaciones[identificador] = (par, op)

    return pasos, operaciones


def simular_transition(
    tid, tr, fs, rutas_target, planes_a03, planes_a02
):
    pasos_originales, operaciones = catalogar_pasos(
        tid, planes_a03, planes_a02
    )

    cambiadas = sorted(planes_a03)

    exigir(cambiadas, f"Transition vacia: {tid}")

    for par in cambiadas:
        exigir(
            par in fs and par in rutas_target,
            f"Comunicacion ausente: {par}",
        )

        exigir(
            fs[par] != rutas_target[par],
            f"Ruta sin cambios: {tid}/{par}",
        )

        exigir(
            planes_a02[par]["ruta_fs"] == fs[par],
            f"FS no coincide: {par}",
        )

        exigir(
            planes_a02[par]["ruta_target"]
            == rutas_target[par],
            f"Target no coincide: {par}",
        )

    preparadas = set()
    grupos = set()
    activadas_ip = set()
    activadas_arp = set()

    barreras = 0
    verificaciones = 0
    procesados = set()
    estados = []

    def registrar(numero, tipo_evento, identificador):
        rutas = []

        for par in cambiadas:
            rutas.append({
                "comunicacion": par,
                "ruta_ip_modelada": (
                    "TARGET"
                    if par in activadas_ip
                    else "FS"
                ),
                "ruta_arp_modelada": (
                    "TARGET"
                    if par in activadas_arp
                    else "FS"
                ),
            })

        mezcladas = sorted(
            activadas_ip.symmetric_difference(
                activadas_arp
            )
        )

        firma = tuple(
            (
                par,
                par in activadas_ip,
                par in activadas_arp,
            )
            for par in cambiadas
        )

        estados.append({
            "estado_id": (
                f"{tr['transition_id']}_E{numero:03d}"
            ),
            "paso_global": numero,
            "evento": tipo_evento,
            "paso_referencia": identificador,
            "flowmods_preparados_modelados":
                len(preparadas),
            "grupos_ff_preparados_modelados":
                len(grupos),
            "barreras_solicitadas_hipoteticas":
                barreras,
            "barreras_confirmadas_realmente": 0,
            "verificaciones_propuestas": verificaciones,
            "comunicaciones_ip_en_target":
                sorted(activadas_ip),
            "comunicaciones_arp_en_target":
                sorted(activadas_arp),
            "comunicaciones_ip_arp_divergentes":
                mezcladas,
            "rutas_por_comunicacion_modificada":
                rutas,
            "_firma": firma,
        })

    registrar(
        0,
        "ESTADO_FS_INICIAL",
        None,
    )

    for numero, paso in enumerate(
        tr["pasos"], start=1
    ):
        identificador = paso["referencia_paso"]

        exigir(
            identificador in pasos_originales,
            f"Paso ajeno a A03: {identificador}",
        )

        exigir(
            identificador not in procesados,
            f"Paso repetido: {identificador}",
        )

        procesados.add(identificador)

        par, original = pasos_originales[identificador]

        exigir(
            paso["orden_global"] == numero,
            f"Numeracion incorrecta en {tid}",
        )

        exigir(
            paso["comunicacion"] == par,
            f"Comunicacion incorrecta: {identificador}",
        )

        exigir(
            paso["categoria"] == original["categoria"]
            and paso["switch"] == original["switch"],
            f"Paso distinto a A03: {identificador}",
        )

        categoria = paso["categoria"]

        if categoria in (
            "FlowMod_ADD_PROPUESTO",
            "GroupMod_ADD_PROPUESTO",
            "FlowMod_MODIFY_STRICT_PROPUESTO",
        ):
            exigir(
                identificador in operaciones,
                f"Operacion ausente de A02: {identificador}",
            )

            par_op, op = operaciones[identificador]

            exigir(
                par_op == par
                and op["comando"] == categoria,
                f"Operacion incongruente: {identificador}",
            )

            if categoria == "FlowMod_ADD_PROPUESTO":
                exigir(
                    op["fase_propuesta"] == "PREPARACION",
                    "FlowMod ADD fuera de preparacion",
                )

                preparadas.add(identificador)

            elif categoria == "GroupMod_ADD_PROPUESTO":
                pendientes = {
                    o["id"]
                    for o in planes_a02[par]["operaciones"]
                    if o["comando"]
                    == "FlowMod_ADD_PROPUESTO"
                }

                exigir(
                    pendientes <= preparadas,
                    f"Grupo antes de preparar ruta: {par}",
                )

                grupos.add(par)

            else:
                exigir(
                    par in grupos,
                    f"Activacion sin GroupMod previo: {par}",
                )

                protocolo = op[
                    "match_objetivo"
                ]["protocolo"]

                exigir(
                    protocolo in ("ip", "arp"),
                    f"Protocolo desconocido: {protocolo}",
                )

                destino = (
                    activadas_ip
                    if protocolo == "ip"
                    else activadas_arp
                )

                exigir(
                    par not in destino,
                    f"Doble activacion {protocolo}: {par}",
                )

                destino.add(par)

        elif categoria == "BarrierRequest_PROPUESTO":
            barreras += 1

        elif categoria == "VERIFICACION_PENDIENTE":
            exigir(
                par in activadas_ip
                and par in activadas_arp,
                f"Verificacion antes de ambas "
                f"activaciones: {par}",
            )

            verificaciones += 1

        else:
            raise RuntimeError(
                f"Categoria desconocida: {categoria}"
            )

        registrar(numero, categoria, identificador)

    posiciones = {
        paso["referencia_paso"]: i
        for i, paso in enumerate(tr["pasos"])
    }

    for plan in planes_a03.values():
        for dependencia in plan["dependencias"]:
            exigir(
                posiciones[dependencia["antes"]]
                < posiciones[dependencia["despues"]],
                f"Dependencia incumplida en "
                f"{tr['transition_id']}",
            )

    exigir(
        procesados == set(pasos_originales),
        f"Faltan pasos en {tr['transition_id']}",
    )

    exigir(
        len(operaciones)
        == tr["cantidad_operaciones_openflow"],
        "Cantidad de operaciones incompatible",
    )

    exigir(
        barreras == tr["cantidad_barreras"],
        "Cantidad de barreras incompatible",
    )

    exigir(
        activadas_ip == set(cambiadas)
        and activadas_arp == set(cambiadas),
        f"No alcanzo el Target logico: "
        f"{tr['transition_id']}",
    )

    exigir(
        len(estados) == tr["cantidad_pasos"] + 1,
        "Cantidad de estados incorrecta",
    )

    firmas = [
        estado.pop("_firma")
        for estado in estados
    ]

    perfiles_sin_repetir = []

    for firma in firmas:
        if (
            not perfiles_sin_repetir
            or firma != perfiles_sin_repetir[-1]
        ):
            perfiles_sin_repetir.append(firma)

    firma_compacta = [
        [
            f"{par}:{int(ip)}{int(arp)}"
            for par, ip, arp in perfil
        ]
        for perfil in perfiles_sin_repetir
    ]

    return {
        "transition_id": tr["transition_id"],
        "estrategia": tr["estrategia"],
        "cantidad_pasos": tr["cantidad_pasos"],
        "cantidad_estados_incluido_fs": len(estados),
        "estados_con_ip_arp_divergentes": sum(
            bool(e["comunicaciones_ip_arp_divergentes"])
            for e in estados
        ),
        "perfiles_rutas_logicas_distintos":
            len(perfiles_sin_repetir),
        "secuencia_perfiles_rutas_logicas":
            firma_compacta,
        "estado_final":
            "TARGET_LOGICO_COMPLETO_NO_VERIFICADO_EN_OVS",
        "estados": estados,
    }


def main():
    inicio = time.perf_counter()

    fs_json = leer(E02 / "FS_postfallo.json")
    targets_json = leer(
        E03 / "TargetsCandidatos.json"
    )
    propuestos = leer(
        E04 / "OperacionesOpenFlowPropuestas.json"
    )
    dependencias = leer(
        E04 / "DependenciasOpenFlow.json"
    )
    candidatas = leer(
        E04 / "TransitionsCandidatas.json"
    )

    fallo = frozenset(
        candidatas["enlace_fallado"]
    )

    for nombre, archivo in (
        ("Targets", targets_json),
        ("Operaciones", propuestos),
        ("Dependencias", dependencias),
    ):
        exigir(
            frozenset(archivo["enlace_fallado"])
            == fallo,
            f"Fallo distinto en {nombre}",
        )

    rutas_fs = rutas_de_lista(
        fs_json["comunicaciones"],
        "ruta_seleccionada",
    )

    targets = {}

    for t in targets_json["targets"]:
        exigir(
            t["id"] not in targets,
            "Target duplicado",
        )

        targets[t["id"]] = rutas_de_lista(
            t["configuracion"], "ruta"
        )

    exigir(
        targets["T000"] == rutas_fs,
        "T000 difiere de FS",
    )

    a02 = indexar_planificacion(propuestos)
    a03 = indexar_planificacion(dependencias)

    exigir(
        set(a02) == set(a03) == set(targets),
        "Targets de entrada inconsistentes",
    )

    resultados = []
    transiciones = 0
    estados_totales = 0
    estados_divergentes = 0

    for target in candidatas["targets"]:
        tid = target["target_id"]

        exigir(
            tid in targets and tid in a02,
            f"Target desconocido: {tid}",
        )

        generadas = []

        for tr in target["transitions"]:
            exigir(
                tr["estado"]
                == "PROPUESTA_NO_EJECUTABLE",
                f"Estado inesperado: {tid}",
            )

            simulado = simular_transition(
                tid,
                tr,
                rutas_fs,
                targets[tid],
                a03[tid],
                a02[tid],
            )

            generadas.append(simulado)
            transiciones += 1

            estados_totales += simulado[
                "cantidad_estados_incluido_fs"
            ]

            estados_divergentes += simulado[
                "estados_con_ip_arp_divergentes"
            ]

        firmas = {
            json.dumps(
                t["secuencia_perfiles_rutas_logicas"],
                sort_keys=True,
            )
            for t in generadas
        }

        resultados.append({
            "target_id": tid,
            "estado_target":
                target["estado_target"],
            "cantidad_transitions":
                len(generadas),
            "perfiles_de_secuencia_de_rutas_distintos":
                len(firmas),
            "rutas_fs": {
                par: rutas_fs[par]
                for par in a03[tid]
            },
            "rutas_target": {
                par: targets[tid][par]
                for par in a03[tid]
            },
            "transitions": generadas,
        })

    exigir(
        transiciones
        == candidatas["transitions_generadas"],
        "Faltan Transitions",
    )

    duracion = time.perf_counter() - inicio

    ruta = (
        E04 / "EstadosIntermediosTransitions.json"
    )

    guardar(ruta, {
        "tipo": "EstadosIntermedios_Logicos_NoEjecutados",
        "generado_utc":
            datetime.now(timezone.utc).isoformat(),
        "enlace_fallado": sorted(fallo),
        "targets_analizados": len(resultados),
        "transitions_modeladas": transiciones,
        "estados_registrados_incluyendo_iniciales":
            estados_totales,
        "estados_con_ip_arp_divergentes":
            estados_divergentes,
        "tiempo_modelado_s": round(duracion, 6),
        "ejecucion_real_ovs": False,
        "supuesto": (
            "Cada operacion se considera aplicada "
            "idealmente al registrar su paso. "
            "Las barreras son eventos propuestos; "
            "no existe BarrierReply real."
        ),
        "limitaciones": [
            "Las rutas son estados logicos modelados, "
            "no recorridos medidos en OVS.",
            "IP y ARP pueden divergir entre "
            "FlowMods independientes.",
            "El Target supone disponible el bucket "
            "FF principal; no demuestra proteccion "
            "ante otros fallos.",
            "Las reglas temporales no se verificaron "
            "realmente en OVS.",
            "No se calcularon Peak MLU, perdidas "
            "ni tiempos reales de instalacion.",
        ],
        "targets": resultados,
    })

    print(
        "\n=== ETAPA 04 - A05: ESTADOS INTERMEDIOS ==="
    )
    print("Targets analizados:", len(resultados))
    print("Transitions modeladas:", transiciones)
    print(
        "Estados registrados (incluyen FS inicial):",
        estados_totales,
    )
    print(
        "Estados con IP/ARP divergentes:",
        estados_divergentes,
    )

    ejemplo = next(
        (
            t for t in resultados
            if t["target_id"] == "T002"
        ),
        None,
    )

    if ejemplo:
        print("\n=== EJEMPLO T002 ===")

        for t in ejemplo["transitions"]:
            print(
                t["transition_id"],
                "|", t["estrategia"],
                "| pasos:", t["cantidad_pasos"],
                "| estados:",
                t["cantidad_estados_incluido_fs"],
                "| perfiles de rutas:",
                t["perfiles_rutas_logicas_distintos"],
            )

        print(
            "Secuencias de rutas distintas en T002:",
            ejemplo[
                "perfiles_de_secuencia_de_rutas_distintos"
            ],
        )

    print(
        f"\nTiempo de modelado: {duracion:.6f} s"
    )
    print("Modificaciones ejecutadas en OVS: 0")
    print("Peak MLU y factibilidad: PENDIENTES")
    print("Archivo generado:", ruta)


if __name__ == "__main__":
    main()
