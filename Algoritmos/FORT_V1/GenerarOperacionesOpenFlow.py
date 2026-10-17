
#!/usr/bin/env python3
"""Etapa 04 - A02: operaciones OpenFlow propuestas.

Reutiliza el sufijo FS cuando sea posible, conservando
su tratamiento VLAN y sus grupos Fast Failover.

Solo genera JSON. NO modifica OVS ni OS-Ken.
"""

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
E01 = BASE / "resultados/etapa01"
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
        encoding="utf-8"
    )
    temporal.replace(ruta)


def construir_puertos(registros):
    puertos = {}

    for e in registros:
        a, b = e["nodo_a"], e["nodo_b"]
        pa, pb = int(e["puerto_a"]), int(e["puerto_b"])

        exigir(
            (a, b) not in puertos and (b, a) not in puertos,
            f"Enlace duplicado: {a}-{b}"
        )

        puertos[(a, b)] = pa
        puertos[(b, a)] = pb

    return puertos


def obtener_ps(ps):
    switches = ps["switches"]
    exigir(isinstance(switches, dict), "Formato PS invalido")

    puertos = {}
    grupos = {}
    ids = set()

    for sw, datos in switches.items():
        puertos[sw] = {
            int(p["numero"]): bool(p["activo"])
            for p in datos["puertos"]
        }

        grupos[sw] = {}

        for g in datos["grupos_fast_failover"]:
            gid = int(g["group_id"])
            exigir(
                gid not in grupos[sw],
                f"Grupo PS duplicado: {sw}:{gid}"
            )
            grupos[sw][gid] = g
            ids.add(gid)

    exigir(bool(ids), "No se encontraron grupos FF")
    return puertos, grupos, ids


def vlans_registradas(fs, ps):
    ocupadas = set()

    for c in fs["comunicaciones"]:
        for p in c["pasos_openflow"]:
            for campo in ("vlan_entrada", "vlan_salida"):
                valor = p.get(campo)
                if valor is not None:
                    ocupadas.add(int(valor))

    texto = json.dumps(ps)

    for valor in re.findall(r"dl_vlan=(\d+)", texto):
        ocupadas.add(int(valor))

    for valor in re.findall(
        r"set_field:(\d+)->vlan_vid", texto
    ):
        ocupadas.add(int(valor) & 4095)

    return ocupadas


def validar_ruta(ruta, inventario, puertos_ps, arcos):
    exigir(
        len(ruta) >= 3 and len(ruta) == len(set(ruta)),
        f"Ruta con ciclos o incompleta: {ruta}"
    )

    for a, b in zip(ruta, ruta[1:]):
        exigir(
            (a, b) in inventario,
            f"Enlace inexistente: {a}->{b}"
        )

        for nodo, vecino in ((a, b), (b, a)):
            if nodo in puertos_ps:
                puerto = inventario[(nodo, vecino)]
                exigir(
                    puertos_ps[nodo].get(puerto) is True,
                    f"Puerto PS no operativo: {nodo}:{puerto}"
                )

        if a in puertos_ps and b in puertos_ps:
            exigir(
                (a, b) in arcos,
                f"Arco post-fallo no operativo: {a}->{b}"
            )


def comienzo_sufijo_comun(fs, target):
    """Primer nodo del sufijo identico de ambas rutas."""
    i = len(fs) - 1
    j = len(target) - 1

    while i >= 0 and j >= 0 and fs[i] == target[j]:
        i -= 1
        j -= 1

    indice_target = j + 1
    nodo = target[indice_target]

    if nodo.startswith("s") and indice_target > 1:
        return indice_target, nodo

    # Solo coincide el host de destino.
    return None, None


def pasos_por_switch(comunicacion):
    pasos = {}

    for paso in comunicacion["pasos_openflow"]:
        sw = paso["switch"]

        exigir(
            sw not in pasos,
            f"Paso FS duplicado: {sw}"
        )

        pasos[sw] = paso

    return pasos


def respaldo_fs(sw, primer_paso, grupos, puerto_fs):
    accion = primer_paso["acciones_openflow"]
    encontrados = re.findall(r"group:(\d+)", accion)

    exigir(
        len(encontrados) <= 1,
        f"Accion FF ambigua: {sw}"
    )

    if not encontrados:
        return {
            "acciones": accion,
            "fuente": "accion_directa_fs"
        }

    gid = int(encontrados[0])
    grupo = grupos[sw].get(gid)

    exigir(grupo is not None, f"Grupo FF ausente: {sw}:{gid}")

    seleccionado = grupo.get("bucket_seleccionado_inferido")

    exigir(
        seleccionado is not None,
        f"Bucket seleccionado desconocido: {sw}:{gid}"
    )

    buckets = [
        b for b in grupo["buckets"]
        if int(b["indice"]) == int(seleccionado)
    ]

    exigir(
        len(buckets) == 1 and buckets[0]["puerto_activo"],
        f"Bucket FF incompatible: {sw}:{gid}"
    )

    exigir(
        int(buckets[0]["watch_port"]) == puerto_fs,
        f"Bucket FF no corresponde a ruta FS: {sw}:{gid}"
    )

    return {
        "acciones": buckets[0]["acciones"],
        "fuente": f"grupo_ff_{gid}",
        "bucket": int(seleccionado)
    }


def match_trafico(tipo, origen, destino, vlan=None):
    resultado = {
        "protocolo": tipo,
        "ip_origen": origen,
        "ip_destino": destino
    }

    if vlan is not None:
        resultado["vlan_id"] = vlan

    return resultado


def accion_de_reincorporacion(paso_fs):
    """Restaurar el estado VLAN esperado por FS y ejecutar su accion."""
    vlan_original = paso_fs["vlan_entrada"]
    accion_fs = paso_fs["acciones_openflow"]

    exigir(
        isinstance(accion_fs, str) and accion_fs,
        "Paso FS sin accion OpenFlow"
    )

    if vlan_original is None:
        prefijo = "pop_vlan"
    else:
        vlan_original = int(vlan_original)
        exigir(
            1 <= vlan_original <= 4094,
            "VLAN FS invalida"
        )
        prefijo = (
            f"set_field:{4096 + vlan_original}->vlan_vid"
        )

    return f"{prefijo},{accion_fs}"


def planificar(target_id, cambio, fs_c, inventario,
               puertos_ps, grupos, arcos, vlan, group_id):
    origen = cambio["origen"]
    destino = cambio["destino"]
    anterior = cambio["ruta_fs"]
    nueva = cambio["ruta_target"]

    exigir(
        anterior == fs_c["ruta_seleccionada"],
        f"FS desactualizado: {origen}->{destino}"
    )

    validar_ruta(nueva, inventario, puertos_ps, arcos)

    exigir(
        anterior[1] == nueva[1],
        "El switch de ingreso cambio"
    )

    ingreso = nueva[1]
    p_target = inventario[(ingreso, nueva[2])]
    p_fs = inventario[(ingreso, anterior[2])]

    pasos_fs = pasos_por_switch(fs_c)

    exigir(
        ingreso in pasos_fs
        and int(pasos_fs[ingreso]["puerto_salida"]) == p_fs,
        "El ingreso FS no coincide con inventario"
    )

    respaldo = respaldo_fs(
        ingreso, pasos_fs[ingreso], grupos, p_fs
    )

    indice_union, switch_union = comienzo_sufijo_comun(
        anterior, nueva
    )

    if indice_union is None:
        ultimo_preparado = len(nueva) - 2
    else:
        ultimo_preparado = indice_union

    operaciones = []

    def agregar(fase, comando, sw, **datos):
        operaciones.append({
            "id": (
                f"{target_id}_{origen}_{destino}_"
                f"O{len(operaciones) + 1:03d}"
            ),
            "fase_propuesta": fase,
            "comando": comando,
            "switch": sw,
            **datos
        })

    ip_origen = fs_c["ip_origen"]
    ip_destino = fs_c["ip_destino"]

    # Preparar solamente el nuevo tramo hasta
    # reincorporarse al sufijo existente de FS.
    for i in range(2, ultimo_preparado + 1):
        sw = nueva[i]
        siguiente = nueva[i + 1]
        puerto = inventario[(sw, siguiente)]

        if sw == switch_union:
            acciones = accion_de_reincorporacion(
                pasos_fs[sw]
            )
            descripcion = "REINCORPORACION_A_FS"

        elif siguiente == destino:
            acciones = f"pop_vlan,output:{puerto}"
            descripcion = "ENTREGA_A_HOST"

        else:
            acciones = f"output:{puerto}"
            descripcion = "TRANSITO_ETIQUETADO"

        for tipo in ("ip", "arp"):
            agregar(
                "PREPARACION",
                "FlowMod_ADD_PROPUESTO",
                sw,
                tabla=0,
                prioridad_provisional=300,
                match=match_trafico(
                    tipo, ip_origen, ip_destino, vlan
                ),
                acciones=acciones,
                funcion=descripcion,
                verificar_conflictos=True
            )

    # Identificar protecciones del sufijo que se conservan.
    grupos_reutilizados = []

    if switch_union is not None:
        indice_fs = anterior.index(switch_union)

        for sw in anterior[indice_fs:-1]:
            paso = pasos_fs.get(sw)
            exigir(
                paso is not None,
                f"Paso FS faltante en {sw}"
            )

            grupos_reutilizados.extend(
                {
                    "switch": sw,
                    "group_id": int(gid)
                }
                for gid in re.findall(
                    r"group:(\d+)",
                    paso["acciones_openflow"]
                )
            )

    # Si ambos caminos usan el mismo primer puerto,
    # no inventar un grupo FF con buckets redundantes.
    independiente = p_target != p_fs

    if independiente:
        primario = (
            "push_vlan:0x8100,"
            f"set_field:{4096 + vlan}->vlan_vid,"
            f"output:{p_target}"
        )

        agregar(
            "PREPARACION",
            "GroupMod_ADD_PROPUESTO",
            ingreso,
            group_id_provisional=group_id,
            tipo="ff",
            buckets=[
                {
                    "indice": 0,
                    "watch_port": p_target,
                    "acciones": primario,
                    "rol": "target"
                },
                {
                    "indice": 1,
                    "watch_port": p_fs,
                    "acciones": respaldo["acciones"],
                    "rol": "respaldo_fs",
                    "fuente": respaldo["fuente"]
                }
            ],
            verificar_proteccion_extremo_a_extremo=True
        )

        for tipo in ("ip", "arp"):
            agregar(
                "ACTIVACION_PENDIENTE",
                "FlowMod_MODIFY_STRICT_PROPUESTO",
                ingreso,
                match_objetivo=match_trafico(
                    tipo, ip_origen, ip_destino
                ),
                prioridad_original="VERIFICAR_EN_OVS",
                acciones_nuevas=f"group:{group_id}",
                requiere_barrier=True,
                requiere_match_exacto=True
            )

        estado = "PROPUESTA_REQUIERE_VALIDACION"

    else:
        estado = "BLOQUEADO_PRIMER_SALTO_COMPARTIDO"

    return {
        "origen": origen,
        "destino": destino,
        "ruta_fs": anterior,
        "ruta_target": nueva,
        "switch_reincorporacion_fs": switch_union,
        "vlan_provisional": vlan,
        "grupo_ff_provisional": (
            group_id if independiente else None
        ),
        "puerto_target": p_target,
        "puerto_respaldo_fs": p_fs,
        "respaldo_primer_salto_independiente": independiente,
        "grupos_ff_reutilizados_en_sufijo":
            grupos_reutilizados,
        "estado_plan": estado,
        "cantidad_operaciones": len(operaciones),
        "operaciones": operaciones,
        "advertencias": [
            "Verificar VLAN, grupos, coincidencias y "
            "prioridades contra OVS actualizado.",
            "Verificar reglas del sufijo FS y ausencia "
            "de restricciones por puerto de entrada.",
            "Comprobar proteccion ante fallos de enlaces "
            "intermedios, no solo el primer salto.",
            "Calcular dependencias y estados intermedios "
            "antes de considerar ejecutable la propuesta.",
            "No eliminar las reglas FS durante preparacion."
        ]
    }


def main():
    inicio = time.perf_counter()

    fs_json = leer(E02 / "FS_postfallo.json")
    ps_json = leer(E02 / "PS_postfallo.json")
    estado = leer(E02 / "EstadoPostFallo.json")
    topologia = leer(E03 / "TopologiaPostFallo.json")
    diferencias = leer(E04 / "DiferenciasFSTargets.json")
    filtrados = leer(E03 / "TargetsFiltrados.json")

    inventario = construir_puertos(
        leer(E01 / "puertos_detectados.json")
    )

    fallo = frozenset(estado["enlace_fallado"])

    exigir(
        frozenset(diferencias["enlace_fallado"]) == fallo
        and frozenset(filtrados["enlace_fallado"]) == fallo,
        "Los registros corresponden a fallos diferentes"
    )

    puertos_ps, grupos_ps, ids_grupos = obtener_ps(ps_json)

    arcos = set()

    for e in topologia["enlaces_operativos"]:
        a, b = e["extremo_a"], e["extremo_b"]
        arcos.add((a, b))
        arcos.add((b, a))

    exigir(
        not any(
            frozenset((a, b)) == fallo
            for a, b in arcos
        ),
        "El enlace fallado aparece operativo"
    )

    fs = {
        (c["origen"], c["destino"]): c
        for c in fs_json["comunicaciones"]
    }

    exigir(
        len(fs) == fs_json["cantidad_comunicaciones"],
        "Comunicaciones FS duplicadas"
    )

    admitidos = {
        x["target_id"] for x in filtrados["admitidos"]
    }

    targets = diferencias["targets"]

    exigir(
        len(targets) == diferencias["cantidad_targets_comparados"],
        "Cantidad de Targets inconsistente"
    )

    disponibles = (
        v for v in range(2000, 4095)
        if v not in vlans_registradas(fs_json, ps_json)
    )

    siguiente_grupo = max(ids_grupos) + 1

    resultados = []
    operaciones_totales = 0
    cambios_totales = 0
    pendientes_primer_salto = 0
    reincorporaciones = 0

    for target in targets:
        tid = target["target_id"]

        exigir(
            tid in admitidos,
            f"Target no admitido: {tid}"
        )

        planes = []

        for cambio in target["cambios"]:
            clave = (cambio["origen"], cambio["destino"])

            exigir(
                clave in fs,
                f"Comunicacion FS ausente: {clave}"
            )

            try:
                vlan = next(disponibles)
            except StopIteration:
                raise RuntimeError(
                    "VLAN provisionales agotadas"
                )

            plan = planificar(
                tid, cambio, fs[clave],
                inventario, puertos_ps, grupos_ps,
                arcos, vlan, siguiente_grupo
            )

            if plan["grupo_ff_provisional"] is not None:
                siguiente_grupo += 1
            else:
                pendientes_primer_salto += 1

            if plan["switch_reincorporacion_fs"]:
                reincorporaciones += 1

            operaciones_totales += plan["cantidad_operaciones"]
            cambios_totales += 1
            planes.append(plan)

        exigir(
            len(planes) == target["cantidad_rutas_modificadas"],
            f"Diferencias inconsistentes: {tid}"
        )

        resultados.append({
            "target_id": tid,
            "cantidad_comunicaciones_modificadas": len(planes),
            "cantidad_operaciones_propuestas": sum(
                p["cantidad_operaciones"] for p in planes
            ),
            "planes_bloqueados": sum(
                p["estado_plan"].startswith("BLOQUEADO")
                for p in planes
            ),
            "planes": planes
        })

    tiempo = time.perf_counter() - inicio

    salida = E04 / "OperacionesOpenFlowPropuestas.json"

    guardar(salida, {
        "tipo": "OperacionesOpenFlowPropuestas",
        "generado_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "enlace_fallado": sorted(fallo),
        "referencia_fs": "T000",
        "targets_analizados": len(resultados),
        "rutas_modificadas_acumuladas": cambios_totales,
        "operaciones_propuestas": operaciones_totales,
        "reincorporaciones_a_fs": reincorporaciones,
        "planes_sin_respaldo_inicial_independiente":
            pendientes_primer_salto,
        "tiempo_generacion_s": round(tiempo, 6),
        "ejecutado_en_ovs": False,
        "identificadores_provisionales": True,
        "limitaciones": [
            "Catalogo preliminar no ejecutable.",
            "Los grupos FF reutilizados deben verificarse "
            "contra el estado real de OVS.",
            "Los planes con primer salto compartido "
            "no incluyen activacion automatica.",
            "Faltan comprobaciones de proteccion remota, "
            "conflictos, dependencias y estados intermedios.",
            "No se han calculado Peak MLU ni costos.",
            "Cada Target es una alternativa independiente."
        ],
        "targets": resultados
    })

    print("\n=== ETAPA 04 - A02: OPERACIONES OPENFLOW ===")
    print("Fallo:", " - ".join(x.upper() for x in sorted(fallo)))
    print("Targets analizados:", len(resultados))
    print("Rutas modificadas acumuladas:", cambios_totales)
    print("Operaciones propuestas:", operaciones_totales)
    print("Reincorporaciones a FS:", reincorporaciones)
    print(
        "Planes pendientes por primer salto compartido:",
        pendientes_primer_salto
    )

    ejemplo = next(
        (t for t in resultados if t["target_id"] == "T001"),
        None
    )

    if ejemplo:
        print("\n=== EJEMPLO T001 ===")

        for plan in ejemplo["planes"]:
            print(
                "Comunicacion:",
                plan["origen"], "->", plan["destino"]
            )
            print(
                "Reincorporacion a FS:",
                plan["switch_reincorporacion_fs"]
            )
            print("VLAN provisional:", plan["vlan_provisional"])
            print(
                "Grupo FF provisional:",
                plan["grupo_ff_provisional"]
            )
            print(
                "Grupos FF reutilizados:",
                plan["grupos_ff_reutilizados_en_sufijo"]
            )

            for op in plan["operaciones"]:
                print(
                    op["fase_propuesta"],
                    "|", op["comando"],
                    "|", op["switch"],
                    "|", op.get("acciones", "")
                )

    print(f"\nTiempo de generacion: {tiempo:.6f} s")
    print("Modificaciones ejecutadas en OVS: 0")
    print("Dependencias y seguridad: PENDIENTES")
    print("Archivo generado:", salida)


if __name__ == "__main__":
    main()
