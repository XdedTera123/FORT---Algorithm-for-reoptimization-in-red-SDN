
#!/usr/bin/env python3
"""FORT: validacion de Targets contra OpenFlow 1.3 real.

Consulta FlowStats, GroupDesc y PortDesc en los switches.
Prepara especificaciones de actualizacion y registra bloqueos.

NO envia FlowMod ni GroupMod.
NO autoriza la ejecucion de Transitions.
"""

import ipaddress
import json

from datetime import datetime, timezone
from pathlib import Path

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    MAIN_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls,
)
from os_ken.lib import hub
from os_ken.ofproto import ofproto_v1_3


BASE = Path(__file__).resolve().parents[1]

PLANES = BASE / "resultados/etapa06/fort_planes"
ESTADOS = BASE / "resultados/etapa06/fort_capturas_estado"
SALIDAS = BASE / "resultados/etapa06/fort_validaciones"

COOKIE_FF = 0xA103


def leer(ruta):
    return json.loads(ruta.read_text(encoding="utf-8"))


def guardar(ruta, datos):
    ruta.parent.mkdir(parents=True, exist_ok=True)

    temporal = ruta.with_suffix(".tmp")
    temporal.write_text(
        json.dumps(datos, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporal.replace(ruta)


def exigir(condicion, mensaje):
    if not condicion:
        raise RuntimeError(mensaje)


def acciones(regla):
    resultado = []

    for instruccion in regla.instructions:
        exigir(
            hasattr(instruccion, "actions"),
            "Instruccion OpenFlow inesperada",
        )
        resultado.extend(instruccion.actions)

    return resultado


def salida_de_acciones(lista):
    salidas = [
        int(a.port)
        for a in lista
        if type(a).__name__ == "OFPActionOutput"
    ]

    exigir(
        len(salidas) == 1,
        "Se esperaba una unica salida fisica",
    )

    return salidas[0]


def resumen_acciones(lista):
    return [str(a) for a in lista]


def puertos_escenario(inventario):
    mapa = {}

    for e in inventario:
        for origen, destino, puerto in (
            (e["nodo_a"], e["nodo_b"], e["puerto_a"]),
            (e["nodo_b"], e["nodo_a"], e["puerto_b"]),
        ):
            clave = (origen, destino)

            exigir(
                clave not in mapa,
                f"Puerto duplicado: {clave}",
            )

            mapa[clave] = int(puerto)

    return mapa


def base_match(par, ips, protocolo):
    origen, destino = par

    if protocolo == "ipv4":
        return {
            "eth_type": 0x0800,
            "ipv4_src": ips[origen],
            "ipv4_dst": ips[destino],
        }

    return {
        "eth_type": 0x0806,
        "arp_spa": ips[origen],
        "arp_tpa": ips[destino],
    }


def hallar_regla(tablas, switch, patron):
    encontradas = []

    for regla in tablas.get(switch, []):
        if (
            int(regla.table_id) == 0
            and int(regla.priority) == 100
            and int(regla.cookie) == COOKIE_FF
            and dict(regla.match.items()) == patron
        ):
            encontradas.append(regla)

    exigir(
        len(encontradas) == 1,
        f"Regla base IP/ARP no unica en {switch}: {patron}",
    )

    return encontradas[0]


def preparar_target(
    target,
    flujos,
    grupos,
    puertos_activos,
    inventario,
    ips,
    vlan_ocupadas,
    grupos_ocupados,
):
    operaciones = []
    bloqueos = []

    total_add = 0
    total_modify = 0
    total_group = 0

    for cambio in target["planes_por_comunicacion"]:
        origen = cambio["origen"]
        destino = cambio["destino"]

        fs = cambio["ruta_fs"]
        nueva = cambio["ruta_target"]

        par = (origen, destino)
        switch = nueva[1]

        try:
            exigir(
                fs[1] == switch,
                "Switch de ingreso diferente",
            )

            exigir(
                fs[2] != nueva[2],
                "Primer salto compartido: requiere otra estrategia",
            )

            for a, b in zip(nueva, nueva[1:]):
                exigir(
                    (a, b) in inventario,
                    f"Enlace inexistente: {a}-{b}",
                )

                if a.startswith("s"):
                    puerto = inventario[(a, b)]

                    exigir(
                        puertos_activos.get((a, puerto)) is True,
                        f"Puerto inactivo: {a}:{puerto}",
                    )

            puerto_fs = inventario[(switch, fs[2])]
            puerto_target = inventario[(switch, nueva[2])]

            reglas_originales = {}
            respaldo = None

            for protocolo in ("ipv4", "arp"):
                patron = base_match(par, ips, protocolo)

                regla = hallar_regla(
                    flujos, switch, patron
                )

                lista = acciones(regla)

                exigir(
                    len(lista) == 1,
                    "Accion de ingreso compleja",
                )

                accion = lista[0]
                tipo = type(accion).__name__

                if tipo == "OFPActionGroup":
                    group_id = int(accion.group_id)

                    grupo = grupos.get(
                        switch, {}
                    ).get(group_id)

                    exigir(
                        grupo is not None
                        and int(grupo.type) == 3,
                        f"Grupo FF invalido: {switch}:{group_id}",
                    )

                    buckets = [
                        b
                        for b in grupo.buckets
                        if puertos_activos.get(
                            (switch, int(b.watch_port))
                        ) is True
                    ]

                    exigir(
                        bool(buckets),
                        "Grupo FF sin bucket operativo",
                    )

                    bucket = buckets[0]

                    exigir(
                        salida_de_acciones(bucket.actions)
                        == puerto_fs,
                        "Salida FF diferente del estado FS",
                    )

                    acciones_respaldo = list(bucket.actions)

                elif tipo == "OFPActionOutput":
                    exigir(
                        int(accion.port) == puerto_fs,
                        "Salida directa diferente del estado FS",
                    )

                    acciones_respaldo = list(lista)

                else:
                    raise RuntimeError(
                        f"Accion de ingreso incompatible: {tipo}"
                    )

                respaldo_actual = resumen_acciones(
                    acciones_respaldo
                )

                if respaldo is None:
                    respaldo = respaldo_actual
                else:
                    exigir(
                        respaldo == respaldo_actual,
                        "IPv4 y ARP tienen respaldos diferentes",
                    )

                reglas_originales[protocolo] = {
                    "match": patron,
                    "cookie": int(regla.cookie),
                    "prioridad": int(regla.priority),
                    "acciones_actuales": resumen_acciones(lista),
                    "acciones_respaldo": respaldo_actual,
                }

            vlan = next(
                (
                    v for v in range(100, 4095)
                    if v not in vlan_ocupadas
                ),
                None,
            )

            exigir(
                vlan is not None,
                "Sin VLAN disponibles",
            )

            vlan_ocupadas.add(vlan)

            grupo_nuevo = next(
                (
                    g for g in range(40000, 65000)
                    if g not in grupos_ocupados
                ),
                None,
            )

            exigir(
                grupo_nuevo is not None,
                "Sin identificadores de grupo disponibles",
            )

            grupos_ocupados.add(grupo_nuevo)

            # Identificar el sufijo comun con FS.
            sufijo = 0

            while (
                sufijo < min(len(fs), len(nueva))
                and fs[-1 - sufijo] == nueva[-1 - sufijo]
            ):
                sufijo += 1

            union = len(nueva) - sufijo

            exigir(
                union > 1,
                "Punto de reincorporacion invalido",
            )

            ultimo = (
                union
                if union < len(nueva) - 1
                else len(nueva) - 2
            )

            exigir(
                ultimo >= 2,
                "Tramo nuevo no preparable",
            )

            preparar = []

            for indice in range(2, ultimo + 1):
                nodo = nueva[indice]
                siguiente = nueva[indice + 1]

                puerto = inventario[(nodo, siguiente)]

                if indice == union and nodo in fs:
                    funcion = "REINCORPORACION_FS"
                    acciones_propuestas = {}

                    for protocolo in ("ipv4", "arp"):
                        regla = hallar_regla(
                            flujos,
                            nodo,
                            base_match(par, ips, protocolo),
                        )

                        acciones_propuestas[protocolo] = (
                            ["pop_vlan"]
                            + resumen_acciones(acciones(regla))
                        )

                elif siguiente == destino:
                    funcion = "ENTREGA_HOST"
                    acciones_propuestas = {
                        p: ["pop_vlan", f"output:{puerto}"]
                        for p in ("ipv4", "arp")
                    }

                else:
                    funcion = "TRANSITO_VLAN"
                    acciones_propuestas = {
                        p: [f"output:{puerto}"]
                        for p in ("ipv4", "arp")
                    }

                for protocolo in ("ipv4", "arp"):
                    patron = {
                        **base_match(par, ips, protocolo),
                        "vlan_vid": 0x1000 | vlan,
                    }

                    conflictos = [
                        regla
                        for regla in flujos.get(nodo, [])
                        if (
                            int(regla.table_id) == 0
                            and dict(regla.match.items()) == patron
                        )
                    ]

                    exigir(
                        not conflictos,
                        f"Match VLAN ocupado: {nodo}:{vlan}",
                    )

                    preparar.append({
                        "switch": nodo,
                        "protocolo": protocolo,
                        "match_exacto": patron,
                        "prioridad": 300,
                        "acciones_propuestas":
                            acciones_propuestas[protocolo],
                        "funcion": funcion,
                    })

            total_add += len(preparar)
            total_modify += 2
            total_group += 1

            operaciones.append({
                "comunicacion": f"{origen}->{destino}",
                "ruta_fs": fs,
                "ruta_target": nueva,
                "switch_ingreso": switch,
                "puerto_fs": puerto_fs,
                "puerto_target": puerto_target,
                "vlan_nueva": vlan,
                "group_id_nuevo": grupo_nuevo,
                "reglas_actuales_ingreso": reglas_originales,
                "respaldo_actual_verificado": respaldo,
                "flowmods_preparacion": preparar,
                "grupo_ff_propuesto": {
                    "bucket_primario": {
                        "watch_port": puerto_target,
                        "acciones": [
                            "push_vlan",
                            f"set_vlan:{vlan}",
                            f"output:{puerto_target}",
                        ],
                    },
                    "bucket_respaldo": {
                        "watch_port": puerto_fs,
                        "acciones": respaldo,
                    },
                },
                "activacion_propuesta": (
                    "MODIFY_STRICT IPv4/ARP "
                    "despues de preparar y verificar"
                ),
                "requiere_barreras": True,
            })

        except Exception as error:
            bloqueos.append({
                "comunicacion": f"{origen}->{destino}",
                "motivo": str(error),
            })

    compatible = bool(operaciones) and not bloqueos

    return {
        "target_id": target["target_id"],
        "estado": (
            "PREPARACION_PLAUSIBLE_REQUIERE_PRUEBA_EN_OVS"
            if compatible
            else "BLOQUEADO"
        ),
        "bloqueos": bloqueos,
        "comunicaciones": operaciones,
        "flowmods_add_propuestos": total_add,
        "flowmods_modify_strict_propuestos": total_modify,
        "groupmods_add_propuestos": total_group,
        "ejecucion_openflow_autorizada": False,
    }


class VerificadorOpenFlowFORT(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.escenario = leer(
            BASE / "config/escenario.json"
        )

        self.inventario = puertos_escenario(
            leer(
                BASE / "resultados/etapa01/"
                "puertos_detectados.json"
            )
        )

        self.ips = {
            h["nombre"]: str(
                ipaddress.ip_interface(h["ip"]).ip
            )
            for h in self.escenario["hosts"]
        }

        self.datapaths = {}

        self.vistos = {
            p.name
            for p in PLANES.glob("FORT_Plan_*.json")
        }

        self.tarea = None
        self.pendientes = {}
        self.respuestas = {}

        hub.spawn(self.vigilar)

        print(
            "FORT VALIDADOR: comprobacion "
            "OpenFlow real ACTIVADA",
            flush=True,
        )

        print(
            "FORT VALIDADOR: modificaciones "
            "en OVS DESACTIVADAS",
            flush=True,
        )

    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        MAIN_DISPATCHER,
    )
    def conectado(self, evento):
        dp = evento.datapath

        if dp is not None:
            self.datapaths[f"s{dp.id}"] = dp

    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        DEAD_DISPATCHER,
    )
    def desconectado(self, evento):
        dp = evento.datapath

        if dp is not None:
            self.datapaths.pop(f"s{dp.id}", None)

            if self.tarea is not None:
                self.fallar(
                    "SWITCH_DESCONECTADO"
                )

    def vigilar(self):
        while True:
            if (
                self.tarea is None
                and set(self.datapaths)
                == set(self.escenario["switches"])
            ):
                for archivo in sorted(
                    PLANES.glob("FORT_Plan_*.json")
                ):
                    if archivo.name in self.vistos:
                        continue

                    captura = ESTADOS / archivo.name.replace(
                        "FORT_Plan_",
                        "FORT_Estado_",
                    )

                    if not captura.is_file():
                        continue

                    try:
                        plan = leer(archivo)
                        estado = leer(captura)

                        exigir(
                            plan["captura_origen_utc"]
                            == estado["fecha_utc"],
                            "Plan y captura desalineados",
                        )

                        self.vistos.add(archivo.name)

                        self.iniciar(
                            archivo,
                            plan,
                            estado,
                        )

                    except Exception as error:
                        self.vistos.add(archivo.name)

                        print(
                            "FORT VALIDADOR ERROR:",
                            error,
                            flush=True,
                        )

                    break

            hub.sleep(0.5)

    def iniciar(self, ruta, plan, estado):
        self.tarea = {
            "ruta": ruta,
            "plan": plan,
            "estado": estado,
        }

        self.pendientes = {}

        self.respuestas = {
            "flujos": {},
            "grupos": {},
            "puertos": {},
        }

        for sw, dp in sorted(self.datapaths.items()):
            parser = dp.ofproto_parser

            solicitudes = {
                "flujos": parser.OFPFlowStatsRequest(dp),
                "grupos": parser.OFPGroupDescStatsRequest(
                    dp, 0
                ),
                "puertos": parser.OFPPortDescStatsRequest(
                    dp, 0
                ),
            }

            for tipo, solicitud in solicitudes.items():
                dp.send_msg(solicitud)

                self.pendientes[(sw, tipo)] = {
                    "xid": solicitud.xid,
                    "partes": [],
                }

        print(
            "FORT VALIDADOR: 24 respuestas "
            "OpenFlow solicitadas",
            flush=True,
        )

        hub.spawn(
            self.esperar_timeout,
            ruta.name,
        )

    def esperar_timeout(self, nombre):
        hub.sleep(12)

        if (
            self.tarea is not None
            and self.tarea["ruta"].name == nombre
        ):
            self.fallar(
                "TIMEOUT_RESPUESTAS_OPENFLOW"
            )

    def fallar(self, motivo):
        if self.tarea is None:
            return

        tarea = self.tarea

        salida = SALIDAS / tarea["ruta"].name.replace(
            "FORT_Plan_",
            "FORT_Preflight_",
        )

        guardar(salida, {
            "tipo": "FORT_PREFLIGHT_OPENFLOW",
            "estado": "BLOQUEADO",
            "motivo": motivo,
            "ejecucion_openflow_autorizada": False,
        })

        self.tarea = None
        self.pendientes.clear()

        print(
            "FORT VALIDADOR: BLOQUEADO:",
            motivo,
            flush=True,
        )

    def incorporar(self, tipo, mensaje):
        if self.tarea is None:
            return

        sw = f"s{mensaje.datapath.id}"

        pendiente = self.pendientes.get(
            (sw, tipo)
        )

        if (
            pendiente is None
            or mensaje.xid != pendiente["xid"]
        ):
            return

        pendiente["partes"].extend(
            mensaje.body
        )

        if (
            mensaje.flags
            & mensaje.datapath.ofproto.OFPMPF_REPLY_MORE
        ):
            return

        self.respuestas[tipo][sw] = (
            pendiente["partes"]
        )

        del self.pendientes[(sw, tipo)]

        if not self.pendientes:
            try:
                self.analizar()

            except Exception as error:
                self.fallar(
                    f"VALIDACION: {error}"
                )

    @set_ev_cls(
        ofp_event.EventOFPFlowStatsReply,
        MAIN_DISPATCHER,
    )
    def respuesta_flujos(self, evento):
        self.incorporar(
            "flujos",
            evento.msg,
        )

    @set_ev_cls(
        ofp_event.EventOFPGroupDescStatsReply,
        MAIN_DISPATCHER,
    )
    def respuesta_grupos(self, evento):
        self.incorporar(
            "grupos",
            evento.msg,
        )

    @set_ev_cls(
        ofp_event.EventOFPPortDescStatsReply,
        MAIN_DISPATCHER,
    )
    def respuesta_puertos(self, evento):
        self.incorporar(
            "puertos",
            evento.msg,
        )

    def analizar(self):
        tarea = self.tarea

        exigir(
            tarea is not None,
            "No existe tarea de validacion",
        )

        switches = set(
            self.escenario["switches"]
        )

        exigir(
            all(
                set(datos) == switches
                for datos in self.respuestas.values()
            ),
            "Snapshot OpenFlow incompleto",
        )

        activos = {}

        for sw, lista in self.respuestas["puertos"].items():
            dp = self.datapaths[sw]

            for puerto in lista:
                activos[(sw, int(puerto.port_no))] = not (
                    int(puerto.config)
                    & dp.ofproto.OFPPC_PORT_DOWN
                    or int(puerto.state)
                    & (
                        dp.ofproto.OFPPS_LINK_DOWN
                        | dp.ofproto.OFPPS_BLOCKED
                    )
                )

        # Confirmar que el fallo no ha cambiado.
        for direccion in tarea["estado"]["rs"]["direcciones"]:
            sw = direccion["origen"]
            vecino = direccion["destino"]

            puerto_a = self.inventario[(sw, vecino)]
            puerto_b = self.inventario[(vecino, sw)]

            esperado = bool(
                direccion["activo"]
            )

            real = (
                activos.get((sw, puerto_a)) is True
                and activos.get((vecino, puerto_b)) is True
            )

            exigir(
                real == esperado,
                f"Topologia modificada: {sw}->{vecino}",
            )

        grupos = {
            sw: {
                int(g.group_id): g
                for g in lista
            }
            for sw, lista in self.respuestas["grupos"].items()
        }

        cantidad_grupos = sum(
            len(g)
            for g in grupos.values()
        )

        exigir(
            cantidad_grupos
            == tarea["estado"]["ps"]["cantidad_grupos_ff"],
            "Inventario de grupos modificado",
        )

        # Detectar VLAN actualmente utilizadas.
        vlans = set()

        for lista in self.respuestas["flujos"].values():
            for regla in lista:
                match = dict(
                    regla.match.items()
                )

                valor = match.get("vlan_vid")

                if isinstance(valor, int):
                    vlans.add(
                        valor & 0xFFF
                    )

        for grupos_sw in grupos.values():
            for grupo in grupos_sw.values():
                for bucket in grupo.buckets:
                    for accion in bucket.actions:
                        if (
                            type(accion).__name__
                            == "OFPActionSetField"
                            and getattr(
                                accion, "key", None
                            ) == "vlan_vid"
                        ):
                            vlans.add(
                                int(accion.value) & 0xFFF
                            )

        ids_grupos = {
            int(gid)
            for datos in grupos.values()
            for gid in datos
        }

        resultados = []

        for target in tarea["plan"]["targets"]:
            resultados.append(
                preparar_target(
                    target,
                    self.respuestas["flujos"],
                    grupos,
                    activos,
                    self.inventario,
                    self.ips,
                    set(vlans),
                    set(ids_grupos),
                )
            )

        compatibles = [
            t for t in resultados
            if t["estado"].startswith(
                "PREPARACION_"
            )
        ]

        ids_compatibles = {
            t["target_id"]
            for t in compatibles
        }

        parejas = [
            p for p in tarea["plan"]["parejas"]
            if (
                p["target_id"] in ids_compatibles
                and p["admisibilidad_modelo"]
            )
        ]

        parejas.sort(
            key=lambda p: (
                p["final_mlu_pct"],
                p["peak_mlu_pct"],
                p["mensajes_modificacion"],
                p["transition_id"],
            )
        )

        preferida = None

        if parejas:
            p = parejas[0]

            preferida = {
                "target_id": p["target_id"],
                "transition_id": p["transition_id"],
                "final_mlu_pct": p["final_mlu_pct"],
                "peak_mlu_pct": p["peak_mlu_pct"],
            }

        salida = SALIDAS / tarea["ruta"].name.replace(
            "FORT_Plan_",
            "FORT_Preflight_",
        )

        guardar(salida, {
            "tipo": "FORT_PREFLIGHT_OPENFLOW",
            "fecha_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "captura_origen_utc":
                tarea["estado"]["fecha_utc"],
            "fallo": tarea["estado"]["fallo"],
            "targets_evaluados": len(resultados),
            "targets_con_preparacion_compatible":
                len(compatibles),
            "targets_bloqueados":
                len(resultados) - len(compatibles),
            "seleccion_preliminar":
                tarea["plan"]["pareja_preferida_preliminar"],
            "pareja_preferida_preflight": preferida,
            "estado": "VALIDACION_ESTRUCTURAL_OPENFLOW_REAL",
            "ejecucion_openflow_autorizada": False,
            "limitaciones": [
                "No se enviaron FlowMod ni GroupMod",
                "No se demostro seguridad de estados intermedios",
                "Pendientes barreras, ejecucion y rollback",
                "Snapshot OpenFlow no atomico",
            ],
            "targets": resultados,
        })

        print(
            "\n=== FORT: PREFLIGHT OPENFLOW REAL ===",
            flush=True,
        )

        print(
            "Fallo:",
            tarea["estado"]["fallo"],
            flush=True,
        )

        print(
            "Targets Pareto:",
            len(resultados),
            flush=True,
        )

        print(
            "Preparaciones compatibles:",
            len(compatibles),
            flush=True,
        )

        print(
            "Bloqueados:",
            len(resultados) - len(compatibles),
            flush=True,
        )

        print(
            "Preferencia OpenFlow preliminar:",
            preferida,
            flush=True,
        )

        print(
            "Modificaciones ejecutadas en OVS: 0",
            flush=True,
        )

        print(
            "Archivo:",
            salida,
            flush=True,
        )

        self.tarea = None
        self.pendientes.clear()
