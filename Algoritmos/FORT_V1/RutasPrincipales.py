
#!/usr/bin/env python3
# Etapa 01 - Actividad 04
# Rutas principales y proteccion Fast Failover OpenFlow 1.3.
# Escenario: un fallo individual de enlace.

import ipaddress
import json
from collections import defaultdict, deque
from pathlib import Path

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3


BASE = Path(__file__).resolve().parents[1]
CONFIG = BASE / "config" / "escenario.json"
INVENTARIO = (
    BASE / "resultados" / "etapa01" / "puertos_detectados.json"
)
COOKIE = 0xA103


def leer_json(ruta):
    with ruta.open("r", encoding="utf-8") as archivo:
        return json.load(archivo)


def camino_minimo(grafo, origen, destino, enlace_excluido=None):
    cola = deque([[origen]])
    visitados = {origen}

    while cola:
        camino = cola.popleft()
        actual = camino[-1]

        if actual == destino:
            return camino

        for vecino in sorted(grafo[actual]):
            if frozenset((actual, vecino)) == enlace_excluido:
                continue
            if vecino not in visitados:
                visitados.add(vecino)
                cola.append(camino + [vecino])

    raise RuntimeError(
        f"No existe desvio entre {origen} y {destino}"
    )


class RutasPrincipales(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.switches_validos = set()
        self.grupos = defaultdict(list)
        self.reglas = defaultdict(list)
        self.rutas = []
        self.total_grupos = 0
        self.total_reglas = 0

        self.preparar_proteccion()

    def agregar_reglas(self, switch, ip_a, ip_b,
                       accion, vlan=None, quitar_vlan=False):
        for protocolo in ("ipv4", "arp"):
            self.reglas[switch].append({
                "protocolo": protocolo,
                "ip_a": ip_a,
                "ip_b": ip_b,
                "accion": accion,
                "vlan": vlan,
                "quitar_vlan": quitar_vlan
            })
            self.total_reglas += 1

    def preparar_proteccion(self):
        escenario = leer_json(CONFIG)
        inventario = leer_json(INVENTARIO)

        switches = escenario["switches"]
        self.switches_validos = set(switches)

        if len(switches) != len(self.switches_validos):
            raise RuntimeError("Switches duplicados")

        hosts = {}
        for host in escenario["hosts"]:
            nombre = host["nombre"]
            if nombre in hosts:
                raise RuntimeError(f"Host duplicado: {nombre}")
            if host["switch"] not in self.switches_validos:
                raise RuntimeError("Switch de host desconocido")

            hosts[nombre] = {
                "switch": host["switch"],
                "ip": str(ipaddress.ip_interface(host["ip"]).ip)
            }

        esperados = {
            frozenset(enlace)
            for enlace in escenario["enlaces"]
        }
        esperados.update(
            frozenset((nombre, datos["switch"]))
            for nombre, datos in hosts.items()
        )

        reales = {
            frozenset((e["nodo_a"], e["nodo_b"]))
            for e in inventario
        }

        if (
            esperados != reales
            or len(inventario) != len(esperados)
        ):
            raise RuntimeError(
                "Inventario de Mininet inconsistente "
                "con el escenario"
            )

        puertos = {}
        ocupados = set()
        grafo = {
            switch: set()
            for switch in self.switches_validos
        }

        for enlace in inventario:
            a = enlace["nodo_a"]
            b = enlace["nodo_b"]

            for nodo, vecino, numero in (
                (a, b, enlace["puerto_a"]),
                (b, a, enlace["puerto_b"])
            ):
                if nodo not in self.switches_validos:
                    continue

                if (
                    type(numero) is not int
                    or numero <= 0
                    or (nodo, numero) in ocupados
                    or (nodo, vecino) in puertos
                ):
                    raise RuntimeError(
                        f"Puerto invalido o duplicado en {nodo}"
                    )

                puertos[(nodo, vecino)] = numero
                ocupados.add((nodo, numero))

            if a in grafo and b in grafo:
                grafo[a].add(b)
                grafo[b].add(a)

        siguiente_grupo = 1000
        siguiente_vlan = 100

        for origen in sorted(hosts):
            for destino in sorted(hosts):
                if origen == destino:
                    continue

                ip_a = hosts[origen]["ip"]
                ip_b = hosts[destino]["ip"]

                ruta = camino_minimo(
                    grafo,
                    hosts[origen]["switch"],
                    hosts[destino]["switch"]
                )

                self.rutas.append((origen, destino, ruta))

                salidas_principales = {}
                desvios = []

                # Preparar grupos y forwarding principal.
                for posicion, switch in enumerate(ruta):
                    if posicion == len(ruta) - 1:
                        accion = (
                            "output",
                            puertos[(switch, destino)]
                        )
                    else:
                        siguiente = ruta[posicion + 1]
                        enlace_fallado = frozenset(
                            (switch, siguiente)
                        )

                        desvio = camino_minimo(
                            grafo,
                            switch,
                            siguiente,
                            enlace_fallado
                        )

                        if siguiente_vlan > 4094:
                            raise RuntimeError(
                                "Sin identificadores VLAN libres"
                            )

                        puerto_principal = puertos[
                            (switch, siguiente)
                        ]
                        puerto_respaldo = puertos[
                            (switch, desvio[1])
                        ]

                        grupo = siguiente_grupo
                        vlan = siguiente_vlan

                        siguiente_grupo += 1
                        siguiente_vlan += 1

                        self.grupos[switch].append({
                            "id": grupo,
                            "principal": puerto_principal,
                            "respaldo": puerto_respaldo,
                            "vlan": vlan
                        })

                        accion = ("group", grupo)
                        desvios.append(
                            (siguiente, desvio, vlan)
                        )
                        self.total_grupos += 1

                    salidas_principales[switch] = accion

                    self.agregar_reglas(
                        switch, ip_a, ip_b, accion
                    )

                # Reglas para los paquetes desviados.
                # Cada desvio usa una VLAN exclusiva.
                for reingreso, desvio, vlan in desvios:
                    for posicion in range(1, len(desvio)):
                        switch = desvio[posicion]

                        if switch == reingreso:
                            # Retirar VLAN y continuar la ruta.
                            accion = salidas_principales[
                                reingreso
                            ]
                            quitar_vlan = True
                        else:
                            siguiente = desvio[posicion + 1]
                            accion = (
                                "output",
                                puertos[(switch, siguiente)]
                            )
                            quitar_vlan = False

                        self.agregar_reglas(
                            switch,
                            ip_a,
                            ip_b,
                            accion,
                            vlan=vlan,
                            quitar_vlan=quitar_vlan
                        )

        print("\nRUTAS PRINCIPALES:", flush=True)
        for origen, destino, ruta in self.rutas:
            print(
                f"{origen.upper()} -> {destino.upper()}: "
                + " -> ".join(s.upper() for s in ruta),
                flush=True
            )

        print(
            f"\nComunicaciones: {len(self.rutas)}",
            flush=True
        )
        print(
            f"Grupos Fast Failover calculados: "
            f"{self.total_grupos}",
            flush=True
        )
        print(
            f"Reglas principales y de desvio calculadas: "
            f"{self.total_reglas}",
            flush=True
        )

    def crear_acciones(self, parser, accion):
        tipo, valor = accion

        if tipo == "group":
            return [parser.OFPActionGroup(valor)]

        return [parser.OFPActionOutput(valor)]

    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER
    )
    def instalar(self, evento):
        dp = evento.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        switch = f"s{dp.id}"

        if switch not in self.switches_validos:
            self.logger.error(
                "Switch no declarado: DPID=%s",
                dp.id
            )
            return

        # Retirar las reglas de nuestro controlador anterior.
        dp.send_msg(
            parser.OFPFlowMod(
                datapath=dp,
                cookie=COOKIE,
                cookie_mask=0xFFFFFFFFFFFFFFFF,
                table_id=ofp.OFPTT_ALL,
                command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                match=parser.OFPMatch()
            )
        )

        # En este laboratorio controlamos toda la tabla de grupos.
        dp.send_msg(
            parser.OFPGroupMod(
                dp,
                ofp.OFPGC_DELETE,
                ofp.OFPGT_ALL,
                ofp.OFPG_ALL,
                []
            )
        )

        # Instalar primero todos los grupos Fast Failover.
        for grupo in self.grupos[switch]:
            puerto_a = grupo["principal"]
            puerto_b = grupo["respaldo"]
            vlan = grupo["vlan"]

            principal = parser.OFPBucket(
                watch_port=puerto_a,
                watch_group=ofp.OFPG_ANY,
                actions=[
                    parser.OFPActionOutput(puerto_a)
                ]
            )

            respaldo = parser.OFPBucket(
                watch_port=puerto_b,
                watch_group=ofp.OFPG_ANY,
                actions=[
                    parser.OFPActionPushVlan(0x8100),
                    parser.OFPActionSetField(
                        vlan_vid=ofp.OFPVID_PRESENT | vlan
                    ),
                    parser.OFPActionOutput(puerto_b)
                ]
            )

            dp.send_msg(
                parser.OFPGroupMod(
                    dp,
                    ofp.OFPGC_ADD,
                    ofp.OFPGT_FF,
                    grupo["id"],
                    [principal, respaldo]
                )
            )

        # Instalar las reglas principales y de desvio.
        for regla in self.reglas[switch]:
            campos = {}

            if regla["protocolo"] == "ipv4":
                campos.update({
                    "eth_type": 0x0800,
                    "ipv4_src": regla["ip_a"],
                    "ipv4_dst": regla["ip_b"]
                })
            else:
                campos.update({
                    "eth_type": 0x0806,
                    "arp_spa": regla["ip_a"],
                    "arp_tpa": regla["ip_b"]
                })

            prioridad = 100

            if regla["vlan"] is not None:
                campos["vlan_vid"] = (
                    ofp.OFPVID_PRESENT | regla["vlan"]
                )
                prioridad = 300

            acciones = []

            if regla["quitar_vlan"]:
                acciones.append(
                    parser.OFPActionPopVlan()
                )

            acciones.extend(
                self.crear_acciones(
                    parser,
                    regla["accion"]
                )
            )

            dp.send_msg(
                parser.OFPFlowMod(
                    datapath=dp,
                    cookie=COOKIE,
                    table_id=0,
                    command=ofp.OFPFC_ADD,
                    priority=prioridad,
                    match=parser.OFPMatch(**campos),
                    instructions=[
                        parser.OFPInstructionActions(
                            ofp.OFPIT_APPLY_ACTIONS,
                            acciones
                        )
                    ],
                    idle_timeout=0,
                    hard_timeout=0
                )
            )

        dp.send_msg(parser.OFPBarrierRequest(dp))

        print(
            f"{switch.upper()}: "
            f"{len(self.grupos[switch])} grupos FF, "
            f"{len(self.reglas[switch])} reglas enviadas",
            flush=True
        )
