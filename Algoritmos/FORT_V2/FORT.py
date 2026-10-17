### 01. Importaciones ###
import os
import time

os.environ.setdefault("OSKEN_HUB_TYPE", "eventlet")

from collections import defaultdict, deque
from os_ken import cfg
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls
)

from os_ken.lib import hub
from os_ken.ofproto import ofproto_v1_3, ofproto_protocol
from os_ken.topology.api import get_switch, get_link
from os_ken.topology import event as topo_event
from os_ken.topology import switches as topology_switches

### 02. Variables ###
HOSTS = {
    "h1": ("10.0.0.1", "s1"),
    "h2": ("10.0.0.2", "s2"),
    "h3": ("10.0.0.3", "s5"),
    "h4": ("10.0.0.4", "s7")
}
SWITCHES_ESPERADOS = {
    f"s{i}" for i in range(1, 9)
}

COOKIE_FF = 0xA103
COOKIE_LLDP = 0xA104
PRIMER_GRUPO = 1000
PRIMER_VLAN = 100
TIEMPO_ESTABILIZACION = 5
INTERVALO_SUPERVISION = 2

### 03. Funciones ###
### Buscar caminos mediante algoritmo BFS ###
def caminos_bfs(
        grafo,
        origen,
        destino,
        excluir=None,
        prohibidos=None
):
    probibidos = set(prohibidos or [])
    cola = deque([(origen)])
    visitados = {origen}

    while cola:
        ruta = cola.popleft()
        actual = ruta[-1]
        if actual == destino:
            return ruta
        for vecino in sorted(grafo[actual]):
            enlace = frozenset({actual, vecino})

            if enlace == excluir:
                continue
            if vecino == prohibidos:
                continue
            if vecino == visitados:
                continue

            visitados.add(vecino)
            cola.append(ruta + [vecino])
    return None

### Guardar instalacion de regla ###
def firma_regla(regla):
    ip_a, ip_b = regla["ips"]

    if regla["tipo"] == "ipv4":
        campos = {
            "eth_type": 0x0800,
            "ipv4_src": ip_a,
            "ipv4_dst": ip_b
        }
    else:
        campos = {
            "eth_type": 0x86DD,
            "arp_spa": ip_a,
            "arp_tpa": ip_b
        }
    prioridad = 100

    if regla["vlan"] is not None:
        campos["vlan_vid"] = (0x1000 | regla["vlan"])
        prioridad = 300

    acciones = []

    if regla["pop"]:
        acciones.append(("pop_vlan",))
    acciones.append(regla["accion"])

    return(
        prioridad,
        frozenset(campos.items()),
        tuple(acciones)
    )

### Verificar la regla instalada en el switch ###
def firma_accion(accion):
    clase = type(accion).__name__

    if clase == "OFPActionOutput":
        return ("output", accion.port)

    if clase == "OFPGroupAction":
        return ("group", accion.group_id)
    
    if clase == "OFPActionPushVlan":
        return ("push_vlan", accion.ethertype)

    if clase == "OFPActionPopVlan":
        return ("pop_vlan",)

    if clase == "OFPActionSetField":
        campo = getattr(accion, "field", None)

        if campo is not None:
            nombre = getattr(campo, "field", None)
            valor = getattr(campo, "value", None)

            if nombre == "vlan_vid":
                return ("vlan_vid", int(valor))
            
        if getattr(accion, "key", None) == "vlan_vid":
            return ("vlan_vid", int(accion.value))
        
    return ("desconocida",clase)

### Verificacion real de la regla ###
def firma_flujo_real(flujo):
    campos = frozenset(dict(flujo.match.items()).items())

    acciones = []

    for instruccion in flujo.intstructions:
        for action in getattr(instruccion, "actions", []):
            acciones.append(firma_accion(action))

    return (
        flujo.priority,
        campos,
        tuple(acciones)
    )

### Controlador ##
class FORT(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    ### Iniciar controlador ###
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.datapaths = {}
        self.puertos_of = {}
        self.puertos_xid = {}
        self.inventario = None
        self.firma_topologia = None
        self.desde_estable = 0
        self.plan = None
        self.proteccion_iniciada = False
        self.pendientes = {}
        self.verificados = set()
        self.errores = set()
        self.reconexiones = set()
        self.cambio_reportado = None
        self.escaneado = False
        self.hilo = hub.spawn(self.supervisar_red)

        print("[FORT] Esperando conexiones de switches...", flush=True)

    ### Registrar conexion de switch ###
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)

    def conectar_switch(self,ev):
        dp = ev.msg.datapath
        sw = f"s{dp.id}"

        if sw not in SWITCHES_ESPERADOS:
            print( f"[ERROR] Switch inesperado: {sw}" ) 
            return      
        
        self.datapaths[sw] = dp
        self.verificados.discard(sw)
        self.escaneado = False

        parser = dp.ofproto_parser
        ofp = dp.ofproto

        ### Permitir recepcion de LLDP ###
        dp.send_msg(
            parser.OFPFlowMod(
                datapath=dp,
                cookie=COOKIE_LLDP,
                table_id=0,
                command=ofp.OFPFC_ADD,
                priority=400,
                match=parser.OFPMatch(eth_type=0x88CC),

                instructions=[
                    parser.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS,
                        [
                            parser.OFPActionOutput(
                                ofp.OFPP_CONTROLLER,
                                ofp.OFPCML_NO_BUFFER
                            )
                        ]
                    )
                ]
            )
        )

        solicitud = parser.OFPPortDescStatsRequest(dp,0)
        dp.send_msg(solicitud)

        self.puertos_xid[sw] = solicitud.xid
        self.puertos_of[sw] = {
            "puertos": {},
            "completo": False
        }

        if self.proteccion_iniciada:
           self.reconexiones.add(sw)
           print(f"[TOPO] {sw.upper()} conectado", flush=True)

        ### Registrar puertos OpenFlow ###
        @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, [CONFIG_DISPATCHER, MAIN_DISPATCHER])

        def recibir_puertos(self, ev):
            dp = ev.msg.datapath
            sw = f"s{dp.id}"

            if ev.msg.xid != self.puertos_xid.get(sw):
                return  

            estado = self.puertos_of.get(sw)

            if estado is None:
                return

            for puerto in ev.msg.body:
                estado["puertos"][int(puerto.port_no)] = puerto
            if not (ev.msg.flags & dp.ofproto.OFPMPF_REPLY_MORE):
                estado["completo"] = True 

        ### Descubrir la topologia operativa ###
        def descubrir_topologia(self):
            switches = get_switch(self, None)
            enlaces = get_link(self, None)

            presentes = {
                f"s{obj.dp.id}": obj
                for obj in switches
                if self.datapaths.get(
                    f"s{obj.dp.id}"
                ) is obj.dp
            }

            if set(presentes) != SWITCHES_ESPERADOS:
                return None 

            for sw in presentes:
                
                estado = self.puertos_of.get(sw)

                if not estado or not estado["completo"]:
                    return None

            ### Comprobar el estado de un puerto
            def puerto_operativo(sw, numero):
                puerto = self.puertos_of[sw]["puertos"].get(numero)

                if puerto is None:
                    return False

                caido = bool(
                    puerto.state & ofproto_v1_3.OFPPS_LINK_DOWN or puerto.config & ofproto_v1_3.OFPPC_PORT_DOWN
                )

                return not caido

            ### Registrar enlaces dirigidos detectados ###
            direcciones = {}

            for enlaces in enlaces:
                a = f"s{enlaces.src.dpid}"
                b = f"s{enlaces.dst.dpid}"
                pa = int(enlaces.src.port_no)
                pb = int(enlaces.dst.port_no)

                if a not in presentes or b not in presentes:
                    continue
                if not puerto_operativo(a, pa):
                    continue
                if not puerto_operativo(b, pb):
                    continue

                direcciones[(a, b)] = (pa, pb)

            grafo = {
                sw: set() for sw in presentes
            }

            puertos = {}
            incompletos = []

            for (a, b), (pa, pb) in direcciones.items():
            
                if direcciones.get((b, a)) != (pb, pa):

                    incompletos.append((a, b))
                    continue

                grafo[a].add(b)
                puerto[(a, b)] = pa

            if incompletos:
                return None

            ### Identificar puertos con acceso a host ###
            for sw in presentes:

                activos = set()

                for puerto in self.puertos_of[sw]["puertos"].values():
                    
                    numero = int(puerto.port_no)

                    if numero <= 0 or numero >= 0xFFFFFF00:
                        continue

                    if puerto_operativo(sw, numero):
                        activos.add(numero)
                interswitch = {
                    puerto
                    for (origen, _), puerto
                    in puerto.items()
                    if origen == sw
                }

                candidatos = activos - interswitch

                hosts_sw = [
                    host
                    for host, (_, acceso)
                    in HOSTS.items()
                    if acceso == sw
                ]

                ### Configuracion de 1 Switch - 1 Host ###
                if len(hosts_sw) > 1:
                    return None

                if len(candidatos) != len(hosts_sw):
                    return None

                if hosts_sw:

                    host = hosts_sw[0]

                    puertos[(sw, host)] = next(iter(candidatos))

                if any(not grafo[sw] for sw in grafo):
                    return None

                return{
                    "switches": set(presentes),
                    "grafo": grafo,
                    "puertos": puertos,
                    "enlaces": {
                        frozenset((a,b))
                        for a in grafo
                        for b in grafo[a]
                    }
                }
        ### Preparar proteccion Fast Failover ###
        def preparar_proteccion(self, inventario):
            grafo = inventario["grafo"]
            puertos = inventario["puertos"]
            grupos = defaultdict(list)
            reglas = defaultdict(list)
            rutas = []
            no_protegidos = []
            siguiente_grupo = PRIMER_GRUPO
            siguiente_vlan = PRIMER_VLAN

            def registrar_regla(
                sw, ips, accion, vlan=None, pop=False
            ):

                for tipo in ("ipv4","arp"):
                    reglas[sw].append({
                        "ips": ips,
                        "tipo": tipo,
                        "accion": accion,
                        "vlan": vlan,
                        "pop": pop
                    })
            ### Calcular comunicaciones dirigidas ###
            for origen in sorted(HOSTS):
                for destino in sorted(HOSTS):

                    if origen == destino:
                        continue
                    ip_a, sw_a = HOSTS[origen]
                    ip_b, sw_b = HOSTS[destino]

                    ruta = caminos_bfs(
                        grafo,
                        sw_a,
                        sw_b
                    )

                    if ruta is None:
                        raise RuntimeError(f"Sin ruta: {origen}->{destino}")
                    rutas.append((origen,destino,ruta))

                    salidas = {}
                    desvios = []

                    for posicion, sw in enumerate(ruta):
                        if posicion == len(ruta) - 1:
                            accion = ("output", puertos[(sw, destino)])
                        else:
                            siguiente = ruta[posicion + 1]
                            enlace = frozenset((sw,siguiente))
                            prohibidos = (set(ruta)-{sw, siguiente})
                            desvio = caminos_bfs(
                                grafo,
                                sw,
                                siguiente,
                                excluir=enlace,
                                prohibidos=prohibidos
                            )

                            if desvio is None:
                                no_protegidos.append(
                                    (
                                        origen,
                                        destino,
                                        sw,
                                        siguiente
                                    )
                                )      

                                accion = ("output", puertos[(sw,siguiente)])

                            else:
                                if siguiente_vlan > 4094:
                                    raise RuntimeError("VLAN disponibles agotadas")

                                if siguiente_grupo >= 0xFFFFFF00:
                                    raise RuntimeError("Group ID disponibles agotados")

                                grupos[sw].append(
                                    {
                                        "id": siguiente_grupo,
                                        "principal": puertos[(sw, siguiente)],
                                        "respaldo": puertos[(sw, desvio[1])],
                                        "vlan": siguiente_vlan
                                    }
                                )

                                accion = ("group", siguiente_grupo)

                                desvios.append(
                                    (
                                        siguiente,
                                        desvio,
                                        siguiente_vlan
                                    )
                                )

                                siguiente_grupo += 1
                                siguiente_vlan += 1
                        salidas[sw] = accion

                        registrar_regla(
                            sw,
                            (ip_a, ip_b),
                            accion
                        )

                        for reingreso, desvio, vlan in desvios:
                            for poscion in range(1, len(desvio)):
                                
                                sw = desvio[posicion]

                                if sw == reingreso:

                                    accion = salidas[sw]
                                    quitar_vlan = True

                                else:

                                    siguiente = desvio[posicion + 1]
                                    accion = ("output", puertos[(sw, siguiente)])
                                    quitar_vlan = False

                                registrar_regla(
                                    sw,
                                    (ip_a, ip_b),
                                    accion,
                                    vlan=vlan,
                                    pop=quitar_vlan
                                )

