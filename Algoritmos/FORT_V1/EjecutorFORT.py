
#!/usr/bin/env python3
"""FORT V1 - Ejecutor controlado de Transitions OpenFlow 1.3.

Instala caminos preparados con VLAN, grupos FF de entrada y activacion
IPv4/ARP. Verifica respuestas de barrera y tablas reales; puede revertir.
La ejecucion esta DESACTIVADA salvo FORT_EJECUTAR=1.
Limitacion: no demuestra consistencia por paquete durante microestados
IPv4/ARP; la seguridad plena requiere pruebas dinamicas adicionales.
"""
import ipaddress
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.ofproto import ofproto_v1_3

BASE = Path(__file__).resolve().parents[1]
VALIDACIONES = BASE / 'resultados/etapa06/fort_validaciones'
CAPTURAS = BASE / 'resultados/etapa06/fort_capturas_estado'
SALIDAS = BASE / 'resultados/etapa06/fort_ejecuciones_reales'
COOKIE_BASE = 0xA103
COOKIE_FORT = 0xF047
HABILITADO = os.environ.get('FORT_EJECUTAR', '0') == '1'
MAX_EDAD_S = 40
MODO = os.environ.get('FORT_MODO', 'piloto').lower()
if MODO not in ('piloto', 'persistente'):
    raise ValueError('FORT_MODO debe ser piloto o persistente')
EPS = 1e-6


def leer(ruta):
    return json.loads(ruta.read_text(encoding='utf-8'))


def guardar(ruta, datos):
    ruta.parent.mkdir(parents=True, exist_ok=True)
    tmp = ruta.with_suffix('.tmp')
    tmp.write_text(json.dumps(datos, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    tmp.replace(ruta)


def asegurar(condicion, mensaje):
    if not condicion:
        raise RuntimeError(mensaje)


def campo(par, ips, proto):
    a, b = par
    if proto == 'ipv4':
        return {'eth_type': 0x0800, 'ipv4_src': ips[a], 'ipv4_dst': ips[b]}
    return {'eth_type': 0x0806, 'arp_spa': ips[a], 'arp_tpa': ips[b]}


def lista_acciones(regla):
    acciones = []
    for instruccion in regla.instructions:
        asegurar(hasattr(instruccion, 'actions'), 'Instruccion OpenFlow no soportada')
        acciones.extend(instruccion.actions)
    return acciones


def salida_unica(lista):
    salidas = [int(a.port) for a in lista if type(a).__name__ == 'OFPActionOutput']
    asegurar(len(salidas) == 1, 'Se esperaba una salida fisica unica')
    return salidas[0]


def buscar_regla(tablas, sw, match, prioridad, cookie):
    reglas = [r for r in tablas.get(sw, [])
              if int(r.table_id) == 0 and int(r.priority) == prioridad
              and int(r.cookie) == cookie and dict(r.match.items()) == match]
    asegurar(len(reglas) == 1, f'Regla no unica en {sw}: {match}')
    return reglas[0]


def puertos_de_inventario(inventario):
    mapa = {}
    for e in inventario:
        for a, b, n in ((e['nodo_a'], e['nodo_b'], e['puerto_a']),
                        (e['nodo_b'], e['nodo_a'], e['puerto_b'])):
            asegurar((a, b) not in mapa, 'Puerto duplicado en inventario')
            mapa[(a, b)] = int(n)
    return mapa


class EjecutorFORT(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        escenario = leer(BASE / 'config/escenario.json')
        self.switches = set(escenario['switches'])
        self.enlaces = {frozenset(e) for e in escenario['enlaces']}
        self.ips = {h['nombre']: str(ipaddress.ip_interface(h['ip']).ip)
                    for h in escenario['hosts']}
        self.puertos = puertos_de_inventario(
            leer(BASE / 'resultados/etapa01/puertos_detectados.json'))
        self.datapaths = {}
        self.pendientes = {}
        self.error_actual = None
        self.interrumpido = None
        self.ocupado = False
        self.activa = None
        self.limpieza_inicial = False
        self.vistos = {p.name for p in VALIDACIONES.glob('FORT_Preflight_*.json')}
        hub.spawn(self.vigilar)
        print('FORT EJECUTOR: ' + (f'HABILITADO ({MODO})' if HABILITADO else 'MODO SEGURO (sin cambios)'), flush=True)

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def conectado(self, ev):
        if ev.datapath is not None:
            self.datapaths[f's{ev.datapath.id}'] = ev.datapath

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def desconectado(self, ev):
        if ev.datapath is not None:
            self.datapaths.pop(f's{ev.datapath.id}', None)
            if self.ocupado or self.activa:
                self.interrumpido = 'Switch desconectado durante FORT'

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def cambio_puerto(self, ev):
        if self.ocupado or self.activa:
            self.interrumpido = 'La topologia cambio durante FORT'

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def error_openflow(self, ev):
        if self.ocupado or self.activa:
            m = ev.msg
            self.error_actual = f'OpenFlow error dpid={m.datapath.id} tipo={m.type} codigo={m.code}'
            print('FORT EJECUTOR ERROR:', self.error_actual, flush=True)

    def recibir(self, msg, clase):
        sw = f's{msg.datapath.id}'
        clave = (sw, int(msg.xid), clase)
        pendiente = self.pendientes.get(clave)
        if pendiente is None:
            return
        if clase != 'barrier':
            pendiente['body'].extend(msg.body)
            if int(msg.flags) & msg.datapath.ofproto.OFPMPF_REPLY_MORE:
                return
        pendiente['done'] = True

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrera(self, ev):
        self.recibir(ev.msg, 'barrier')

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def reglas(self, ev):
        self.recibir(ev.msg, 'flows')

    @set_ev_cls(ofp_event.EventOFPGroupDescStatsReply, MAIN_DISPATCHER)
    def grupos(self, ev):
        self.recibir(ev.msg, 'groups')

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def puertos_estado(self, ev):
        self.recibir(ev.msg, 'ports')

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def puertos_contadores(self, ev):
        self.recibir(ev.msg, 'counters')

    def enviar_consulta(self, sw, clase):
        dp = self.datapaths[sw]
        p = dp.ofproto_parser
        if clase == 'flows':
            msg = p.OFPFlowStatsRequest(dp)
        elif clase == 'groups':
            msg = p.OFPGroupDescStatsRequest(dp, 0)
        elif clase == 'ports':
            msg = p.OFPPortDescStatsRequest(dp, 0)
        elif clase == 'counters':
            msg = p.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY)
        elif clase == 'barrier':
            msg = p.OFPBarrierRequest(dp)
        else:
            raise RuntimeError('Solicitud desconocida')
        dp.send_msg(msg)
        clave = (sw, int(msg.xid), clase)
        self.pendientes[clave] = {'done': False, 'body': []}
        return clave

    def esperar(self, claves, plazo_s=5.0, controlar_topologia=True, controlar_errores=True):
        limite = time.monotonic() + plazo_s
        while time.monotonic() < limite:
            if controlar_errores:
                asegurar(self.error_actual is None, self.error_actual or 'Error OpenFlow')
            if controlar_topologia:
                asegurar(self.interrumpido is None, self.interrumpido or 'Topologia modificada')
            if all(self.pendientes[k]['done'] for k in claves):
                return {k: self.pendientes.pop(k)['body'] for k in claves}
            hub.sleep(0.04)
        faltan = [str(k) for k in claves if not self.pendientes[k]['done']]
        for k in claves:
            self.pendientes.pop(k, None)
        raise RuntimeError('Timeout OpenFlow esperando ' + ', '.join(faltan))

    def consultar(self, clases, switches=None, controlar_topologia=True):
        claves = [self.enviar_consulta(sw, clase)
                  for sw in sorted(switches or self.switches)
                  for clase in clases]
        datos = self.esperar(claves, 6.0, controlar_topologia)
        respuesta = {tipo: {} for tipo in clases}
        for (sw, _xid, clase), cuerpo in datos.items():
            respuesta[clase][sw] = cuerpo
        return respuesta

    def sincronizar(self, afectados, controlar_topologia=True, controlar_errores=True):
        claves = [self.enviar_consulta(sw, 'barrier') for sw in sorted(afectados)]
        self.esperar(claves, 5.0, controlar_topologia, controlar_errores)

    def estado_puertos(self, datos):
        vivos = {}
        for sw, lista in datos['ports'].items():
            ofp = self.datapaths[sw].ofproto
            for port in lista:
                vivos[(sw, int(port.port_no))] = not (
                    int(port.config) & ofp.OFPPC_PORT_DOWN
                    or int(port.state) & (ofp.OFPPS_LINK_DOWN | ofp.OFPPS_BLOCKED))
        return vivos

    def validar_topologia(self, vivos, fallo):
        asegurar(set(self.datapaths) == self.switches, 'Switches no conectados')
        for enlace in self.enlaces:
            a, b = sorted(enlace)
            real = (vivos.get((a, self.puertos[(a, b)])) is True
                    and vivos.get((b, self.puertos[(b, a)])) is True)
            asegurar(real == (enlace != fallo), f'Estado inesperado en {a}-{b}')

    def verificar_original(self, snapshot, operaciones):
        tablas = snapshot['flows']
        grupos = {sw: {int(g.group_id): g for g in lista}
                  for sw, lista in snapshot['groups'].items()}
        vivos = self.estado_puertos(snapshot)
        paquetes = []
        usados_vlans = set()
        usados_grupos = {int(gid) for gr in grupos.values() for gid in gr}
        for lista in snapshot['flows'].values():
            for regla in lista:
                v = dict(regla.match.items()).get('vlan_vid')
                if isinstance(v, int):
                    usados_vlans.add(v & 0xFFF)
        for gr in grupos.values():
            for grupo in gr.values():
                for b in grupo.buckets:
                    for a in b.actions:
                        if type(a).__name__ == 'OFPActionSetField' and getattr(a, 'key', '') == 'vlan_vid':
                            usados_vlans.add(int(a.value) & 0xFFF)

        reservas_v = set()
        reservas_g = set()
        for operacion in operaciones:
            a, b = operacion['comunicacion'].split('->')
            par = (a, b)
            fs, ruta = operacion['ruta_fs'], operacion['ruta_target']
            sw = operacion['switch_ingreso']
            vlan, gid = int(operacion['vlan_nueva']), int(operacion['group_id_nuevo'])
            asegurar(fs[0] == a and fs[-1] == b and ruta[0] == a and ruta[-1] == b,
                    'Extremos de comunicacion invalidos')
            asegurar(fs[1] == ruta[1] == sw and fs[2] != ruta[2], 'Primer salto no soportado')
            asegurar(len(ruta) == len(set(ruta)), 'Target con bucles')
            asegurar(100 <= vlan <= 4094 and vlan not in usados_vlans and vlan not in reservas_v,
                    'VLAN ocupada o invalida')
            asegurar(40000 <= gid < 65000 and gid not in usados_grupos and gid not in reservas_g,
                    'Group ID ocupado o invalido')
            reservas_v.add(vlan)
            reservas_g.add(gid)
            for x, y in zip(ruta, ruta[1:]):
                asegurar((x, y) in self.puertos, f'Arco sin puerto {x}-{y}')
                if x.startswith('s'):
                    asegurar(vivos.get((x, self.puertos[(x, y)])) is True, f'Puerto caido {x}->{y}')
            asegurar(self.puertos[(sw, fs[2])] == int(operacion['puerto_fs']), 'Puerto FS inconsistente')
            asegurar(self.puertos[(sw, ruta[2])] == int(operacion['puerto_target']), 'Puerto Target inconsistente')
            respaldo = None
            originales = {}
            for proto in ('ipv4', 'arp'):
                patron = campo(par, self.ips, proto)
                regla = buscar_regla(tablas, sw, patron, 100, COOKIE_BASE)
                accion = lista_acciones(regla)
                asegurar(len(accion) == 1, 'Accion de ingreso no soportada')
                asegurar([str(x) for x in accion] == operacion['reglas_actuales_ingreso'][proto]['acciones_actuales'],
                        'Accion base cambio despues del preflight')
                tipo = type(accion[0]).__name__
                if tipo == 'OFPActionGroup':
                    grupo = grupos[sw].get(int(accion[0].group_id))
                    asegurar(grupo is not None and int(grupo.type) == 3, 'Grupo FF original ausente')
                    posibles = [bb for bb in grupo.buckets if vivos.get((sw, int(bb.watch_port))) is True]
                    asegurar(bool(posibles), 'FF sin puerto operativo')
                    actual = list(posibles[0].actions)
                elif tipo == 'OFPActionOutput':
                    actual = list(accion)
                else:
                    raise RuntimeError('Accion original no compatible')
                asegurar(salida_unica(actual) == int(operacion['puerto_fs']),
                        'Ruta FS cambio desde el preflight')
                asegurar([str(x) for x in actual] == operacion['reglas_actuales_ingreso'][proto]['acciones_respaldo'],
                        'Respaldo FF modificado desde el preflight')
                if respaldo is None:
                    respaldo = actual
                else:
                    asegurar([str(x) for x in respaldo] == [str(x) for x in actual],
                            'IP/ARP no comparten el mismo respaldo')
                originales[proto] = list(accion)

            # Preparar exclusivamente los matches VLAN anunciados por preflight.
            preparar = []
            for op in operacion['flowmods_preparacion']:
                nodo = op['switch']
                proto = op['protocolo']
                asegurar(proto in ('ipv4', 'arp'), 'Protocolo invalido')
                patron = {**campo(par, self.ips, proto), 'vlan_vid': 0x1000 | vlan}
                asegurar(patron == op['match_exacto'] and op['prioridad'] == 300,
                        'Match de preparacion inesperado')
                asegurar(not any(int(r.table_id) == 0 and dict(r.match.items()) == patron
                                for r in tablas.get(nodo, [])), 'Match VLAN en uso')
                funcion = op['funcion']
                if funcion == 'REINCORPORACION_FS':
                    base = buscar_regla(tablas, nodo, campo(par, self.ips, proto), 100, COOKIE_BASE)
                    objetivo = ['pop_vlan'] + [str(x) for x in lista_acciones(base)]
                    acciones_nuevas = [self.datapaths[nodo].ofproto_parser.OFPActionPopVlan()] + lista_acciones(base)
                else:
                    puertos = [int(s.split(':')[1]) for s in op['acciones_propuestas']
                               if isinstance(s, str) and s.startswith('output:')]
                    asegurar(len(puertos) == 1, 'Output de VLAN no unico')
                    destino = self.puertos.get((nodo, ruta[ruta.index(nodo) + 1]))
                    asegurar(destino == puertos[0], 'Salida propuesta no coincide con Target')
                    if funcion == 'ENTREGA_HOST':
                        objetivo = ['pop_vlan', f'output:{destino}']
                        acciones_nuevas = [self.datapaths[nodo].ofproto_parser.OFPActionPopVlan(),
                                           self.datapaths[nodo].ofproto_parser.OFPActionOutput(destino)]
                    else:
                        asegurar(funcion == 'TRANSITO_VLAN', 'Funcion VLAN desconocida')
                        objetivo = [f'output:{destino}']
                        acciones_nuevas = [self.datapaths[nodo].ofproto_parser.OFPActionOutput(destino)]
                asegurar(objetivo == op['acciones_propuestas'], 'Preflight no coincide con acciones vivas')
                preparar.append((nodo, patron, acciones_nuevas))
            asegurar(len(preparar) >= 2 and len(preparar) % 2 == 0,
                    'Tramo preparado incompleto')
            paquetes.append({'par': par, 'fs': fs, 'ruta': ruta, 'ingreso': sw,
                             'vlan': vlan, 'gid': gid, 'originales': originales,
                             'fallback': respaldo, 'preparar': preparar,
                             'puerto_target': int(operacion['puerto_target']),
                             'puerto_fs': int(operacion['puerto_fs'])})
        asegurar(paquetes, 'Preflight sin operaciones')
        return paquetes

    def flowmod(self, sw, match, acciones, cookie, prioridad, comando):
        dp = self.datapaths[sw]
        ofp, parser = dp.ofproto, dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, cookie=cookie, table_id=0, command=comando,
            priority=prioridad, match=parser.OFPMatch(**match),
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
            instructions=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, acciones)],
            idle_timeout=0, hard_timeout=0))

    def group_add(self, paquete):
        sw = paquete['ingreso']
        dp = self.datapaths[sw]
        ofp, parser = dp.ofproto, dp.ofproto_parser
        port = paquete['puerto_target']
        vlan = paquete['vlan']
        buckets = [
            parser.OFPBucket(watch_port=port, watch_group=ofp.OFPG_ANY,
                             actions=[parser.OFPActionPushVlan(0x8100),
                                      parser.OFPActionSetField(vlan_vid=ofp.OFPVID_PRESENT | vlan),
                                      parser.OFPActionOutput(port)]),
            parser.OFPBucket(watch_port=paquete['puerto_fs'], watch_group=ofp.OFPG_ANY,
                             actions=paquete['fallback'])]
        dp.send_msg(parser.OFPGroupMod(dp, ofp.OFPGC_ADD, ofp.OFPGT_FF, paquete['gid'], buckets))

    def group_delete(self, paquete):
        sw = paquete['ingreso']
        dp = self.datapaths[sw]
        dp.send_msg(dp.ofproto_parser.OFPGroupMod(
            dp, dp.ofproto.OFPGC_DELETE, dp.ofproto.OFPGT_ALL,
            paquete['gid'], []))

    def verificar_tablas(self, paquetes, verificar_ingresos, comprobar_grupos=True, controlar_topologia=True):
        datos = self.consultar(('flows', 'groups', 'ports'), controlar_topologia=controlar_topologia)
        vivos = self.estado_puertos(datos)
        for paquete in paquetes:
            vlan = paquete['vlan']
            for sw, patron, acciones in paquete['preparar']:
                regla = buscar_regla(datos['flows'], sw, patron, 300, COOKIE_FORT)
                asegurar([str(a) for a in lista_acciones(regla)] == [str(a) for a in acciones],
                        f'Regla VLAN diferente a Target en {sw}')
            if comprobar_grupos:
                grupos = {int(g.group_id): g for g in datos['groups'][paquete['ingreso']]}
                grupo = grupos.get(paquete['gid'])
                asegurar(grupo is not None and int(grupo.type) == 3 and len(grupo.buckets) == 2,
                        'Grupo nuevo FF no encontrado')
                asegurar(int(grupo.buckets[0].watch_port) == paquete['puerto_target']
                        and int(grupo.buckets[1].watch_port) == paquete['puerto_fs'],
                        'Buckets de grupo FORT inesperados')
                prim = grupo.buckets[0].actions
                asegurar(len(prim) == 3
                        and type(prim[0]).__name__ == 'OFPActionPushVlan'
                        and type(prim[1]).__name__ == 'OFPActionSetField'
                        and getattr(prim[1], 'key', None) == 'vlan_vid'
                        and int(prim[1].value) == 0x1000 | paquete['vlan']
                        and salida_unica(prim) == paquete['puerto_target'],
                        'Acciones del bucket principal distintas del Target')
                asegurar([str(x) for x in grupo.buckets[1].actions]
                        == [str(x) for x in paquete['fallback']],
                        'Bucket de respaldo FF alterado')
            for proto in ('ipv4', 'arp'):
                match = campo(paquete['par'], self.ips, proto)
                regla = buscar_regla(datos['flows'], paquete['ingreso'], match, 100, COOKIE_BASE)
                a = lista_acciones(regla)
                esperado = ([f'OFPActionGroup(group_id={paquete["gid"]},len=8,type=22)']
                            if verificar_ingresos else [str(x) for x in paquete['originales'][proto]])
                if verificar_ingresos:
                    asegurar(len(a) == 1 and type(a[0]).__name__ == 'OFPActionGroup'
                            and int(a[0].group_id) == paquete['gid'], 'Ingreso no activado')
                else:
                    asegurar([str(x) for x in a] == esperado, 'Ingreso cambio durante preparacion')
            asegurar(vivos.get((paquete['ingreso'], paquete['puerto_target'])) is True,
                    'Puerto nuevo ya no operativo')
        return datos

    def medir_mlu(self, fallo, segundos=5):
        primera = self.consultar(('counters',), controlar_topologia=True)['counters']
        t0 = time.monotonic()
        hub.sleep(segundos)
        segunda = self.consultar(('counters',), controlar_topologia=True)['counters']
        t1 = time.monotonic()
        capacidades = leer(BASE / 'config/escenario.json')['capacidad_enlace_mbps'] * 1e6
        mlu, detalles = 0.0, []
        for enlace in self.enlaces:
            if enlace == fallo:
                continue
            a, b = tuple(enlace)
            for sw, vecino in ((a, b), (b, a)):
                puerto = self.puertos[(sw, vecino)]
                ant = {int(r.port_no): int(r.tx_bytes) for r in primera[sw]}
                nue = {int(r.port_no): int(r.tx_bytes) for r in segunda[sw]}
                asegurar(puerto in ant and puerto in nue, 'Contadores incompletos')
                delta = nue[puerto] - ant[puerto]
                asegurar(delta >= 0, 'Contador reiniciado')
                pct = 100 * (delta * 8 / (t1 - t0)) / capacidades
                mlu = max(mlu, pct)
                detalles.append({'origen': sw, 'destino': vecino, 'utilizacion_pct': round(pct, 6)})
        return round(mlu, 6), detalles

    def rollback(self, paquetes, agregadas, grupos_creados, cambiadas):
        errores = []
        # Primero recuperar los ingresos; conservar la infraestructura de desvio
        # mientras se completan y verifican las barreras.
        switches = set()
        for paq in reversed(cambiadas):
            for proto in ('ipv4', 'arp'):
                try:
                    dp = self.datapaths[paq['ingreso']]
                    self.flowmod(paq['ingreso'], campo(paq['par'], self.ips, proto),
                                 paq['originales'][proto], COOKIE_BASE, 100,
                                 dp.ofproto.OFPFC_MODIFY_STRICT)
                    switches.add(paq['ingreso'])
                except Exception as exc:
                    errores.append('Restore ingress: ' + str(exc))
        if switches:
            try:
                self.sincronizar(switches, controlar_topologia=False, controlar_errores=False)
            except Exception as exc:
                errores.append('Barrier restauracion: ' + str(exc))
        if errores:
            return errores  # NO eliminar infraestructura si rollback de ingress fallo.
        switches.clear()
        for paq in reversed(grupos_creados):
            try:
                self.group_delete(paq)
                switches.add(paq['ingreso'])
            except Exception as exc:
                errores.append('Delete group: ' + str(exc))
        for sw, match in reversed(agregadas):
            try:
                dp = self.datapaths[sw]
                p = dp.ofproto_parser
                dp.send_msg(p.OFPFlowMod(
                    datapath=dp, cookie=COOKIE_FORT, cookie_mask=0xFFFFFFFFFFFFFFFF,
                    table_id=0, command=dp.ofproto.OFPFC_DELETE_STRICT,
                    out_port=dp.ofproto.OFPP_ANY, out_group=dp.ofproto.OFPG_ANY,
                    priority=300, match=p.OFPMatch(**match)))
                switches.add(sw)
            except Exception as exc:
                errores.append('Delete flow: ' + str(exc))
        if switches:
            try:
                self.sincronizar(switches, controlar_topologia=False, controlar_errores=False)
            except Exception as exc:
                errores.append('Barrier limpieza: ' + str(exc))
        return errores

    def ejecutar(self, preflight, estado, salida):
        informe = {'tipo': 'FORT_EJECUCION_V1', 'inicio_utc': datetime.now(timezone.utc).isoformat(),
                   'captura_origen_utc': estado['fecha_utc'], 'fallo': estado['fallo'],
                   'ejecucion_habilitada': HABILITADO, 'estado': 'INICIADO',
                   'etapas': [], 'mlu_ff_observada_pct': estado['rs']['maxima_utilizacion_observada_pct'],
                   'mlu_post_fort_observada_pct': None, 'mejora_observada_pp': None}
        agregadas, creados, cambiadas, paquetes = [], [], [], []
        self.ocupado = True
        self.error_actual = None
        self.interrumpido = None
        try:
            asegurar(HABILITADO, 'Ejecucion desactivada: definir FORT_EJECUTAR=1')
            asegurar(preflight.get('tipo') == 'FORT_PREFLIGHT_OPENFLOW'
                    and preflight.get('estado') == 'VALIDACION_ESTRUCTURAL_OPENFLOW_REAL',
                    'Preflight no confirmado')
            preferida = preflight.get('pareja_preferida_preflight')
            asegurar(preferida is not None, 'No hay pareja compatible')
            salida_target = next((t for t in preflight['targets']
                                  if t['target_id'] == preferida['target_id']), None)
            asegurar(salida_target and salida_target['estado'].startswith('PREPARACION_')
                    and not salida_target['bloqueos'], 'Target bloqueado')
            asegurar(0 < len(salida_target['comunicaciones']) <= 12,
                    'Cantidad de comunicaciones a modificar invalida')
            asegurar(set(self.datapaths) == self.switches, 'Controlador incompleto')
            # Garantizar que no se instalen planes viejos o reemplazados.
            edad = time.time() - datetime.fromisoformat(
                preflight['fecha_utc'].replace('Z', '+00:00')).timestamp()
            asegurar(0 <= edad <= MAX_EDAD_S, f'Preflight obsoleto ({edad:.1f}s)')
            asegurar(preflight['captura_origen_utc'] == estado['fecha_utc'], 'Run ID diferente')
            fallo = frozenset(estado['fallo'].split('-'))
            asegurar(len(fallo) == 2 and fallo in self.enlaces, 'Fallo invalido')
            captura = self.consultar(('flows', 'groups', 'ports'))
            self.validar_topologia(self.estado_puertos(captura), fallo)
            paquetes = self.verificar_original(captura, salida_target['comunicaciones'])
            orden_transition = str(preferida['transition_id'])
            asegurar(orden_transition.startswith(preferida['target_id'] + '_TR'),
                    'La Transition no pertenece al Target')
            if orden_transition.endswith('_DESC'):
                paquetes.sort(key=lambda p: p['par'], reverse=True)
            elif orden_transition.endswith('_ASC') or orden_transition.endswith('_PREPARAR_TODOS'):
                paquetes.sort(key=lambda p: p['par'])
            else:
                raise RuntimeError('Orden de Transition desconocido')
            informe['transition_id'] = orden_transition
            informe['orden_aplicado'] = [f'{p["par"][0]}->{p["par"][1]}' for p in paquetes]
            informe['etapas'].append('PRECONDICIONES_VERIFICADAS')
            print('FORT EJECUTOR: precondiciones OK; preparando', flush=True)

            # FASE 1: preparar todas las reglas VLAN sin afectar trafico base.
            switches = set()
            for paq in paquetes:
                for sw, patron, acciones in paq['preparar']:
                    dp = self.datapaths[sw]
                    self.flowmod(sw, patron, acciones, COOKIE_FORT, 300, dp.ofproto.OFPFC_ADD)
                    agregadas.append((sw, patron))
                    switches.add(sw)
            self.sincronizar(switches)
            self.verificar_tablas(paquetes, verificar_ingresos=False, comprobar_grupos=False)
            informe['etapas'].append('REGLAS_PREPARADAS_VERIFICADAS')
            print('FORT EJECUTOR: reglas VLAN verificadas', flush=True)

            # FASE 2: grupos FF nuevos conservando rutas originales como backup.
            switches = set()
            for paq in paquetes:
                self.group_add(paq)
                creados.append(paq)
                switches.add(paq['ingreso'])
            self.sincronizar(switches)
            self.verificar_tablas(paquetes, verificar_ingresos=False, comprobar_grupos=True)
            informe['etapas'].append('GRUPOS_FF_PREPARADOS_VERIFICADOS')
            print('FORT EJECUTOR: grupos FF verificados', flush=True)

            # FASE 3: cambiar los ingresos uno por uno; conservar cookie BASE
            # para que el controlador inicial pueda restablecer el estado.
            for paq in paquetes:
                cambiadas.append(paq)  # Incluir en rollback incluso si falla el primer FlowMod.
                dp = self.datapaths[paq['ingreso']]
                for proto in ('ipv4', 'arp'):
                    self.flowmod(paq['ingreso'], campo(paq['par'], self.ips, proto),
                                 [dp.ofproto_parser.OFPActionGroup(paq['gid'])],
                                 COOKIE_BASE, 100, dp.ofproto.OFPFC_MODIFY_STRICT)
                self.sincronizar({paq['ingreso']})
            self.verificar_tablas(paquetes, verificar_ingresos=True)
            informe['etapas'].append('RUTAS_INGRESO_ACTIVADAS_VERIFICADAS')
            print('FORT EJECUTOR: rutas Target activadas y verificadas', flush=True)

            mlu, arcos = self.medir_mlu(fallo, 5)
            informe['mlu_post_fort_observada_pct'] = mlu
            informe['direccion_mlu_post'] = arcos
            informe['mejora_observada_pp'] = round(
                float(informe['mlu_ff_observada_pct']) - mlu, 6)
            informe['comparabilidad'] = ('MEDICION_PILOTO_NO_CONTROLADA: '
                'el trafico ofrecido puede variar entre ambas ventanas')
            informe['estado'] = 'APLICADO_VERIFICADO_EN_CONTROLADOR'
            informe['operaciones'] = {'flowmods_add': len(agregadas),
                                     'groupmods_add': len(creados),
                                     'comunicaciones_activadas': len(cambiadas)}
            if MODO == 'piloto':
                errores = self.rollback(paquetes, agregadas, creados, cambiadas)
                informe['rollback_piloto'] = ('VERIFICADO_POR_BARRERAS' if not errores
                                             else 'INCOMPLETO')
                informe['errores_rollback_piloto'] = errores
                if errores:
                    informe['estado'] = 'APLICADO_PERO_REVERSION_INCOMPLETA'
                else:
                    informe['estado'] = 'PILOTO_APLICADO_Y_REVERTIDO'
                print('FORT EJECUTOR: modo piloto; red restaurada a FF' if not errores
                      else 'FORT EJECUTOR: rollback piloto INCOMPLETO', flush=True)
            else:
                self.activa = {'paquetes': paquetes, 'agregadas': agregadas,
                              'creados': creados, 'cambiadas': cambiadas,
                              'fallo': fallo, 'salida': salida}
            print(f'FORT EJECUTOR: MLU post-FORT {mlu}% | MLU post-FF '
                  f'{informe["mlu_ff_observada_pct"]}% '
                  '(comparacion exploratoria)', flush=True)
        except Exception as exc:
            informe['estado'] = 'FALLO_O_BLOQUEO'
            informe['error'] = str(exc)
            print('FORT EJECUTOR: BLOQUEADO/FALLO:', exc, flush=True)
            if agregadas or creados or cambiadas:
                errores = self.rollback(paquetes, agregadas, creados, cambiadas)
                informe['errores_rollback'] = errores
                informe['rollback'] = ('PARCIAL_REQUIERE_INTERVENCION' if errores
                                       else 'SOLICITADO_Y_BARRERAS_CONFIRMADAS')
                print('FORT EJECUTOR: rollback:', informe['rollback'], flush=True)
        finally:
            informe['fin_utc'] = datetime.now(timezone.utc).isoformat()
            guardar(salida, informe)
            self.ocupado = False
            self.pendientes.clear()
            print('FORT EJECUTOR: resultado:', salida, flush=True)

    def limpiar_inicio(self):
        """Quita solo artefactos con identificadores propios de FORT.

        RutasPrincipales reinstala grupos FF y flujos base al reconectar.
        Esto retira restos de reglas VLAN de un proceso FORT interrumpido.
        """
        self.ocupado = True
        try:
            datos = self.consultar(('groups',), controlar_topologia=False)
            afectados = set()
            for sw in sorted(self.switches):
                dp = self.datapaths[sw]
                ofp, p = dp.ofproto, dp.ofproto_parser
                dp.send_msg(p.OFPFlowMod(
                    datapath=dp, cookie=COOKIE_FORT,
                    cookie_mask=0xFFFFFFFFFFFFFFFF,
                    table_id=ofp.OFPTT_ALL, command=ofp.OFPFC_DELETE,
                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                    match=p.OFPMatch()))
                afectados.add(sw)
                for g in datos['groups'][sw]:
                    gid = int(g.group_id)
                    if 40000 <= gid < 65000:
                        dp.send_msg(p.OFPGroupMod(
                            dp, ofp.OFPGC_DELETE, ofp.OFPGT_ALL, gid, []))
            self.sincronizar(afectados, controlar_topologia=False)
            self.limpieza_inicial = True
            print('FORT EJECUTOR: limpieza de artefactos propios verificada', flush=True)
        except Exception:
            self.logger.exception('FORT: fallo limpieza inicial')
            # Impedir operaciones si hay restos en estado incierto.
            self.limpieza_inicial = False
        finally:
            self.ocupado = False
            self.pendientes.clear()

    def gestionar_recuperacion(self):
        """Si vuelve el enlace originalmente fallado, restaurar FF base."""
        actual = self.activa
        if actual is None:
            return
        self.ocupado = True
        try:
            datos = self.consultar(('ports',), controlar_topologia=False)
            activos = self.estado_puertos(datos)
            a, b = sorted(actual['fallo'])
            recuperado = (activos.get((a, self.puertos[(a, b)])) is True
                          and activos.get((b, self.puertos[(b, a)])) is True)
            if not recuperado:
                print('FORT EJECUTOR: evento de topologia distinto de recuperacion. '
                      'Conservar estado y revisar (fallos multiples no soportados).', flush=True)
                return
            # Restaurar solo al estado sin fallos, no si aparecio otra averia.
            self.validar_topologia(activos, frozenset())
            print(f'FORT EJECUTOR: enlace {a}-{b} recuperado; restaurando FF', flush=True)
            errores = self.rollback(actual['paquetes'], actual['agregadas'],
                                    actual['creados'], actual['cambiadas'])
            if errores:
                print('FORT EJECUTOR: rollback de recuperacion INCOMPLETO', errores, flush=True)
                return
            # Comprobar restauracion de reglas base en el ingreso.
            estado = self.consultar(('flows',), controlar_topologia=False)['flows']
            for paq in actual['paquetes']:
                for proto in ('ipv4', 'arp'):
                    r = buscar_regla(estado, paq['ingreso'],
                                     campo(paq['par'], self.ips, proto), 100, COOKIE_BASE)
                    asegurar([str(x) for x in lista_acciones(r)]
                            == [str(x) for x in paq['originales'][proto]],
                            'Ingreso no recuperado')
            reporte = leer(actual['salida'])
            reporte['restauracion_por_recuperacion_utc'] = datetime.now(timezone.utc).isoformat()
            reporte['restauracion_por_recuperacion'] = 'VERIFICADA'
            reporte['estado'] = 'REOPTIMIZACION_REVERTIDA_TRAS_RECUPERACION'
            guardar(actual['salida'], reporte)
            self.activa = None
            print('FORT EJECUTOR: FF restaurado; listo para otro fallo', flush=True)
        except Exception as exc:
            self.logger.exception('FORT: error al restaurar tras recuperacion')
            print('FORT EJECUTOR: revisar manualmente; error:', exc, flush=True)
        finally:
            self.interrumpido = None
            self.ocupado = False
            self.pendientes.clear()

    def vigilar(self):
        while True:
            try:
                if HABILITADO and not self.limpieza_inicial and not self.ocupado \
                        and set(self.datapaths) == self.switches:
                    self.limpiar_inicio()
                if self.activa and not self.ocupado and self.interrumpido:
                    self.gestionar_recuperacion()
                if HABILITADO and self.limpieza_inicial and not self.ocupado and not self.activa \
                        and set(self.datapaths) == self.switches:
                    for p in sorted(VALIDACIONES.glob('FORT_Preflight_*.json')):
                        if p.name in self.vistos:
                            continue
                        try:
                            pre = leer(p)
                        except (OSError, ValueError):
                            continue
                        self.vistos.add(p.name)
                        captura = CAPTURAS / p.name.replace('FORT_Preflight_', 'FORT_Estado_')
                        if not captura.is_file():
                            continue
                        try:
                            estado = leer(captura)
                            salida = SALIDAS / p.name.replace('FORT_Preflight_', 'FORT_Resultado_')
                            hub.spawn(self.ejecutar, pre, estado, salida)
                        except Exception:
                            self.logger.exception('No pudo iniciar ejecucion %s', p)
                        break
            except Exception:
                self.logger.exception('Error vigilando ejecuciones FORT')
            hub.sleep(0.5)
