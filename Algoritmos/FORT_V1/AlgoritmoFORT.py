
#!/usr/bin/env python3
"""FORT: Target-Transition + estado post-FF dinamico.

Captura FS, PS, RS y demandas IPv4 mediante OpenFlow 1.3.

Los buckets y las rutas se infieren a partir de las reglas.
La utilizacion se mide mediante contadores de puertos.
No ejecuta Transitions ni modifica reglas de OVS.
"""

import argparse
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
import uuid

from datetime import datetime, timezone
from pathlib import Path

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    MAIN_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls,
)
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub


BASE = Path(__file__).resolve().parents[1]
RESULTADOS = BASE / "resultados"

INVENTARIO = (
    RESULTADOS / "etapa01/puertos_detectados.json"
)

EVENTOS = (
    RESULTADOS / "etapa06/FORT_EventosEnlace.jsonl"
)

DESTINO = (
    RESULTADOS / "etapa06/fort_ejecuciones"
)

VENTANA_MEDICION_S = 5.0
TIMEOUT_CAPTURA_S = 25.0


FASES = [
    ("E03", "ActualizarTopologia.py", []),
    ("E03", "CalcularCaminos.py", []),
    ("E03", "GenerarTargets.py", ["--max-targets", "40"]),
    ("E03", "EstimarCargaTargets.py", []),
    ("E03", "FiltrarTargets.py", []),

    ("E04", "CompararFSvsTargets.py", []),
    ("E04", "GenerarOperacionesOpenFlow.py", []),
    ("E04", "OrdenarOperacionesOpenFlow.py", []),
    ("E04", "GenerarTransitions.py", ["--max-transitions", "3"]),
    ("E04", "ConstruirEstadosIntermedios.py", []),

    ("E05", "EvaluarFactibilidad.py", []),
    ("E05", "CalcularFinalMLU.py", []),
    ("E05", "CalcularPeakMLU.py", []),
    ("E05", "CalcularCostoReconfiguracion.py", []),
    ("E05", "SeleccionarPareja.py", []),
]


def cargar(ruta):
    if not ruta.is_file():
        raise RuntimeError(
            f"Archivo inexistente: {ruta}"
        )

    return json.loads(
        ruta.read_text(encoding="utf-8")
    )


def escribir(ruta, datos):
    ruta.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    ruta.write_text(
        json.dumps(
            datos,
            indent=2,
            ensure_ascii=False,
        ) + "\n",
        encoding="utf-8",
    )


def ahora():
    return datetime.now(timezone.utc).isoformat()


def fallo_registrado(datos):
    registros = datos.get(
        "enlaces_fallados_observados", []
    )

    if len(registros) != 1:
        raise RuntimeError(
            "Se esperaba un unico enlace fallado"
        )

    r = registros[0]

    return frozenset((
        r["extremo_a"],
        r["extremo_b"],
    ))


def comprobar_entradas():
    estado = cargar(
        RESULTADOS / "etapa02/EstadoPostFallo.json"
    )

    fallo = frozenset(
        estado["enlace_fallado"]
    )

    if len(fallo) != 2:
        raise RuntimeError(
            "Fallo de referencia invalido"
        )

    for nombre in (
        "FS_postfallo",
        "PS_postfallo",
        "RS_postfallo",
    ):
        datos = cargar(
            RESULTADOS / "etapa02" / (nombre + ".json")
        )

        if fallo_registrado(datos) != fallo:
            raise RuntimeError(
                f"Fallo inconsistente en {nombre}"
            )

    demandas = cargar(
        RESULTADOS
        / "etapa03/DemandasObservadas_iperf2.json"
    )

    flujos = demandas.get("flujos", [])

    if (
        frozenset(demandas["enlace_fallado"]) != fallo
        or not flujos
        or len(flujos)
        != demandas.get("cantidad_flujos")
    ):
        raise RuntimeError(
            "Demandas de referencia inconsistentes"
        )

    cargar(INVENTARIO)
    cargar(BASE / "config/escenario.json")

    return {
        "fallo": sorted(fallo),
        "flujos": len(flujos),
        "captura_simultanea": (
            estado.get("validacion", {}).get(
                "captura_simultanea"
            )
        ),
        "fuente": "ENSAYO_PREEXISTENTE",
    }


def ejecutar_fort(modo):
    entrada = comprobar_entradas()

    print(
        "\n=== FORT - ALGORITMO TARGET-TRANSITION ===",
        flush=True,
    )
    print("Modo:", modo.upper(), flush=True)
    print(
        "Fallo:",
        " - ".join(entrada["fallo"]).upper(),
        flush=True,
    )
    print(
        "Demandas observadas del ensayo:",
        entrada["flujos"],
        flush=True,
    )
    print(
        "Captura FS/PS/RS atomica:",
        entrada["captura_simultanea"],
        flush=True,
    )

    if modo == "verificar":
        print(
            "Integracion ejecutada: NO "
            "(solo validacion de entradas)",
            flush=True,
        )
        print(
            "Cambios enviados a OVS: 0",
            flush=True,
        )
        return

    inicio = time.perf_counter()

    identificador = (
        datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        + "_"
        + uuid.uuid4().hex[:8]
    )

    carpeta = DESTINO / identificador
    proyecto = carpeta / "proyecto"

    for nombre in ("config", "herramientas"):
        shutil.copytree(
            BASE / nombre,
            proyecto / nombre,
            ignore=shutil.ignore_patterns(
                "__pycache__",
                "*.pyc",
            ),
        )

    archivos = (
        "etapa01/puertos_detectados.json",
        "etapa02/FS_postfallo.json",
        "etapa02/PS_postfallo.json",
        "etapa02/RS_postfallo.json",
        "etapa02/EstadoPostFallo.json",
        "etapa03/DemandasObservadas_iperf2.json",
    )

    for relativo in archivos:
        destino = proyecto / "resultados" / relativo

        destino.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        shutil.copy2(
            RESULTADOS / relativo,
            destino,
        )

    registros = []

    try:
        for numero, (etapa, script, parametros) in enumerate(
            FASES,
            start=1,
        ):
            proceso = subprocess.run(
                [
                    sys.executable,
                    str(proyecto / "herramientas" / script),
                    *parametros,
                ],
                cwd=proyecto,
                text=True,
                capture_output=True,
                timeout=180,
                check=False,
                env={
                    **os.environ,
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )

            logs = carpeta / "logs"
            logs.mkdir(
                parents=True,
                exist_ok=True,
            )

            (
                logs / f"{numero:02d}_{script}.log"
            ).write_text(
                proceso.stdout + "\n" + proceso.stderr,
                encoding="utf-8",
            )

            registros.append({
                "etapa": etapa,
                "modulo": script,
                "codigo": proceso.returncode,
            })

            if proceso.returncode:
                detalle = "\n".join(
                    (proceso.stdout + proceso.stderr)
                    .splitlines()[-8:]
                )

                raise RuntimeError(
                    f"FORT abortado en {script}: "
                    + detalle
                )

            print(
                f"[{numero:02d}/{len(FASES)}] "
                f"{etapa}: {script} OK",
                flush=True,
            )

        seleccionado = cargar(
            proyecto
            / "resultados/etapa05/SeleccionPareja.json"
        ).get("pareja_preferida_modelo")

        if seleccionado:
            print(
                "Pareja preliminar:",
                seleccionado["target_id"],
                "+",
                seleccionado["transition_id"],
                flush=True,
            )

            print(
                "Final MLU estimada:",
                seleccionado["final_mlu_pct"],
                "%",
                flush=True,
            )

            print(
                "Peak MLU estimada:",
                seleccionado["peak_mlu_pct"],
                "%",
                flush=True,
            )

        else:
            print(
                "Sin pareja candidata: mantener FS",
                flush=True,
            )

        resumen = carpeta / "FORT_Resumen.json"

        escribir(resumen, {
            "algoritmo": "FORT",
            "modo": "PILOTO_CON_DATOS_PREVIOS",
            "run_id": identificador,
            "entrada": entrada,
            "etapas": registros,
            "seleccion": seleccionado,
            "autorizada_para_ejecucion": False,
            "cambios_ovs": 0,
            "tiempo_s": round(
                time.perf_counter() - inicio,
                6,
            ),
        })

        print(
            "Resultado aislado:",
            resumen,
            flush=True,
        )
        print(
            "Cambios enviados a OVS: 0",
            flush=True,
        )
        print(
            "Ejecucion automatica/OS-Ken: PENDIENTE",
            flush=True,
        )

    except Exception as error:
        escribir(
            carpeta / "FORT_Error.json",
            {
                "run_id": identificador,
                "etapas": registros,
                "error": str(error),
            },
        )
        raise


def campos_match(regla):
    return dict(regla.match.items())


def acciones_de_regla(regla):
    acciones = []

    for instruccion in regla.instructions:
        if not hasattr(instruccion, "actions"):
            raise RuntimeError(
                "Instruccion OpenFlow no soportada"
            )

        acciones.extend(instruccion.actions)

    return acciones


def actualizar_vlan(accion, vlan):
    tipo = type(accion).__name__

    if tipo == "OFPActionPopVlan":
        return None

    if tipo == "OFPActionPushVlan":
        return vlan

    if tipo == "OFPActionSetField":
        clave = getattr(accion, "key", None)
        valor = getattr(accion, "value", None)

        if (
            clave is None
            and hasattr(accion, "fields")
            and accion.fields
        ):
            campo = accion.fields[0]

            clave = getattr(
                campo, "field", None
            )
            valor = getattr(
                campo, "value", None
            )

        if clave != "vlan_vid":
            raise RuntimeError(
                f"SetField no soportado: {clave}"
            )

        return int(valor) & 0xFFF

    return vlan


class FORT(app_manager.OSKenApp):
    """Aplicacion OpenFlow de FORT.

    Captura el estado post-FF.
    No modifica flujos ni grupos de OVS.
    """

    OFP_VERSIONS = [
        ofproto_v1_3.OFP_VERSION
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        escenario = cargar(
            BASE / "config/escenario.json"
        )

        registros = cargar(INVENTARIO)

        self.switches = set(
            escenario["switches"]
        )

        self.capacidad_bps = (
            float(
                escenario["capacidad_enlace_mbps"]
            ) * 1e6
        )

        if self.capacidad_bps <= 0:
            raise RuntimeError(
                "Capacidad configurada no valida"
            )

        self.hosts = {
            h["nombre"]: {
                "ip": str(
                    ipaddress.ip_interface(
                        h["ip"]
                    ).ip
                ),
                "switch": h["switch"],
            }
            for h in escenario["hosts"]
        }

        self.enlaces = {}
        self.vecinos = {}
        self.por_puerto = {}

        for e in registros:
            a = e["nodo_a"]
            b = e["nodo_b"]

            pa = int(e["puerto_a"])
            pb = int(e["puerto_b"])

            self.vecinos[(a, pa)] = b
            self.vecinos[(b, pb)] = a

            if (
                a in self.switches
                and b in self.switches
            ):
                clave = "-".join(
                    sorted((a, b))
                )

                if clave in self.enlaces:
                    raise RuntimeError(
                        "Enlace duplicado: " + clave
                    )

                self.enlaces[clave] = (
                    (a, pa),
                    (b, pb),
                )

                for extremo in self.enlaces[clave]:
                    if extremo in self.por_puerto:
                        raise RuntimeError(
                            "Puerto duplicado: "
                            + str(extremo)
                        )

                    self.por_puerto[extremo] = clave

        if (
            len(self.enlaces)
            != len(escenario["enlaces"])
            or not self.vecinos
        ):
            raise RuntimeError(
                "Inventario incoherente con topologia"
            )

        self.datapaths = {}
        self.iniciales = {}
        self.baseline_recibida = set()

        self.estados_puerto = {}
        self.caidos = set()

        self.baseline_lista = False
        self.secuencia_evento = 0

        self.captura = None
        self.capturas_pendientes = {}

        print(
            "\n=== FORT - OBSERVACION OPENFLOW ===",
            flush=True,
        )
        print(
            "Switches esperados:",
            len(self.switches),
            flush=True,
        )
        print(
            "Enlaces supervisados:",
            len(self.enlaces),
            flush=True,
        )
        print(
            "Fuente: FS + PS + RS + "
            "demandas IP por OpenFlow 1.3",
            flush=True,
        )
        print(
            "Modo: SOLO OBSERVACION | "
            "Cambios enviados a OVS: 0",
            flush=True,
        )

    def registrar(
        self,
        tipo,
        enlace=None,
        **detalles,
    ):
        EVENTOS.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        evento = {
            "fecha_utc": ahora(),
            "algoritmo": "FORT",
            "tipo": tipo,
            "enlace": enlace,
            "reoptimizacion_ejecutada": False,
            **detalles,
        }

        with EVENTOS.open(
            "a",
            encoding="utf-8",
        ) as archivo:
            archivo.write(
                json.dumps(
                    evento,
                    ensure_ascii=False,
                ) + "\n"
            )

    @staticmethod
    def activo(dp, puerto):
        ofp = dp.ofproto

        return not (
            int(puerto.config)
            & ofp.OFPPC_PORT_DOWN
            or int(puerto.state)
            & (
                ofp.OFPPS_LINK_DOWN
                | ofp.OFPPS_BLOCKED
            )
        )

    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        MAIN_DISPATCHER,
    )
    def conectado(self, evento):
        dp = evento.datapath

        if dp is None:
            return

        sw = f"s{dp.id}"

        if sw not in self.switches:
            return

        self.datapaths[sw] = dp
        self.baseline_lista = False
        self.baseline_recibida.discard(sw)

        solicitud = (
            dp.ofproto_parser
            .OFPPortDescStatsRequest(dp, 0)
        )

        dp.send_msg(solicitud)

        self.iniciales[sw] = {
            "xid": solicitud.xid,
            "partes": [],
        }

        print(
            f"FORT: {sw.upper()} conectado; "
            "solicitando puertos",
            flush=True,
        )

    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        DEAD_DISPATCHER,
    )
    def desconectado(self, evento):
        dp = evento.datapath

        if dp is None:
            return

        sw = f"s{dp.id}"

        if self.datapaths.get(sw) is not dp:
            return

        del self.datapaths[sw]

        self.iniciales.pop(sw, None)
        self.baseline_recibida.discard(sw)

        self.estados_puerto = {
            puerto: activo
            for puerto, activo
            in self.estados_puerto.items()
            if puerto[0] != sw
        }

        self.baseline_lista = False
        self.caidos.clear()
        self.secuencia_evento += 1

        self.captura = None
        self.capturas_pendientes.clear()

        self.registrar(
            "SWITCH_DESCONECTADO",
            switch=sw,
        )

        print(
            f"FORT: {sw.upper()} desconectado; "
            "captura invalidada",
            flush=True,
        )

    @set_ev_cls(
        ofp_event.EventOFPPortDescStatsReply,
        MAIN_DISPATCHER,
    )
    def respuesta_puertos(self, evento):
        mensaje = evento.msg
        dp = mensaje.datapath

        sw = f"s{dp.id}"

        inicial = self.iniciales.get(sw)

        if (
            inicial
            and inicial["xid"] == mensaje.xid
        ):
            inicial["partes"].extend(
                mensaje.body
            )

            mas_partes = bool(
                mensaje.flags
                & dp.ofproto.OFPMPF_REPLY_MORE
            )

            if not mas_partes:
                for puerto in inicial["partes"]:
                    clave = (
                        sw,
                        int(puerto.port_no),
                    )

                    if clave in self.por_puerto:
                        self.estados_puerto[clave] = (
                            self.activo(dp, puerto)
                        )

                self.baseline_recibida.add(sw)
                self.iniciales.pop(sw, None)

                self.inicializar_baseline()

            return

        self.incorporar_respuesta(
            "puertos", mensaje
        )

    def inicializar_baseline(self):
        if self.baseline_lista:
            return

        if set(self.datapaths) != self.switches:
            return

        if (
            self.baseline_recibida
            != self.switches
        ):
            return

        if not all(
            puerto in self.estados_puerto
            for puerto in self.por_puerto
        ):
            return

        self.caidos = {
            nombre
            for nombre, (a, b)
            in self.enlaces.items()
            if not (
                self.estados_puerto[a]
                and self.estados_puerto[b]
            )
        }

        self.baseline_lista = True

        self.registrar(
            "REFERENCIA_INICIAL",
            enlaces_supervisados=len(
                self.enlaces
            ),
            enlaces_ya_caidos=sorted(
                self.caidos
            ),
        )

        print(
            "FORT: referencia inicial completada",
            flush=True,
        )
        print(
            "FORT: enlaces caidos inicialmente:",
            sorted(self.caidos),
            flush=True,
        )
        print(
            "FORT: esperando eventos OpenFlow",
            flush=True,
        )

        if len(self.caidos) == 1:
            enlace = next(iter(self.caidos))

            print(
                "FORT: capturando FS + PS + RS "
                "del fallo preexistente",
                flush=True,
            )

            hub.spawn(
                self.captura_despues_del_fallo,
                self.secuencia_evento,
                enlace,
                2.0,
            )

    @set_ev_cls(
        ofp_event.EventOFPPortStatus,
        MAIN_DISPATCHER,
    )
    def puerto_cambiado(self, evento):
        mensaje = evento.msg
        dp = mensaje.datapath

        sw = f"s{dp.id}"

        clave = (
            sw,
            int(mensaje.desc.port_no),
        )

        enlace = self.por_puerto.get(
            clave
        )

        if enlace is None:
            return

        if (
            mensaje.reason
            == dp.ofproto.OFPPR_DELETE
        ):
            activo = False
        else:
            activo = self.activo(
                dp, mensaje.desc
            )

        self.estados_puerto[clave] = activo

        if not self.baseline_lista:
            return

        a, b = self.enlaces[enlace]

        if not (
            a in self.estados_puerto
            and b in self.estados_puerto
        ):
            return

        enlace_activo = (
            self.estados_puerto[a]
            and self.estados_puerto[b]
        )

        if (
            not enlace_activo
            and enlace not in self.caidos
        ):
            self.caidos.add(enlace)
            self.secuencia_evento += 1

            self.registrar(
                "ENLACE_NO_OPERATIVO",
                enlace,
                extremos=[
                    list(a),
                    list(b),
                ],
            )

            print(
                "FORT: ENLACE NO OPERATIVO:",
                enlace,
                flush=True,
            )
            print(
                "FORT: iniciando captura "
                "FS + PS + RS por OpenFlow",
                flush=True,
            )

            hub.spawn(
                self.captura_despues_del_fallo,
                self.secuencia_evento,
                enlace,
            )

        elif (
            enlace_activo
            and enlace in self.caidos
        ):
            self.caidos.remove(enlace)
            self.secuencia_evento += 1

            self.registrar(
                "ENLACE_RECUPERADO",
                enlace,
            )

            print(
                "FORT: ENLACE RECUPERADO:",
                enlace,
                flush=True,
            )

    def captura_despues_del_fallo(
        self,
        secuencia,
        enlace,
        demora=0.8,
    ):
        hub.sleep(demora)

        if (
            secuencia != self.secuencia_evento
            or not self.baseline_lista
            or self.caidos != {enlace}
        ):
            return

        if self.captura is not None:
            self.registrar(
                "CAPTURA_OMITIDA",
                enlace,
                causa="Captura previa en curso",
            )
            return

        cid = (
            datetime.now(timezone.utc).strftime(
                "%Y%m%dT%H%M%SZ"
            )
            + "_"
            + uuid.uuid4().hex[:6]
        )

        captura = {
            "id": cid,
            "fallo": enlace,
            "secuencia": secuencia,
            "inicio_utc": ahora(),
            "fase": 0,
            "pendientes": set(),
            "datos": {
                tipo: {}
                for tipo in (
                    "flujos0",
                    "grupos",
                    "puertos",
                    "contadores0",
                    "flujos1",
                    "contadores1",
                )
            },
            "instantes": {
                tipo: {}
                for tipo in (
                    "contadores0",
                    "contadores1",
                    "flujos0",
                    "flujos1",
                )
            },
        }

        self.captura = captura

        self.solicitar_lote(
            captura,
            fase=0,
        )

        hub.spawn(
            self.esperar_captura,
            cid,
        )

    def solicitar_lote(
        self,
        captura,
        fase,
    ):
        if self.captura is not captura:
            return

        captura["fase"] = fase
        captura["pendientes"].clear()
        self.capturas_pendientes.clear()

        for sw, dp in sorted(
            self.datapaths.items()
        ):
            parser = dp.ofproto_parser

            if fase == 0:
                solicitudes = {
                    "flujos0": (
                        parser.OFPFlowStatsRequest(dp)
                    ),
                    "grupos": (
                        parser.OFPGroupDescStatsRequest(
                            dp, 0
                        )
                    ),
                    "puertos": (
                        parser.OFPPortDescStatsRequest(
                            dp, 0
                        )
                    ),
                    "contadores0": (
                        parser.OFPPortStatsRequest(
                            dp,
                            0,
                            dp.ofproto.OFPP_ANY,
                        )
                    ),
                }

            else:
                solicitudes = {
                    "flujos1": (
                        parser.OFPFlowStatsRequest(dp)
                    ),
                    "contadores1": (
                        parser.OFPPortStatsRequest(
                            dp,
                            0,
                            dp.ofproto.OFPP_ANY,
                        )
                    ),
                }

            for tipo, solicitud in solicitudes.items():
                dp.send_msg(solicitud)

                self.capturas_pendientes[
                    (sw, tipo)
                ] = {
                    "xid": solicitud.xid,
                    "partes": [],
                }

                captura["pendientes"].add(
                    (sw, tipo)
                )

        print(
            f"FORT [{captura['id']}]: "
            f"fase {fase + 1}/2 | "
            f"{len(captura['pendientes'])} "
            "respuestas OpenFlow solicitadas",
            flush=True,
        )

    def segunda_muestra(self, cid):
        hub.sleep(
            VENTANA_MEDICION_S
        )

        if (
            self.captura is None
            or self.captura["id"] != cid
        ):
            return

        captura = self.captura

        if (
            captura["secuencia"]
            != self.secuencia_evento
            or self.caidos
            != {captura["fallo"]}
        ):
            self.abortar(
                "CAMBIO_DE_ESTADO_DURANTE_MUESTREO"
            )
            return

        self.solicitar_lote(
            captura,
            fase=1,
        )

    def esperar_captura(self, cid):
        hub.sleep(
            TIMEOUT_CAPTURA_S
        )

        if (
            self.captura is not None
            and self.captura["id"] == cid
        ):
            self.abortar(
                "TIMEOUT_OPENFLOW"
            )

    def abortar(self, causa):
        if self.captura is None:
            return

        captura = self.captura
        self.captura = None

        pendientes = sorted(
            f"{sw}:{tipo}"
            for sw, tipo
            in captura["pendientes"]
        )

        self.capturas_pendientes.clear()

        self.registrar(
            "CAPTURA_CANCELADA",
            captura["fallo"],
            captura_id=captura["id"],
            causa=causa,
            pendientes=pendientes,
        )

        print(
            f"FORT: CAPTURA CANCELADA ({causa}). "
            "FF permanece sin cambios",
            flush=True,
        )

    def incorporar_respuesta(
        self,
        tipo,
        mensaje,
    ):
        sw = f"s{mensaje.datapath.id}"
        clave = (sw, tipo)

        solicitud = self.capturas_pendientes.get(
            clave
        )

        if (
            self.captura is None
            or solicitud is None
            or mensaje.xid
            != solicitud["xid"]
        ):
            return

        solicitud["partes"].extend(
            mensaje.body
        )

        if (
            mensaje.flags
            & mensaje.datapath.ofproto.OFPMPF_REPLY_MORE
        ):
            return

        captura = self.captura

        captura["datos"][tipo][sw] = (
            solicitud["partes"]
        )

        if tipo in captura["instantes"]:
            captura["instantes"][tipo][sw] = (
                time.monotonic()
            )

        del self.capturas_pendientes[
            clave
        ]

        captura["pendientes"].discard(
            clave
        )

        if captura["pendientes"]:
            return

        if captura["fase"] == 0:
            hub.spawn(
                self.segunda_muestra,
                captura["id"],
            )

        else:
            self.captura = None
            self.capturas_pendientes.clear()

            try:
                self.procesar_estado(
                    captura
                )

            except Exception as error:
                self.registrar(
                    "CAPTURA_ESTADO_ERROR",
                    captura["fallo"],
                    captura_id=captura["id"],
                    error=str(error),
                )

                print(
                    "FORT: ERROR capturando "
                    "FS/PS/RS:",
                    repr(error),
                    flush=True,
                )

    @set_ev_cls(
        ofp_event.EventOFPFlowStatsReply,
        MAIN_DISPATCHER,
    )
    def respuesta_flujos(self, evento):
        fase = (
            self.captura["fase"]
            if self.captura
            else 0
        )

        self.incorporar_respuesta(
            "flujos1"
            if fase == 1
            else "flujos0",
            evento.msg,
        )

    @set_ev_cls(
        ofp_event.EventOFPGroupDescStatsReply,
        MAIN_DISPATCHER,
    )
    def respuesta_grupos(self, evento):
        self.incorporar_respuesta(
            "grupos",
            evento.msg,
        )

    @set_ev_cls(
        ofp_event.EventOFPPortStatsReply,
        MAIN_DISPATCHER,
    )
    def respuesta_contadores(self, evento):
        fase = (
            self.captura["fase"]
            if self.captura
            else 0
        )

        self.incorporar_respuesta(
            "contadores1"
            if fase == 1
            else "contadores0",
            evento.msg,
        )

    def recorrer_acciones(
        self,
        sw,
        acciones,
        vlan,
        grupos_activados,
        grupos,
        puertos,
        profundidad=0,
    ):
        if profundidad > 4:
            raise RuntimeError(
                "Grupos FF encadenados en exceso"
            )

        salida = None

        for accion in acciones:
            tipo = type(accion).__name__

            if tipo in (
                "OFPActionPushVlan",
                "OFPActionPopVlan",
                "OFPActionSetField",
            ):
                vlan = actualizar_vlan(
                    accion,
                    vlan,
                )

            elif tipo == "OFPActionGroup":
                gid = int(
                    accion.group_id
                )

                desc = grupos.get(
                    sw, {}
                ).get(gid)

                if (
                    desc is None
                    or desc.type
                    != ofproto_v1_3.OFPGT_FF
                ):
                    raise RuntimeError(
                        f"Grupo FF desconocido: {sw}:{gid}"
                    )

                elegido = None

                for indice, bucket in enumerate(
                    desc.buckets
                ):
                    if (
                        puertos.get((
                            sw,
                            int(bucket.watch_port),
                        ))
                        is True
                    ):
                        elegido = (
                            indice,
                            bucket,
                        )
                        break

                if elegido is None:
                    raise RuntimeError(
                        f"Sin bucket FF disponible: {sw}:{gid}"
                    )

                indice, bucket = elegido

                grupos_activados.append({
                    "switch": sw,
                    "grupo": gid,
                    "bucket_indice": indice,
                    "modo_inferido": (
                        "PRINCIPAL"
                        if indice == 0
                        else "RESPALDO"
                    ),
                    "watch_port": int(
                        bucket.watch_port
                    ),
                })

                salida, vlan = self.recorrer_acciones(
                    sw,
                    bucket.actions,
                    vlan,
                    grupos_activados,
                    grupos,
                    puertos,
                    profundidad + 1,
                )

            elif tipo == "OFPActionOutput":
                salida = int(
                    accion.port
                )

            else:
                raise RuntimeError(
                    "Accion OpenFlow no soportada: "
                    + tipo
                )

        if salida is None:
            raise RuntimeError(
                f"Acciones sin puerto de salida: {sw}"
            )

        return salida, vlan

    def reconstruir(
        self,
        origen,
        destino,
        flujos,
        grupos,
        puertos,
    ):
        sw = self.hosts[origen]["switch"]

        ip_a = self.hosts[origen]["ip"]
        ip_b = self.hosts[destino]["ip"]

        ruta = [origen, sw]
        registros_grupo = []
        visitados = set()

        vlan = None

        for _ in range(32):
            estado = (sw, vlan)

            if estado in visitados:
                raise RuntimeError(
                    f"Bucle {origen}->{destino}: "
                    f"{sw}, VLAN={vlan}"
                )

            visitados.add(estado)
            candidatas = []

            for regla in flujos[sw]:
                m = campos_match(regla)

                if (
                    int(m.get("eth_type", 0))
                    != 0x0800
                    or m.get("ipv4_src") != ip_a
                    or m.get("ipv4_dst") != ip_b
                    or int(regla.table_id) != 0
                ):
                    continue

                match_vlan = m.get(
                    "vlan_vid"
                )

                if isinstance(
                    match_vlan,
                    (list, tuple),
                ):
                    raise RuntimeError(
                        "VLAN con mascara no soportada"
                    )

                vlan_regla = (
                    None
                    if match_vlan is None
                    else int(match_vlan) & 0xFFF
                )

                if vlan_regla != vlan:
                    continue

                candidatas.append(
                    regla
                )

            if not candidatas:
                raise RuntimeError(
                    f"Sin regla IP "
                    f"{origen}->{destino} "
                    f"en {sw}, VLAN={vlan}"
                )

            regla = max(
                candidatas,
                key=lambda r: r.priority,
            )

            if sum(
                r.priority == regla.priority
                for r in candidatas
            ) > 1:
                raise RuntimeError(
                    "Reglas ambiguas en "
                    f"{sw} para "
                    f"{origen}->{destino}"
                )

            salida, vlan = self.recorrer_acciones(
                sw,
                acciones_de_regla(regla),
                vlan,
                registros_grupo,
                grupos,
                puertos,
            )

            if (
                puertos.get((sw, salida))
                is not True
            ):
                raise RuntimeError(
                    "Puerto de salida inactivo: "
                    f"{sw}:{salida}"
                )

            vecino = self.vecinos.get(
                (sw, salida)
            )

            if vecino is None:
                raise RuntimeError(
                    "Vecino no encontrado: "
                    f"{sw}:{salida}"
                )

            ruta.append(
                vecino
            )

            if vecino == destino:
                return {
                    "origen": origen,
                    "destino": destino,
                    "ruta_seleccionada": ruta,
                    "grupos_ff": registros_grupo,
                }

            if vecino not in self.switches:
                raise RuntimeError(
                    "Destino inesperado: "
                    f"{vecino} "
                    f"({origen}->{destino})"
                )

            sw = vecino

        raise RuntimeError(
            "Limite de saltos excedido: "
            f"{origen}->{destino}"
        )

    def resumir_ps(
        self,
        datos,
        puertos,
    ):
        registros = []
        total_buckets = 0
        respaldo = 0

        for sw, lista in sorted(
            datos["grupos"].items()
        ):
            for grupo in lista:
                if (
                    int(grupo.type)
                    != ofproto_v1_3.OFPGT_FF
                ):
                    continue

                buckets = []
                elegido = None

                for indice, bucket in enumerate(
                    grupo.buckets
                ):
                    clave = (
                        sw,
                        int(bucket.watch_port),
                    )

                    vivo = puertos.get(
                        clave
                    )

                    if (
                        vivo is True
                        and elegido is None
                    ):
                        elegido = indice

                    buckets.append({
                        "indice": indice,
                        "watch_port": int(
                            bucket.watch_port
                        ),
                        "activo": vivo,
                        "acciones": [
                            str(a)
                            for a in bucket.actions
                        ],
                    })

                total_buckets += len(
                    buckets
                )

                if (
                    elegido is not None
                    and elegido > 0
                ):
                    respaldo += 1

                registros.append({
                    "switch": sw,
                    "group_id": int(
                        grupo.group_id
                    ),
                    "buckets": buckets,
                    "bucket_seleccionado_inferido":
                        elegido,
                })

        reglas = sum(
            len(lista)
            for lista in datos["flujos0"].values()
        )

        return {
            "grupos_ff": registros,
            "cantidad_grupos_ff": len(registros),
            "cantidad_buckets_ff": total_buckets,
            "grupos_con_respaldo_inferido":
                respaldo,
            "reglas_openflow_totales":
                reglas,
            "nota": (
                "Bucket seleccionado inferido "
                "por estado del watch_port"
            ),
        }

    def resumir_rs(
        self,
        captura,
        puertos,
    ):
        datos = captura["datos"]

        primera = {}
        segunda = {}

        for sw in sorted(
            self.switches
        ):
            primera.update({
                (sw, int(p.port_no)): p
                for p in datos["contadores0"][sw]
            })

            segunda.update({
                (sw, int(p.port_no)): p
                for p in datos["contadores1"][sw]
            })

        direcciones = []

        for nombre, (a, b) in sorted(
            self.enlaces.items()
        ):
            for origen, destino in (
                (a, b),
                (b, a),
            ):
                if (
                    origen not in primera
                    or origen not in segunda
                ):
                    raise RuntimeError(
                        "Contadores faltantes: "
                        f"{origen}"
                    )

                delta_t = (
                    captura["instantes"][
                        "contadores1"
                    ][origen[0]]
                    -
                    captura["instantes"][
                        "contadores0"
                    ][origen[0]]
                )

                if not (
                    2.0 <= delta_t <= 20.0
                ):
                    raise RuntimeError(
                        "Ventana anomala: "
                        f"{origen}, {delta_t}"
                    )

                antes = int(
                    primera[origen].tx_bytes
                )
                despues = int(
                    segunda[origen].tx_bytes
                )

                if (
                    antes < 0
                    or despues < antes
                    or despues >= 2**64 - 1
                ):
                    raise RuntimeError(
                        "Contador TX invalido: "
                        f"{origen}"
                    )

                tasa = (
                    (despues - antes)
                    * 8.0 / delta_t
                )

                activo = bool(
                    puertos[origen]
                    and puertos[destino]
                )

                direcciones.append({
                    "origen": origen[0],
                    "destino": destino[0],
                    "puerto": origen[1],
                    "activo": activo,
                    "tx_bytes_delta": (
                        despues - antes
                    ),
                    "intervalo_s": round(
                        delta_t, 5
                    ),
                    "tasa_tx_bps": round(
                        tasa, 3
                    ),
                    "capacidad_configurada_bps":
                        self.capacidad_bps,
                    "utilizacion_observada_pct":
                        round(
                            100.0
                            * tasa
                            / self.capacidad_bps,
                            5,
                        ),
                    "capacidad_residual_estimada_bps":
                        (
                            max(
                                0.0,
                                self.capacidad_bps - tasa,
                            )
                            if activo
                            else 0.0
                        ),
                    "advertencia": (
                        "TX incremento en enlace "
                        "no operativo"
                        if not activo and tasa > 0
                        else None
                    ),
                })

        operativas = [
            r
            for r in direcciones
            if r["activo"]
        ]

        return {
            "cantidad_direcciones":
                len(direcciones),
            "cantidad_direcciones_operativas":
                len(operativas),
            "capacidad_fuente": (
                "escenario.json: capacidad "
                "nominal, no verificacion tc"
            ),
            "maxima_utilizacion_observada_pct":
                max(
                    (
                        r["utilizacion_observada_pct"]
                        for r in operativas
                    ),
                    default=0.0,
                ),
            "direcciones": direcciones,
        }

    def resumir_demandas_ip(
        self,
        captura,
    ):
        datos = captura["datos"]
        tasas = []

        for origen in sorted(
            self.hosts
        ):
            sw = self.hosts[origen][
                "switch"
            ]

            for destino in sorted(
                self.hosts
            ):
                if origen == destino:
                    continue

                ip_a = self.hosts[origen][
                    "ip"
                ]

                ip_b = self.hosts[destino][
                    "ip"
                ]

                muestras = []

                for tipo in (
                    "flujos0",
                    "flujos1",
                ):
                    candidatos = []

                    for regla in datos[tipo][sw]:
                        m = campos_match(
                            regla
                        )

                        if (
                            m.get("eth_type")
                            == 0x0800
                            and m.get("ipv4_src")
                            == ip_a
                            and m.get("ipv4_dst")
                            == ip_b
                            and "vlan_vid" not in m
                            and int(regla.table_id)
                            == 0
                        ):
                            candidatos.append(
                                regla
                            )

                    if not candidatos:
                        raise RuntimeError(
                            "Sin regla IPv4 de ingreso "
                            f"{origen}->{destino}"
                        )

                    prioridad = max(
                        int(r.priority)
                        for r in candidatos
                    )

                    elegidos = [
                        r
                        for r in candidatos
                        if int(r.priority)
                        == prioridad
                    ]

                    if len(elegidos) != 1:
                        raise RuntimeError(
                            "Reglas ambiguas de ingreso "
                            f"{origen}->{destino}"
                        )

                    muestras.append(
                        elegidos[0]
                    )

                anterior, posterior = muestras

                if (
                    int(anterior.priority)
                    != int(posterior.priority)
                    or int(posterior.byte_count)
                    < int(anterior.byte_count)
                ):
                    raise RuntimeError(
                        "Regla reemplazada o "
                        "contador decreciente: "
                        f"{origen}->{destino}"
                    )

                intervalo = (
                    captura["instantes"][
                        "flujos1"
                    ][sw]
                    -
                    captura["instantes"][
                        "flujos0"
                    ][sw]
                )

                if not (
                    2.0 <= intervalo <= 20.0
                ):
                    raise RuntimeError(
                        "Ventana invalida de demanda"
                    )

                delta_bytes = (
                    int(posterior.byte_count)
                    -
                    int(anterior.byte_count)
                )

                tasa = (
                    delta_bytes
                    * 8.0 / intervalo
                )

                tasas.append({
                    "origen": origen,
                    "destino": destino,
                    "tasa_ipv4_observada_bps":
                        round(tasa, 3),
                    "bytes_delta": delta_bytes,
                    "intervalo_s": round(
                        intervalo, 5
                    ),
                    "protocolo": "IP_AGREGADO",
                })

        return {
            "fuente": (
                "FlowStats de reglas IPv4 "
                "en switches de ingreso"
            ),
            "tipo": (
                "DEMANDAS_IP_OBSERVADAS_EN_VENTANA"
            ),
            "nota": (
                "No separa TCP/UDP ni ARP. "
                "Sin trafico, las tasas "
                "pueden ser cero"
            ),
            "comunicaciones": tasas,
            "comunicaciones_con_trafico":
                sum(
                    x["tasa_ipv4_observada_bps"] > 0
                    for x in tasas
                ),
        }

    def procesar_estado(
        self,
        captura,
    ):
        if (
            captura["secuencia"]
            != self.secuencia_evento
            or not self.baseline_lista
            or self.caidos
            != {captura["fallo"]}
        ):
            self.registrar(
                "CAPTURA_DESCARTADA_ESTADO_CAMBIADO",
                captura["fallo"],
            )
            return

        datos = captura["datos"]

        for tipo in (
            "flujos0",
            "grupos",
            "puertos",
            "contadores0",
            "flujos1",
            "contadores1",
        ):
            if set(datos[tipo]) != self.switches:
                raise RuntimeError(
                    "Respuestas OpenFlow "
                    "incompletas: " + tipo
                )

        puertos = {}

        for sw, lista in datos["puertos"].items():
            dp = self.datapaths.get(
                sw
            )

            if dp is None:
                raise RuntimeError(
                    "Switch desconectado: " + sw
                )

            for descripcion in lista:
                clave = (
                    sw,
                    int(descripcion.port_no),
                )

                if clave in self.vecinos:
                    puertos[clave] = (
                        self.activo(
                            dp,
                            descripcion,
                        )
                    )

        esperados = {
            clave
            for clave in self.vecinos
            if clave[0] in self.switches
        }

        faltantes = sorted(
            esperados - set(puertos)
        )

        if faltantes:
            raise RuntimeError(
                "Snapshot incompleto de "
                "puertos de switches: "
                + str(faltantes)
            )

        caidos = {
            nombre
            for nombre, (a, b)
            in self.enlaces.items()
            if not (
                puertos[a]
                and puertos[b]
            )
        }

        if caidos != {captura["fallo"]}:
            raise RuntimeError(
                "Fallo cambio durante captura: "
                + str(sorted(caidos))
            )

        grupos = {
            sw: {
                int(g.group_id): g
                for g in lista
            }
            for sw, lista
            in datos["grupos"].items()
        }

        comunicaciones = [
            self.reconstruir(
                a,
                b,
                datos["flujos0"],
                grupos,
                puertos,
            )
            for a in sorted(self.hosts)
            for b in sorted(self.hosts)
            if a != b
        ]

        respaldo = [
            c
            for c in comunicaciones
            if any(
                g["modo_inferido"]
                == "RESPALDO"
                for g in c["grupos_ff"]
            )
        ]

        ps = self.resumir_ps(
            datos,
            puertos,
        )

        rs = self.resumir_rs(
            captura,
            puertos,
        )

        demandas = self.resumir_demandas_ip(
            captura
        )

        if (
            captura["secuencia"]
            != self.secuencia_evento
            or self.caidos
            != {captura["fallo"]}
        ):
            raise RuntimeError(
                "Estado cambio antes de guardar"
            )

        directorio = (
            RESULTADOS
            / "etapa06/fort_capturas_estado"
        )

        estado_path = (
            directorio
            / ("FORT_Estado_" + captura["id"] + ".json")
        )

        escribir(estado_path, {
            "tipo": "FORT_ESTADO_POST_FF_DINAMICO",
            "fecha_utc": ahora(),
            "fallo": captura["fallo"],
            "inicio_utc": captura["inicio_utc"],
            "captura_atomica": False,
            "fs": {
                "comunicaciones": comunicaciones,
                "cantidad": len(comunicaciones),
            },
            "ps": ps,
            "rs": rs,
            "demandas": demandas,
            "reoptimizacion_ejecutada": False,
            "nota": (
                "Captura coordinada no atomica "
                "con intervalos reales "
                "de contadores OpenFlow"
            ),
        })

        fs_path = (
            RESULTADOS
            / "etapa06/fort_capturas_fs"
            / ("FORT_FS_" + captura["id"] + ".json")
        )

        escribir(fs_path, {
            "tipo": (
                "FORT_FS_POST_FF_INFERIDO_OPENFLOW"
            ),
            "fecha_utc": ahora(),
            "inicio_consultas_utc":
                captura["inicio_utc"],
            "captura_atomica": False,
            "enlace_fallado":
                captura["fallo"].split("-"),
            "fuente": (
                "FlowStats + GroupDescStats "
                "+ PortDescStats OpenFlow 1.3"
            ),
            "cantidad_comunicaciones":
                len(comunicaciones),
            "comunicaciones": comunicaciones,
        })

        self.registrar(
            "ESTADO_POST_FF_CAPTURADO",
            captura["fallo"],
            comunicaciones=len(comunicaciones),
            rutas_con_respaldo=len(respaldo),
            ps_grupos=ps["cantidad_grupos_ff"],
            rs_operativos=rs[
                "cantidad_direcciones_operativas"
            ],
            mlu_rs_pct=rs[
                "maxima_utilizacion_observada_pct"
            ],
            demandas_activas=demandas[
                "comunicaciones_con_trafico"
            ],
            archivo=str(estado_path),
        )

        print(
            "\n=== FORT: ESTADO POST-FAST-FAILOVER ===",
            flush=True,
        )

        print(
            "Enlace fallado:",
            captura["fallo"].upper(),
            flush=True,
        )

        print(
            "FS | Comunicaciones:",
            len(comunicaciones),
            flush=True,
        )

        for c in respaldo:
            print(
                c["origen"].upper(),
                "->",
                c["destino"].upper(),
                ":",
                " -> ".join(
                    n.upper()
                    for n in c["ruta_seleccionada"]
                ),
                flush=True,
            )

            for g in c["grupos_ff"]:
                if g["modo_inferido"] == "RESPALDO":
                    print(
                        f'  {g["switch"].upper()} | '
                        f'Grupo {g["grupo"]} | '
                        f'RESPALDO inferido | '
                        f'watch_port={g["watch_port"]}',
                        flush=True,
                    )

        print(
            "PS | Grupos FF:",
            ps["cantidad_grupos_ff"],
            "| Buckets:",
            ps["cantidad_buckets_ff"],
            "| Respaldos inferidos:",
            ps["grupos_con_respaldo_inferido"],
            flush=True,
        )

        print(
            "RS | Direcciones operativas:",
            rs["cantidad_direcciones_operativas"],
            "| MLU observada:",
            rs["maxima_utilizacion_observada_pct"],
            "%",
            flush=True,
        )

        print(
            "Demandas IP activas:",
            demandas["comunicaciones_con_trafico"],
            "/",
            len(demandas["comunicaciones"]),
            flush=True,
        )

        print(
            "FORT | Captura coordinada: SI",
            flush=True,
        )

        print(
            "FORT | Captura atomica: NO",
            flush=True,
        )

        print(
            "FORT | Archivo:",
            estado_path,
            flush=True,
        )

        print(
            "FORT | Reoptimizacion: "
            "NO EJECUTADA (observacion)",
            flush=True,
        )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "FORT - algoritmo Target-Transition"
        )
    )

    parser.add_argument(
        "--modo",
        choices=("verificar", "piloto"),
        default="verificar",
    )

    argumentos = parser.parse_args()

    ejecutar_fort(
        argumentos.modo
    )


if __name__ == "__main__":
    try:
        main()

    except (
        RuntimeError,
        OSError,
        ValueError,
        subprocess.TimeoutExpired,
    ) as error:
        raise SystemExit(
            f"ERROR FORT: {error}"
        )
