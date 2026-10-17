
#!/usr/bin/env python3
"""Arranque OS-Ken + FORT V1 con consola agrupada por etapas.

El formateador solo cambia la presentacion de stdout.
No modifica eventos, reglas OpenFlow, decisiones ni archivos JSON.
"""

import os
import re
import sys
from datetime import datetime

# Debe establecerse ANTES de importar OS-Ken.
os.environ["OSKEN_HUB_TYPE"] = "eventlet"

from os_ken import cfg
from os_ken.base import app_manager
from os_ken.lib import hub


class ConsolaFORT:
    """Agrupa mensajes existentes sin modificar los otros seis modulos."""

    SECCIONES = (
        ("=== CONTROLADOR SDN", "CONTROL", "INICIO DEL CONTROLADOR"),
        ("RUTAS PRINCIPALES:", "FF", "ETAPA 01 | RUTAS Y FAST FAILOVER"),
        ("=== FORT - OBSERVACION OPENFLOW", "CAPTURA", "ETAPA 02 | SUPERVISION OPENFLOW"),
        ("=== FORT: ESTADO POST-FAST-FAILOVER", "CAPTURA", "ETAPA 02 | ESTADO POST-FF (FS / PS / RS)"),
        ("=== FORT: BUSQUEDA ADAPTATIVA", "TARGETS", "ETAPA 03 | BUSQUEDA Y TARGETS"),
        ("=== FORT: ETAPAS 04 + 05 DINAMICAS", "TRANSITION", "ETAPAS 04-05 | EVALUACION TARGET-TRANSITION"),
        ("=== FORT: PREFLIGHT OPENFLOW REAL", "PREFLIGHT", "ETAPA 05 | VALIDACION OPENFLOW"),
    )

    COLORES = {
        "CONTROL": "\033[1;37m",
        "FF": "\033[36m",
        "CAPTURA": "\033[34m",
        "TARGETS": "\033[35m",
        "TRANSITION": "\033[33m",
        "PREFLIGHT": "\033[33m",
        "EJECUTOR": "\033[32m",
        "ERROR": "\033[1;31m",
        "AVISO": "\033[1;33m",
    }

    def __init__(self, original, detalle=False):
        self.original = original
        self.detalle = detalle
        self.colorear = bool(original.isatty()) and os.environ.get(
            "FORT_CONSOLA_COLOR", "1"
        ) != "0"
        self.pendiente = ""
        self.fase = "CONTROL"
        self.traceback = False

    def __getattr__(self, atributo):
        return getattr(self.original, atributo)

    def write(self, contenido):
        if not isinstance(contenido, str):
            contenido = str(contenido)

        self.pendiente += contenido

        while "\n" in self.pendiente:
            linea, self.pendiente = self.pendiente.split("\n", 1)
            self._mostrar(linea.rstrip("\r"))

        return len(contenido)

    def flush(self):
        self.original.flush()

    def _pintar(self, texto, categoria):
        if not self.colorear:
            return texto

        return (
            self.COLORES.get(categoria, "")
            + texto
            + "\033[0m"
        )

    def _emitir(self, categoria, texto, importante=False):
        hora = datetime.now().strftime("%H:%M:%S")
        etiqueta = self._pintar(
            f"[{categoria:<10}]",
            categoria
        )

        if importante:
            self.original.write(
                "\n" + "=" * 74 + "\n"
            )

        self.original.write(
            f"[{hora}] {etiqueta} {texto}\n"
        )

        if importante:
            self.original.write(
                "-" * 74 + "\n"
            )

        self.original.flush()

    def _mostrar(self, linea):
        linea = linea.strip()

        if not linea:
            return

        # Encabezados de las etapas de FORT.
        for prefijo, categoria, titulo in self.SECCIONES:
            if linea.startswith(prefijo):
                self.fase = categoria
                self._emitir(
                    categoria,
                    titulo,
                    importante=True
                )
                return

        # Ocultar las 12 rutas iniciales solamente
        # cuando se utiliza la vista resumida.
        if re.match(r"^H\d+ -> H\d+: S\d+", linea):
            if not self.detalle:
                return

            self._emitir("FF", linea)
            return

        # Mensajes individuales de conexion.
        if re.match(r"^FORT: S\d+ conectado;", linea):
            if not self.detalle:
                return

            self._emitir("CAPTURA", linea)
            return

        # Errores y excepciones.
        if linea.startswith(
            "Traceback (most recent call last)"
        ):
            self.traceback = True

        if self.traceback:
            self._emitir("ERROR", linea)

            if re.match(
                r"^\w+(?:\.\w+)*(?:Error|Exception):",
                linea
            ):
                self.traceback = False

            return

        if (
            "Exception occurred" in linea
            or "ERROR:" in linea
            or "rollback INCOMPLETO" in linea
        ):
            self._emitir("ERROR", linea)
            return

        # Ejecutor de Transitions OpenFlow.
        if linea.startswith("FORT EJECUTOR"):
            if linea.startswith(
                "FORT EJECUTOR: precondiciones OK"
            ):
                self._emitir(
                    "EJECUTOR",
                    "ETAPA 06 | EJECUCION CONTROLADA",
                    importante=True
                )

            categoria = "EJECUTOR"

            if any(
                palabra in linea.upper()
                for palabra in (
                    "BLOQUEADO",
                    "FALLO",
                    "INCOMPLETO",
                )
            ):
                categoria = "AVISO"

            self._emitir(categoria, linea)
            return

        # Verificador OpenFlow.
        if linea.startswith("FORT VALIDADOR"):
            self._emitir("PREFLIGHT", linea)
            return

        # Planificador Target-Transition.
        if linea.startswith("FORT ETAPAS"):
            self._emitir("TRANSITION", linea)
            return

        # Generador de Targets.
        if linea.startswith("FORT MOTOR"):
            self._emitir("TARGETS", linea)
            return

        # Deteccion de fallos y captura OpenFlow.
        if (
            linea.startswith("FORT:")
            or linea.startswith("FORT [")
        ):
            self._emitir("CAPTURA", linea)
            return

        # Instalacion inicial de FF por switch.
        if re.match(
            r"^S\d+: .*grupos FF.*reglas enviadas",
            linea
        ):
            self._emitir("FF", linea)
            return

        # Diferenciar limitaciones y advertencias.
        if any(
            texto in linea
            for texto in (
                "SOLO OBSERVACION",
                "NO AUTORIZADO",
                "PENDIENTE",
            )
        ):
            self._emitir("AVISO", linea)
            return

        # Subapartados dentro de cada fase.
        if linea.startswith("=== "):
            self._emitir(
                self.fase,
                linea,
                importante=True
            )
            return

        # Mensajes restantes: conservar su contenido.
        self._emitir(self.fase, linea)


def main():
    cfg.CONF(
        args=[],
        project="tesis_sdn"
    )

    cfg.CONF.set_override(
        "ofp_listen_host",
        "127.0.0.1"
    )

    cfg.CONF.set_override(
        "ofp_tcp_listen_port",
        6653
    )

    original = sys.stdout

    sys.stdout = ConsolaFORT(
        original,
        detalle=(
            os.environ.get(
                "FORT_CONSOLA_DETALLE", "0"
            ) == "1"
        )
    )

    try:
        print(
            "\n=== CONTROLADOR SDN - FORT V1 ===",
            flush=True
        )

        print(
            "OpenFlow 1.3 | Puerto 6653",
            flush=True
        )

        print(
            "Ejecucion:",
            (
                "ACTIVADA"
                if os.environ.get(
                    "FORT_EJECUTAR"
                ) == "1"
                else "DESACTIVADA"
            ),
            flush=True
        )

        print(
            "Modo:",
            os.environ.get(
                "FORT_MODO", "piloto"
            ),
            flush=True
        )

        print(
            "Consola:",
            (
                "DETALLADA"
                if os.environ.get(
                    "FORT_CONSOLA_DETALLE"
                ) == "1"
                else "RESUMIDA"
            ),
            flush=True
        )

        mgr = app_manager.AppManager.get_instance()

        mgr.load_apps([
            "os_ken.controller.ofp_handler",
            "RutasPrincipales",
            "AlgoritmoFORT",
            "MotorFORT",
            "PlanificadorFORT",
            "VerificadorOpenFlowFORT",
            "EjecutorFORT",
        ])

        ctx = mgr.create_contexts()

        servicios = mgr.instantiate_apps(
            **ctx
        )

        print(
            "FORT V1: FF -> captura -> Targets -> "
            "Transitions -> preflight -> ejecutor",
            flush=True
        )

        try:
            hub.joinall(servicios)

        except KeyboardInterrupt:
            print(
                "Deteniendo controlador...",
                flush=True
            )

        finally:
            mgr.close()

        print(
            "Controlador detenido.",
            flush=True
        )

    finally:
        if sys.stdout.pendiente:
            sys.stdout._mostrar(
                sys.stdout.pendiente
            )

        sys.stdout = original


if __name__ == "__main__":
    main()
