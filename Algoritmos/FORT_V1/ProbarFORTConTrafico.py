
#!/usr/bin/env python3
"""Prueba integral FORT bajo trafico concurrente.

Reutiliza el perfil iperf2 de la Etapa 03.
Provoca un fallo controlado y valida la captura
dinamica FS + PS + RS + demandas de FORT.

No modifica reglas OpenFlow ni grupos FF.
"""

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path.cwd()
sys.path.insert(0, str(BASE / "herramientas"))

from MedirDemandas import PERFIL, analizar

DURACION = 35
PUERTO_BASE = 6201

CAPTURAS = (
    BASE / "resultados/etapa06/fort_capturas_estado"
)

PRUEBAS = (
    BASE / "resultados/etapa06/fort_pruebas_trafico"
)


def ejecutar(net):
    assert len(PERFIL) == 6
    assert sum(f[2] == "TCP" for f in PERFIL) == 3
    assert sum(f[2] == "UDP" for f in PERFIL) == 3

    enlace = net.linksBetween(
        net.get("s1"),
        net.get("s2"),
    )

    if len(enlace) != 1:
        raise RuntimeError(
            "Se esperaba un unico enlace S1-S2"
        )

    if (
        enlace[0].intf1.isUp()
        or enlace[0].intf2.isUp()
    ):
        raise RuntimeError(
            "La prueba requiere S1-S2 inicialmente DOWN"
        )

    hosts = {
        h.name: h
        for h in net.hosts
    }

    for sw in (
        "s1", "s2", "s3", "s4",
        "s5", "s6", "s7", "s8",
    ):
        conectado = subprocess.check_output(
            [
                "ovs-vsctl",
                "get",
                "Controller",
                sw,
                "is_connected",
            ],
            text=True,
        ).strip()

        if conectado != "true":
            raise RuntimeError(
                f"OS-Ken desconectado de {sw}"
            )

    identificador = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    carpeta = PRUEBAS / identificador
    carpeta.mkdir(
        parents=True,
        exist_ok=False,
    )

    anteriores = {
        p.name
        for p in CAPTURAS.glob(
            "FORT_Estado_*.json"
        )
    }

    servidores = []
    clientes = []
    archivos = []

    enlace_tocado = False
    resultado = None

    print(
        "\n=== PRUEBA INTEGRAL FORT BAJO CARGA ===",
        flush=True,
    )
    print(
        "Flujos: 3 TCP + 3 UDP",
        flush=True,
    )
    print(
        "Duracion:",
        DURACION,
        "segundos",
        flush=True,
    )

    try:
        # Preparar los seis servidores iperf2.
        for i, (_, destino, protocolo, _) in enumerate(
            PERFIL
        ):
            comando = [
                "iperf",
                "-s",
                "-p",
                str(PUERTO_BASE + i),
            ]

            if protocolo == "UDP":
                comando.append("-u")

            servidores.append(
                hosts[destino].popen(
                    comando,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            )

        time.sleep(1)

        if any(
            p.poll() is not None
            for p in servidores
        ):
            raise RuntimeError(
                "Un servidor iperf termino"
            )

        # Recuperar el enlace para generar
        # un nuevo evento de fallo.
        net.configLinkStatus(
            "s1", "s2", "up"
        )
        enlace_tocado = True

        print(
            "S1-S2: UP",
            flush=True,
        )

        time.sleep(3)

        # Iniciar simultaneamente seis clientes.
        for i, (
            origen,
            destino,
            protocolo,
            tasa,
        ) in enumerate(PERFIL):
            ruta = carpeta / f"F{i + 1:02d}.log"

            archivo = ruta.open(
                "w",
                encoding="utf-8",
            )

            archivos.append(archivo)

            comando = [
                "iperf",
                "-c",
                hosts[destino].IP(),
                "-p",
                str(PUERTO_BASE + i),
                "-t",
                str(DURACION),
                "-i",
                "2",
                "-b",
                f"{tasa}M",
            ]

            if protocolo == "UDP":
                comando.append("-u")

            clientes.append(
                hosts[origen].popen(
                    comando,
                    stdout=archivo,
                    stderr=subprocess.STDOUT,
                )
            )

        time.sleep(4)

        if any(
            p.poll() is not None
            for p in clientes
        ):
            raise RuntimeError(
                "Un flujo termino antes del fallo"
            )

        print(
            "Seis flujos activos",
            flush=True,
        )

        # Inducir fallo durante el trafico.
        net.configLinkStatus(
            "s1", "s2", "down"
        )

        print(
            "S1-S2: DOWN",
            flush=True,
        )
        print(
            "Esperando captura automatica de FORT...",
            flush=True,
        )

        limite = time.monotonic() + 22
        archivo_fort = None

        while time.monotonic() < limite:
            nuevos = [
                p
                for p in CAPTURAS.glob(
                    "FORT_Estado_*.json"
                )
                if p.name not in anteriores
            ]

            if nuevos:
                archivo_fort = max(
                    nuevos,
                    key=lambda p: p.stat().st_mtime_ns,
                )

                try:
                    resultado = json.loads(
                        archivo_fort.read_text(
                            encoding="utf-8"
                        )
                    )
                    break

                except json.JSONDecodeError:
                    pass

            time.sleep(0.5)

        for cliente in clientes:
            cliente.wait(
                timeout=DURACION + 20
            )

        for archivo in archivos:
            archivo.close()

        archivos.clear()

        print(
            "\n=== TRAFICO IPERF2 ===",
            flush=True,
        )

        for i, (
            origen,
            destino,
            protocolo,
            tasa,
        ) in enumerate(PERFIL):
            ruta = carpeta / f"F{i + 1:02d}.log"

            try:
                datos = analizar(
                    ruta.read_text(
                        encoding="utf-8"
                    ),
                    protocolo,
                )

                print(
                    f"F{i + 1:02d}: "
                    f"{origen}->{destino} "
                    f"{protocolo} | "
                    f"Solicitado: {tasa} Mbps | "
                    "Enviado: "
                    f"{datos['tasa_enviada_bps']/1e6:.3f} Mbps",
                    flush=True,
                )

            except (
                RuntimeError,
                ValueError,
                KeyError,
            ) as error:
                print(
                    f"F{i + 1:02d}: "
                    f"log conservado, "
                    f"resumen no disponible: {error}",
                    flush=True,
                )

        if resultado is None:
            print(
                "\nFORT: no se encontro una "
                "nueva captura consolidada",
                flush=True,
            )
            print(
                "Revisar la consola de OS-Ken",
                flush=True,
            )

        else:
            print(
                "\n=== ESTADO DINAMICO FORT ===",
                flush=True,
            )

            print(
                "Fallo:",
                resultado["fallo"],
                flush=True,
            )

            print(
                "FS comunicaciones:",
                resultado["fs"]["cantidad"],
                flush=True,
            )

            print(
                "PS grupos FF:",
                resultado["ps"]["cantidad_grupos_ff"],
                flush=True,
            )

            print(
                "RS direcciones operativas:",
                resultado["rs"][
                    "cantidad_direcciones_operativas"
                ],
                flush=True,
            )

            mlu = resultado["rs"][
                "maxima_utilizacion_observada_pct"
            ]

            print(
                "MLU OBSERVADA:",
                mlu,
                "%",
                flush=True,
            )

            activas = resultado["demandas"][
                "comunicaciones_con_trafico"
            ]

            print(
                "Demandas IPv4 activas:",
                activas,
                "/12",
                flush=True,
            )

            print(
                "Archivo FORT:",
                archivo_fort,
                flush=True,
            )

            if mlu <= 0:
                print(
                    "ALERTA: sin carga observada",
                    flush=True,
                )

            if activas <= 0:
                print(
                    "ALERTA: sin demandas IPv4",
                    flush=True,
                )

        print(
            "Logs del ensayo:",
            carpeta,
            flush=True,
        )

    finally:
        # Conservar el fallo original.
        if enlace_tocado:
            net.configLinkStatus(
                "s1", "s2", "down"
            )

        # Detener los procesos de prueba.
        for proceso in clientes + servidores:
            if proceso.poll() is None:
                proceso.terminate()

        for proceso in clientes + servidores:
            if proceso.poll() is None:
                try:
                    proceso.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proceso.kill()

        for archivo in archivos:
            if not archivo.closed:
                archivo.close()


if __name__ == "__main__":
    ejecutar(net)
