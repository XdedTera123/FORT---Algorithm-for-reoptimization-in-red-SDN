
#!/usr/bin/env python3
"""Captura coordinada de demandas, FS, PS y RS en Mininet."""

import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path.cwd()
HERRAMIENTAS = BASE / "herramientas"
ETAPA02 = BASE / "resultados/etapa02"
ETAPA03 = BASE / "resultados/etapa03"

sys.path.insert(0, str(HERRAMIENTAS))

from MedirDemandas import PERFIL, analizar
from ActualizarTopologia import puertos_ovs

DURACION = 45


def exigir(condicion, mensaje):
    if not condicion:
        raise RuntimeError(mensaje)


def leer(ruta):
    return json.loads(ruta.read_text(encoding="utf-8"))


def ejecutar_modulo(nombre, argumentos=None):
    argumentos = argumentos or []

    resultado = subprocess.run(
        [
            sys.executable,
            str(HERRAMIENTAS / nombre),
            *argumentos,
        ],
        cwd=BASE,
        capture_output=True,
        text=True,
    )

    if resultado.returncode != 0:
        raise RuntimeError(
            f"Error en {nombre}:\n"
            + resultado.stdout
            + resultado.stderr
        )

    return resultado.stdout


def fallo_actual():
    escenario = leer(BASE / "config/escenario.json")
    inventario = leer(
        BASE / "resultados/etapa01/puertos_detectados.json"
    )

    estados = {
        sw: puertos_ovs(sw)
        for sw in escenario["switches"]
    }

    fallos = []

    switches = set(escenario["switches"])

    for e in inventario:
        a, b = e["nodo_a"], e["nodo_b"]

        if a not in switches or b not in switches:
            continue

        pa = int(e["puerto_a"])
        pb = int(e["puerto_b"])

        exigir(
            pa in estados[a] and pb in estados[b],
            f"Puerto inexistente: {a}-{b}"
        )

        if not (estados[a][pa] and estados[b][pb]):
            fallos.append(sorted((a, b)))

    exigir(
        len(fallos) == 1,
        f"Se requiere un fallo unico: {fallos}"
    )

    return fallos[0]


def guardar(ruta, datos):
    ruta.parent.mkdir(parents=True, exist_ok=True)

    temporal = ruta.with_suffix(".json.tmp")
    temporal.write_text(
        json.dumps(datos, indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    temporal.replace(ruta)


def ejecutar(net):
    hosts = {h.name: h for h in net.hosts}
    fallo = fallo_actual()

    exigir(
        len(PERFIL) == 6
        and sum(f[2] == "TCP" for f in PERFIL) == 3
        and sum(f[2] == "UDP" for f in PERFIL) == 3,
        "Perfil experimental invalido",
    )

    inicio_id = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    carpeta = (
        ETAPA03 / "capturas_coordinadas" / inicio_id
    )
    carpeta.mkdir(parents=True, exist_ok=True)

    logs = carpeta / "logs"
    logs.mkdir()

    # Conservar copia de registros anteriores.
    respaldo = carpeta / "registros_anteriores"
    respaldo.mkdir()

    anteriores = [
        ETAPA02 / "FS_postfallo.json",
        ETAPA02 / "PS_postfallo.json",
        ETAPA02 / "RS_postfallo.json",
        ETAPA02 / "EstadoPostFallo.json",
        ETAPA03 / "DemandasObservadas_iperf2.json",
    ]

    for archivo in anteriores:
        if archivo.exists():
            shutil.copy2(
                archivo,
                respaldo / archivo.name
            )

    servidores = []
    clientes = []
    archivos = []

    print("\n=== CAPTURA COORDINADA POST-FALLO ===")
    print("Fallo observado:", " - ".join(
        x.upper() for x in fallo
    ))
    print("Perfil: 3 TCP + 3 UDP")
    print("Duracion:", DURACION, "segundos")

    try:
        for i, (_, destino, protocolo, _) in enumerate(
            PERFIL
        ):
            puerto = 5801 + i

            comando = [
                "iperf", "-s", "-p", str(puerto)
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

        inicio_trafico = datetime.now(
            timezone.utc
        ).isoformat()

        for i, (origen, destino, protocolo, tasa) in (
            enumerate(PERFIL)
        ):
            puerto = 5801 + i
            ruta_log = logs / f"F{i+1:02d}.log"
            archivo = ruta_log.open("w")
            archivos.append(archivo)

            comando = [
                "iperf",
                "-c", hosts[destino].IP(),
                "-p", str(puerto),
                "-t", str(DURACION),
                "-i", "2",
                "-b", f"{tasa}M",
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

        time.sleep(2)

        exigir(
            all(p.poll() is None for p in clientes),
            "Algun flujo termino antes de la captura"
        )

        print("Trafico iniciado: 6 flujos")

        marcas = {}

        for nombre, modulo, argumentos in (
            ("FS", "RegistrarFS.py", []),
            ("PS", "RegistrarPS.py", []),
            ("RS", "RegistrarRS.py", ["--intervalo", "5"]),
        ):
            marcas[nombre + "_inicio"] = (
                datetime.now(timezone.utc).isoformat()
            )

            ejecutar_modulo(modulo, argumentos)

            marcas[nombre + "_fin"] = (
                datetime.now(timezone.utc).isoformat()
            )

            exigir(
                all(p.poll() is None for p in clientes),
                f"El trafico termino durante {nombre}"
            )

            print(f"{nombre}: CAPTURADO CON TRAFICO ACTIVO")

        ejecutar_modulo(
            "ConstruirEstadoPostFallo.py"
        )
        print("FS + PS + RS: INTEGRADOS")

        for i, cliente in enumerate(clientes):
            cliente.wait(timeout=DURACION + 45)

            exigir(
                cliente.returncode == 0,
                f"F{i+1:02d} fallo: revisar logs"
            )

        for archivo in archivos:
            archivo.close()
        archivos.clear()

        fin_trafico = datetime.now(
            timezone.utc
        ).isoformat()

        registros = []

        for i, (origen, destino, protocolo, tasa) in (
            enumerate(PERFIL)
        ):
            datos = analizar(
                (logs / f"F{i+1:02d}.log").read_text(),
                protocolo
            )

            registros.append({
                "id": f"F{i+1:02d}",
                "origen": origen,
                "destino": destino,
                "protocolo": protocolo,
                "tasa_solicitada_mbps": tasa,
                **datos,
            })

        resultado = {
            "tipo": "DemandasObservadas_Piloto_iperf2",
            "id_captura": inicio_id,
            "inicio_utc": inicio_trafico,
            "fin_utc": fin_trafico,
            "enlace_fallado": fallo,
            "duracion_solicitada_s": DURACION,
            "cantidad_flujos": len(registros),
            "captura_coordinada": True,
            "marcas_captura": marcas,
            "nota": (
                "FS, PS y RS se capturaron secuencialmente "
                "durante la misma ejecucion de seis flujos. "
                "No son lecturas atomicas simultaneas."
            ),
            "flujos": registros,
        }

        guardar(
            ETAPA03 / "DemandasObservadas_iperf2.json",
            resultado
        )

        for nombre, archivo in (
            ("FS", ETAPA02 / "FS_postfallo.json"),
            ("PS", ETAPA02 / "PS_postfallo.json"),
            ("RS", ETAPA02 / "RS_postfallo.json"),
        ):
            dato = leer(archivo)
            fallos = dato["enlaces_fallados_observados"]

            exigir(
                len(fallos) == 1
                and sorted((
                    fallos[0]["extremo_a"],
                    fallos[0]["extremo_b"]
                )) == fallo,
                f"{nombre} no coincide con el fallo"
            )

            shutil.copy2(
                archivo,
                carpeta / archivo.name
            )

        for archivo in (
            ETAPA02 / "EstadoPostFallo.json",
            ETAPA03 / "DemandasObservadas_iperf2.json",
        ):
            shutil.copy2(
                archivo,
                carpeta / archivo.name
            )

        print("\n=== RESULTADOS ===")

        for f in registros:
            print(
                f'{f["id"]} {f["protocolo"]}: '
                f'{f["tasa_enviada_bps"]/1e6:.3f} Mbps'
            )

        print("Flujos registrados:", len(registros))
        print("Fallo FS + PS + RS: COINCIDENTE")
        print("Captura durante trafico: COMPLETADA")
        print("Capturas no atomicas: SI")
        print("Registros guardados:", carpeta)

    finally:
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
            archivo.close()


if __name__ == "__main__":
    ejecutar(net)
