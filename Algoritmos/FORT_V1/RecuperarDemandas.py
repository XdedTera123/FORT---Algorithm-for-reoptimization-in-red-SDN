
#!/usr/bin/env python3
"""Recuperar demandas desde logs iperf2 conservados."""

import json
import math
from datetime import datetime, timezone
from pathlib import Path

from MedirDemandas import PERFIL, analizar

BASE = Path(__file__).resolve().parents[1]
RAIZ = BASE / "resultados/etapa03/capturas_coordinadas"


def exigir(condicion, mensaje):
    if not condicion:
        raise RuntimeError(mensaje)


def main():
    carpetas = sorted(
        (
            p for p in RAIZ.iterdir()
            if p.is_dir()
            and all(
                (p / "logs" / f"F{i:02d}.log").is_file()
                for i in range(1, len(PERFIL) + 1)
            )
        ),
        reverse=True
    )

    exigir(bool(carpetas), "No hay logs completos")

    carpeta = carpetas[0]

    for nombre in (
        "FS_postfallo.json",
        "PS_postfallo.json",
        "RS_postfallo.json",
        "EstadoPostFallo.json",
    ):
        exigir(
            (carpeta / nombre).is_file(),
            f"Falta respaldo: {nombre}"
        )

    flujos = []
    invalidos = []

    for i, (origen, destino, protocolo, tasa) in enumerate(
        PERFIL, start=1
    ):
        identificador = f"F{i:02d}"
        ruta = carpeta / "logs" / f"{identificador}.log"
        texto = ruta.read_text(
            encoding="utf-8", errors="replace"
        )

        receptor_valido = True
        observacion = None

        try:
            datos = analizar(texto, protocolo)
        except RuntimeError as error:
            exigir(
                protocolo == "UDP",
                f"{identificador}: {error}"
            )

            # Recuperar SOLO las estadisticas del emisor.
            texto_emisor = texto.split(
                "Server Report:", 1
            )[0]

            datos = analizar(texto_emisor, "TCP")
            receptor_valido = False
            observacion = str(error)
            invalidos.append(identificador)

        enviado = datos["tasa_enviada_bps"]

        exigir(
            math.isfinite(enviado)
            and enviado >= 0
            and datos["duracion_real_s"] > 0,
            f"Medicion del emisor invalida: {identificador}"
        )

        flujos.append({
            "id": identificador,
            "origen": origen,
            "destino": destino,
            "protocolo": protocolo,
            "tasa_solicitada_mbps": tasa,
            **datos,
            "receptor_valido": receptor_valido,
            "observacion": observacion,
            "log_original": str(ruta.relative_to(BASE)),
        })

    resultado = {
        "tipo": "DemandasRecuperadas_Piloto",
        "id_captura": carpeta.name,
        "recuperado_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "cantidad_flujos": len(flujos),
        "flujos_con_receptor_invalido": invalidos,
        "recepcion_completa_validada": not invalidos,
        "nota": (
            "Las tasas enviadas proceden de logs iperf2. "
            "Las estadisticas invalidas del receptor "
            "se conservan como datos no disponibles. "
            "No utilizar esta captura como validacion "
            "experimental definitiva."
        ),
        "flujos": flujos,
    }

    salida = carpeta / "DemandasRecuperadas.json"
    temporal = salida.with_suffix(".json.tmp")

    temporal.write_text(
        json.dumps(
            resultado, indent=2, ensure_ascii=False
        ) + "\n",
        encoding="utf-8"
    )
    temporal.replace(salida)

    print("\n=== RECUPERACION DE DEMANDAS ===")

    for flujo in flujos:
        recibido = flujo["tasa_recibida_bps"]

        print(
            f'{flujo["id"]} {flujo["protocolo"]}: '
            f'Enviado={flujo["tasa_enviada_bps"]/1e6:.3f} Mbps | '
            + (
                f'Recibido={recibido/1e6:.3f} Mbps'
                if recibido is not None
                else "Recibido=NO DISPONIBLE"
            )
        )

    print("Flujos recuperados:", len(flujos))
    print("Receptores invalidos:", invalidos)
    print("Archivo generado:", salida)


if __name__ == "__main__":
    main()
