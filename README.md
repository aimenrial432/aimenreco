# 🛡️ Aimenreco v3.0 (Modular Framework en desarrollo)

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Category](https://img.shields.io/badge/category-Pentesting-red)
![Status](https://img.shields.io/badge/status-Development--Branch-orange)

```text
    _   ___ __  __ _____ _   _ ____  _____ ____ ___
   / \ |_ _|  \/  | ____| \ | |  _ \| ____/ ___/ _ \
  / _ \ | || |\/| |  _| |  \| | |_) |  _|| |  | | | |
 / ___ \| || |  | | |___| |\  |  _ <| |__| |__| |_| |
/_/   \_\___|_|  |_|_____|_| \_|_| \_\_____\____\___/


Aimenreco es un framework de reconocimiento avanzado y descubrimiento de activos diseñado para auditores de seguridad. A diferencia de los fuzzers tradicionales.
Aimenreco combina inteligencia pasiva (OSINT) con un motor de enumeración activa de alto rendimiento.

⚠️ NOTA: Esta herramienta se encuentra actualmente en fase de desarrollo. Se están añadiendo nuevas funcionalidades y optimizando el motor constantemente.

⚠️ NOTA: Estás en la rama dev. Esta versión incluye el nuevo motor modular y funciones de reconocimiento pasivo.


🚀 Características Principales
🔍 Wildcard Detection: Identifica comportamientos de DNS/HTTP comodín para eliminar falsos positivos antes de empezar.

⚡ High-Speed Multi-threading: Motor optimizado con gestión de colas para manejar cientos de peticiones por segundo.

🎨 Professional UI: Interfaz limpia con barra de progreso dinámica y hallazgos en tiempo real.

📦 Modular & Portable: Estructura de paquete estándar para una instalación limpia y global en sistemas Linux.



🛠️ Instalación y Configuración
    1. Clonar y Dependencias

        git clone [https://github.com/aimenrial432/aimenreco.git](https://github.com/aimenrial432/aimenreco.git)
        cd aimenreco
        git checkout dev
        pip install -r requirements.txt

    2. Instalación en el Sistema (Recomendado)

        Para poder ejecutar dirforcer desde cualquier ruta y con privilegios de root ademas de que sea modo editable:
            sudo pip install -e . --break-system-packages

📖 Guía de Uso

    sudo aimenreco -d <URL> -w <WORDLIST> [OPCIONES]


💡 Ejemplos de Uso

    Escaneo básico:
        sudo aimenreco -d target.com -w common.txt


📁 Estructura del Proyecto
    aimenreco/
    ├── aimenreco/          # Paquete principal
    │   ├── core/           # Motor de escaneo y lógica Wildcard
    │   ├── ui/             # Interfaz, colores y banners
    │   ├── utils/          # Helpers y cargador de recursos
    │   └── cli.py          # Punto de entrada (Entry point)
    ├── setup.py            # Script de instalación
    ├── requirements.txt    # Dependencias de Python
    └── README.md           # Documentación
    └── CHANGELOG.md        # Cambios realizados en la herramienta


⚖️ Descargo de Responsabilidad
    El empleo de la herramienta para atacar objetivos sin la autorización adecuada es ilícito. Cada usuario debe asegurarse de seguir todas las normativas locales, estatales y federales que correspondan. El creador no se hace cargo de ninguna culpa ni es responsable por el uso indebido o los daños provocados por el mal uso de esta herramienta.
```
