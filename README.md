# 🛡️ DirForcer v4.0 (En Desarrollo)

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Category](https://img.shields.io/badge/category-Pentesting-red)
![Status](https://img.shields.io/badge/status-In--Development-yellow)

```text
    ____  _      ______
   / __ \(_)____/ ____/___  _____________  _____
  / / / / / ___/ /_  / __ \/ ___/ ___/ _ \/ ___/
 / /_/ / / /  / __/ / /_/ / /  / /__/  __/ /
/_____/_/_/  /_/    \____/_/   \___/\___/_/


DirForcer es un fuzzer de directorios y archivos de alto rendimiento diseñado para la fase de enumeración en auditorías de seguridad. Su arquitectura modular y su motor multihilo permiten una velocidad excepcional con una precisión quirúrgica.

⚠️ NOTA: Esta herramienta se encuentra actualmente en fase de desarrollo. Se están añadiendo nuevas funcionalidades y optimizando el motor constantemente.


🚀 Características Principales
🔍 Wildcard Detection: Identifica comportamientos de DNS/HTTP comodín para eliminar falsos positivos antes de empezar.

⚡ High-Speed Multi-threading: Motor optimizado con gestión de colas para manejar cientos de peticiones por segundo.

🎨 Professional UI: Interfaz limpia con barra de progreso dinámica y hallazgos en tiempo real.

📦 Modular & Portable: Estructura de paquete estándar para una instalación limpia y global en sistemas Linux.



🛠️ Instalación y Configuración
    1. Clonar y Dependencias

        git clone [https://github.com/tu-usuario/dirforcer_v2.git](https://github.com/tu-usuario/dirforcer_v2.git)
        cd dirforcer_v2
        pip install -r requirements.txt

    2. Instalación en el Sistema (Recomendado)

        Para poder ejecutar dirforcer desde cualquier ruta y con privilegios de root:
            sudo pip install .

📖 Guía de Uso

    sudo dirforcer -d <URL> -w <WORDLIST> [OPCIONES]


💡 Ejemplos de Uso

    Escaneo básico:
        sudo dirforcer -d target.com -w common.txt


📁 Estructura del Proyecto
    dirforcer_v2/
    ├── dirforcer/          # Paquete principal
    │   ├── core/           # Motor de escaneo y lógica Wildcard
    │   ├── ui/             # Interfaz, colores y banners
    │   ├── utils/          # Helpers y cargador de recursos
    │   └── cli.py          # Punto de entrada (Entry point)
    ├── setup.py            # Script de instalación
    ├── requirements.txt    # Dependencias de Python
    └── README.md           # Documentación


⚖️ Descargo de Responsabilidad
    El empleo de la herramienta para atacar objetivos sin la autorización adecuada es ilícito. Cada usuario debe asegurarse de seguir todas las normativas locales, estatales y federales que correspondan. El creador no se hace cargo de ninguna culpa ni es responsable por el uso indebido o los daños provocados por el mal uso de esta herramienta.
```
