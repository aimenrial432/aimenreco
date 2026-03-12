#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DirForcer UI - Terminal Color Palette
-------------------------------------
Este módulo define la identidad visual de DirForcer v3.

Creador: Oier Garcia
"""

# --- CÓDIGOS ANSI BASE ---
# Definimos los colores base para construir la interfaz
GREEN  = "\033[1;32m"  # Éxito (Directorios encontrados)
RED    = "\033[1;31m"  # Errores (404, Timeouts, Fallos de red)
YELLOW = "\033[1;33m"  # Avisos (Detección de Wildcards, Interrupciones)
BLUE   = "\033[1;34m"  # Información (Configuración de hilos, carga de wordlist)
CYAN   = "\033[1;36m"  # Estética (Banners y títulos)
WHITE  = "\033[1;37m"  # Resaltado (URLs, rutas encontradas)
GREY   = "\033[1;90m"  # Detalles (Barra de progreso, IDs de hilos)
RESET  = "\033[0m"     # Reset (Indispensable para no manchar la consola)

# --- MAPEO SEMÁNTICO (Lógica de la herramienta) ---
# Facilita que, si se cambia el color aquí, cambie en todo el programa.
CLR_SUCCESS = GREEN
CLR_ERROR   = RED
CLR_WARN    = YELLOW
CLR_INFO    = CYAN
CLR_PATH    = WHITE
CLR_METRIC  = GREY

# --- PRESETS DE MENSAJERÍA ---
# Etiquetas preformateadas para mantener la consistencia en los prints
# Uso: print(f"{MSG_FOUND} {url}")
MSG_FOUND = f"{WHITE}[{GREEN}+{WHITE}]{RESET}"
MSG_ERROR = f"{WHITE}[{RED}!{WHITE}]{RESET}"
MSG_INFO  = f"{WHITE}[{CYAN}i{WHITE}]{RESET}"
MSG_WAIT  = f"{WHITE}[{YELLOW}*{WHITE}]{RESET}"
MSG_STEP  = f"{GREY}[{WHITE}#{GREY}]{RESET}"