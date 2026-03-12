#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

def get_resource_path(relative_path):
    """
    Localiza los diccionarios dentro de la carpeta 'resources'.
    
    Esta función calcula la ubicación real del proyecto en tu disco duro
    para que siempre encuentre los archivos, sin importar desde dónde
    se lance el comando en la terminal.
    
    En este caso se ha usado un archivo de ejemplo que es el common.txt situado en resources
    """
    # 1. Obtenemos la ruta absoluta de donde está instalado ESTE archivo (helpers.py)
    # Ejemplo: dirforcer/utils/helpers.py
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # 2. Subimos un nivel para salir de 'utils' y llegar a la carpeta raíz 'dirforcer'
    project_root = os.path.dirname(current_dir)

    # 3. Construimos la ruta final entrando en 'resources'
    # Ejemplo: /home/oier/proyectos/dirforcer/resources/common.txt
    return os.path.join(project_root, "resources", relative_path)

def clean_url(url):
    """
    Limpia la URL para que el motor no de errores .
    Quita espacios, barras finales y asegura que lleve http/https.
    """
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    return url

def load_wordlist(filename):
    """
    Carga el diccionario usando la ruta inteligente.
    """
    # Usamos la función de busqueda del diccionario para saber donde esta el diccionario realmente
    full_path = get_resource_path(filename)
    
    if not os.path.exists(full_path):
        print(f"[!] Error: No se encuentra el archivo mencionado en {full_path}")
        return None
    
    with open(full_path, 'r', encoding="utf-8", errors="ignore") as f:
        # Quitamos espacios y saltos de línea de cada palabra
        return [line.strip() for line in f if line.strip()]