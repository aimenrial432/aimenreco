#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import pyfiglet
from .colors import CYAN, GREEN, YELLOW, WHITE, RED, RESET

def show_logo():
    """Imprime solo el logo ASCII y la versión."""
    ascii_banner = pyfiglet.figlet_format("AIMENRECO")
    print(f"{CYAN}{ascii_banner}{RESET}")
    print(f"{WHITE}v3.0 (Modular) - Advanced Recon & Secret Discovery Framework{RESET}\n")

class ManualHelpParser(argparse.ArgumentParser):
    """Personaliza la ayuda (-h) manteniendo la esencia de DirForcer v2"""
    def print_help(self):
        
        def fmt_line(short, long, metavar, desc):
            s_part = f"{GREEN}{short}{RESET}" if short else "  "
            comma = f"{WHITE},{RESET} " if short else "  "
            l_part = f"{CYAN}{long}{RESET}"
            m_part = f" {WHITE}{metavar}{RESET}" if metavar else ""
            full_flags = f"  {s_part}{comma}{l_part}{m_part}"
            padding = " " * (34 - (len(short or "") + len(long) + len(metavar or "") + (4 if short else 2)))
            print(f"{full_flags}{padding}{desc}")

        print(f"{YELLOW}Argumentos Obligatorios:{RESET}")
        fmt_line("-d", "--domain", "URL", "URL objetivo (ej: google.com)")
        fmt_line("-w", "--wordlist", "FILE", "Ruta al diccionario (o nombre en resources)")
        print(f"\n{YELLOW}Configuración de Ataque:{RESET}")
        fmt_line("-m", "--mode", "MODE", f"Modo: {GREEN}std{RESET} (40) o {RED}aggressive{RESET} (200)")
        fmt_line("-x", "--extensions", "EXT", "Extensiones (php,txt...)")
        fmt_line("-t", "--threads", "N", "Forzar número de hilos")
        print(f"\n{YELLOW}Salida y Visualización:{RESET}")
        fmt_line("-o", "--output", "FILE", "Guardar resultados en archivo")
        fmt_line("-h", "--help", "", "Muestra este manual de ayuda")