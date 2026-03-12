#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import os

# Importaciones de tus módulos locales
from aimenreco.ui.banners import ManualHelpParser, show_logo
from aimenreco.ui.colors import CYAN, WHITE, GREEN, RED, BLUE, YELLOW, RESET, GREY
from aimenreco.utils.helpers import clean_url, load_wordlist
from aimenreco.core.wildcard import WildcardAnalyzer 
from aimenreco.core.scanner import Scanner

def main():
    # --- CHEQUEO DE PRIVILEGIOS ---
    if os.geteuid() != 0:
        show_logo()
        print(f"{RED}[!] Error: Aimenreco requiere privilegios de superusuario (root).{RESET}")
        print(f"{YELLOW}[i] Intenta ejecutar: sudo aimenreco <argumentos>{RESET}\n")
        sys.exit(1)
    
    # --- PASO 0: EL LOGO ---
    show_logo()
    
    parser = ManualHelpParser(add_help=False)
    parser.add_argument("-d", "--domain")
    parser.add_argument("-w", "--wordlist")
    parser.add_argument("-m", "--mode", default="std")
    parser.add_argument("-x", "--extensions", default="")
    parser.add_argument("-t", "--threads", type=int)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("-o", "--output")
    parser.add_argument("-h", "--help", action="store_true")

    args = parser.parse_args()

    if args.help or not args.domain or not args.wordlist:
        parser.print_help()
        sys.exit(1)

    url = clean_url(args.domain)
    threads = args.threads or (200 if args.mode == "aggressive" else 40)
    
    print("-" * 80)
    print(f"{CYAN}Target: {url} | Hilos: {threads} | Modo: {args.mode.upper()}{RESET}")
    print("-" * 80)
    
    # --- PASO 1: ANÁLISIS DE RED (WILDCARD) ---
    analyzer = WildcardAnalyzer(url, args.timeout)
    w_data = analyzer.check() 
    
    # --- PASO 2: CARGAR DICCIONARIO BASE ---
    words = load_wordlist(args.wordlist)
    if not words:
        print(f"{RED}[!] Error: No se pudo cargar el diccionario.{RESET}")
        sys.exit(1)
    
    # Preparamos la lista de extensiones SOLO si vienen por argumento
    # Si no, pasamos None para que el Scanner use su archivo por defecto
    ext_list = None
    if args.extensions:
        ext_list = [e.strip() for e in args.extensions.split(",")]

    # --- PASO 3: LANZAR ESCANEO ---
    # Pasamos ext_list al constructor
    scanner = Scanner(url, threads, args.timeout, w_data, extensions_arg=ext_list)
    start_time = time.time()
    
    try:
        # IMPORTANTE: Le pasamos 'words' (el base). 
        # El método scanner.run() se encargará de llamar a prepare_wordlist()
        results = scanner.run(words)
    except KeyboardInterrupt:
        # El Scanner ya maneja el KeyboardInterrupt internamente, 
        # pero esto es un seguro extra.
        results = scanner.results 

    # --- PASO 4: FINALIZACIÓN Y GUARDADO ---
    duration = time.time() - start_time
    print(f"\n" + "-" * 80)
    print(f"{GREEN}[✓] Finalizado en {duration:.2f}s | Hallazgos: {len(results)}{RESET}")
    
    if args.output and results:
        try:
            with open(args.output, "w") as f_out:
                for r in results: 
                    f_out.write(r + "\n")
            print(f"{BLUE}[i] Resultados guardados en: {args.output}{RESET}")
        except Exception as e:
            print(f"{RED}[!] Error al guardar el archivo: {e}{RESET}")
    print("-" * 80 + "\n")

if __name__ == "__main__":
    main()