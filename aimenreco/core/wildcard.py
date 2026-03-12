#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import random
import hashlib
import json
from collections import Counter

# Importaciones relativas del proyecto
from aimenreco.ui.colors import YELLOW, GREY, WHITE, CYAN, RED, RESET, GREEN
from aimenreco.utils.helpers import get_resource_path

class WildcardAnalyzer:
    """
    Analizador de ADN de red para identificar comportamientos de Catch-all.
    """
    def __init__(self, target_url, timeout=5):
        self.target_url = target_url
        self.timeout = timeout
        self.user_agents = self._load_json_resource("user_agents.json", ["DirForcer/4.0"])

    def _load_json_resource(self, filename, fallback):
        path = get_resource_path(filename)
        try:
            with open(path, 'r', encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return fallback

    def check(self):
        """Realiza 10 tests de ADN para identificar Wildcards por Status y Tamaño promedio."""
        metrics = []
        print(f"{YELLOW}[*] Analizando métricas de red (10 Pruebas de ADN):{RESET}")
        
        for i in range(1, 11):
            random_path = f"wildcard_{random.getrandbits(24)}"
            test_url = f"{self.target_url}/{random_path}"
            try:
                headers = {"User-Agent": random.choice(self.user_agents)}
                r = requests.get(test_url, timeout=self.timeout, headers=headers, 
                                 allow_redirects=False, verify=False)
                
                c_hash = hashlib.md5(r.content).hexdigest()
                size = len(r.content)
                
                print(f"  {GREY}Test {i:02d}:{RESET} {WHITE}/{random_path:<20}{RESET} "
                      f"Status: {CYAN}{r.status_code}{RESET} | Size: {CYAN}{size}{RESET}")
                
                metrics.append({'size': size, 'hash': c_hash, 'status': r.status_code})
            except Exception as e:
                print(f"  {RED}[!] Test {i:02d} fallido: {e}{RESET}")

        if not metrics: return False, None, 0

        # Lógica de detección agresiva:
        # 1. Contamos los status codes
        s_counts = Counter([m['status'] for m in metrics])
        m_status, s_count = s_counts.most_common(1)[0]
        
        # 2. Si el 80% devuelven el mismo status de éxito o redirección (caso maristak)
        if s_count >= 8 and m_status in {200, 301, 302}:
            # Calculamos el hash más común y el tamaño PROMEDIO
            h_counts = Counter([m['hash'] for m in metrics])
            m_hash = h_counts.most_common(1)[0][0]
            avg_size = sum([m['size'] for m in metrics]) / len(metrics)
            
            print(f"\n  {RED}[!] ALERTA WILDCARD DETECTADO (Status común: {m_status}){RESET}")
            return True, m_hash, int(avg_size)
        
        print(f"\n  {GREEN}[✓] Servidor estable: Sin Wildcard.{RESET}\n")
        return False, None, 0