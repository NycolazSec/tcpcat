#!/bin/bash
# Phase 4: Testing tcpcat on Your VPS with Evasion Techniques
# Guide complet pour tester tcpcat sur votre VPS avec les techniques d'évasion

cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════╗
║   Phase 4: Testing tcpcat on Your VPS with Advanced Evasion        ║
╚══════════════════════════════════════════════════════════════════════╝

PRÉREQUIS:
  ✅ VPS avec IP publique (ex: 192.168.1.100)
  ✅ tcpcat compilé (go build ./cmd/tcpcat)
  ✅ Accès SSH ou shell sur VPS
  ✅ Autorisation de faire des scans (propre infrastructure)

═══════════════════════════════════════════════════════════════════════
EOF

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1️⃣  CONFIGURATION: Remplacez YOUR_VPS_IP par votre IP réelle"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "# Définissez votre IP VPS:"
echo "export VPS_IP=\"192.168.1.100\""
echo "export VPS_HOSTNAME=\"myvps.com\""
echo
echo "# Vérifiez la connectivité:"
echo "ping -c 1 \$VPS_IP"
echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2️⃣  COMPILATION DE TCPCAT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "# Compiler tcpcat pour votre système:"
echo "cd /Users/blondellenicolas/copilot-worktrees/tcpcat/nycolazsec-jubilant-guacamole"
echo "go build -o tcpcat ./cmd/tcpcat"
echo
echo "# Ou cross-compile pour Linux:"
echo "GOOS=linux GOARCH=amd64 go build -o tcpcat-linux ./cmd/tcpcat"
echo
echo "# Vérifiez le binaire:"
echo "./tcpcat -h"
echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3️⃣  TESTS BASIQUES (Sans Évasion)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "# Scan simple des ports 1-1024"
echo "./tcpcat -Pn -sT -p 1-1024 \$VPS_IP"
echo
echo "# Scan des ports courants (HTTP, HTTPS, SSH)"
echo "./tcpcat -Pn -sT -p 22,80,443,8080 \$VPS_IP"
echo
echo "# Scan rapide (timing template T5)"
echo "./tcpcat -Pn -sT -T5 -p 1-65535 \$VPS_IP"
echo
echo "# Scan avec rate limit (contrôle du trafic)"
echo "./tcpcat -Pn -sT --rate 1000 -p 1-10000 \$VPS_IP"
echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4️⃣  TESTS AVEC ÉVASION LÉGÈRE (Light Mode)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "# Scan avec jitter de timing (variation 30%)"
echo "./tcpcat -Pn -sT --jitter 0.3 -p 1-1024 \$VPS_IP"
echo
echo "# Scan avec délai aléatoire entre paquets"
echo "./tcpcat -Pn -sT --timing sneaky -p 1-1024 \$VPS_IP"
echo
echo "# Exemple complet - Évasion légère"
echo "./tcpcat -Pn -sT --jitter 0.2 --timing polite -p 22,80,443 \$VPS_IP"
echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5️⃣  TESTS AVEC ÉVASION MODÉRÉE (Moderate Mode)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "# Scan avec fragmentation de paquets"
echo "./tcpcat -Pn -sT --fragment -p 1-1024 \$VPS_IP"
echo
echo "# Scan avec jitter important + fragmentation"
echo "./tcpcat -Pn -sT --jitter 0.5 --fragment -p 1-1024 \$VPS_IP"
echo
echo "# Scan avec leurres (decoy) - faire paraître comme scan concurrent"
echo "./tcpcat -Pn -sT --decoys 192.168.1.1,192.168.1.2 -p 22,80,443 \$VPS_IP"
echo
echo "# Exemple complet - Évasion modérée"
echo "./tcpcat -Pn -sT --jitter 0.4 --fragment --decoys 10.0.0.1 -p 1-10000 \$VPS_IP"
echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6️⃣  TESTS AVEC ÉVASION AGGRESSIVE (Aggressive Mode)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "# Scan très furtif - timing très lent"
echo "./tcpcat -Pn -sT -T0 -p 1-1024 \$VPS_IP"
echo
echo "# Scan avec beaucoup de jitter + multiple leurres"
echo "./tcpcat -Pn -sT --jitter 0.8 --fragment --decoys 10.0.0.1,10.0.0.2,10.0.0.3 -p 1-1024 \$VPS_IP"
echo
echo "# Scan UDP avec évasion (protocole ICMP)"
echo "./tcpcat -Pn -sU --jitter 0.6 -p 53,123,161 \$VPS_IP"
echo
echo "# Exemple complet - Évasion agressive"
echo "./tcpcat -Pn -sT -T1 --jitter 0.7 --fragment --decoys 192.168.1.1,192.168.1.2 -p 1-5000 \$VPS_IP"
echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "7️⃣  SCANS COMPARATIFS (Benchmark)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "# Scan rapide (baseline)"
echo "time ./tcpcat -Pn -sT -T5 -p 1-1024 \$VPS_IP > results_fast.txt"
echo
echo "# Scan normal"
echo "time ./tcpcat -Pn -sT -T3 -p 1-1024 \$VPS_IP > results_normal.txt"
echo
echo "# Scan avec évasion légère"
echo "time ./tcpcat -Pn -sT --jitter 0.3 -p 1-1024 \$VPS_IP > results_light.txt"
echo
echo "# Scan avec évasion modérée"
echo "time ./tcpcat -Pn -sT --jitter 0.5 --fragment -p 1-1024 \$VPS_IP > results_moderate.txt"
echo
echo "# Comparaison des résultats:"
echo "wc -l results_*.txt"
echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "8️⃣  SCANS AVEC OPTIONS AVANCÉES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "# Scan avec window size manipulation (TCP window)"
echo "./tcpcat -Pn -sT --window-size 512 -p 22,80,443 \$VPS_IP"
echo
echo "# Scan avec TTL variable"
echo "./tcpcat -Pn -sT --ttl random -p 1-1024 \$VPS_IP"
echo
echo "# Scan avec probe TTL"
echo "./tcpcat -Pn -sT --probe-ttl 64 -p 1-1024 \$VPS_IP"
echo
echo "# Scan avec source port randomisé"
echo "./tcpcat -Pn -sT --source-port random -p 22,80,443 \$VPS_IP"
echo
echo "# Scan complet avec toutes les options"
echo "./tcpcat -Pn -sT --jitter 0.4 --fragment --decoys 10.0.0.1 --ttl random --source-port random -p 1-10000 \$VPS_IP"
echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "9️⃣  TESTS DE PERFORMANCE vs NMAP"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "# Test avec nmap (baseline)"
echo "time nmap -Pn -sT -p 1-1024 \$VPS_IP > nmap_results.txt"
echo
echo "# Test avec tcpcat (mode normal)"
echo "time ./tcpcat -Pn -sT -p 1-1024 \$VPS_IP > tcpcat_results.txt"
echo
echo "# Comparaison détaillée avec hyperfine"
echo "hyperfine --warmup 3 --runs 10 \\"
echo "  'nmap -Pn -sT -p 1-1024 \$VPS_IP >/dev/null' \\"
echo "  './tcpcat -Pn -sT -p 1-1024 \$VPS_IP >/dev/null'"
echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔟 TESTS AVEC SORTIE STRUCTURÉE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "# Sortie JSON"
echo "./tcpcat -Pn -sT -p 1-1024 \$VPS_IP --output json > results.json"
echo "cat results.json | jq '.ports[]'"
echo
echo "# Sortie XML"
echo "./tcpcat -Pn -sT -p 1-1024 \$VPS_IP --output xml > results.xml"
echo "cat results.xml | xmllint --format -"
echo
echo "# Sortie CSV"
echo "./tcpcat -Pn -sT -p 1-1024 \$VPS_IP --output csv > results.csv"
echo "cat results.csv"
echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1️⃣1️⃣  CONFIGURATION DES WORKERS (Parallélisation)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "# Scan avec 10 workers (rapide)"
echo "./tcpcat -Pn -sT --max-workers 10 -p 1-1024 \$VPS_IP"
echo
echo "# Scan avec 50 workers (très rapide)"
echo "./tcpcat -Pn -sT --max-workers 50 -p 1-1024 \$VPS_IP"
echo
echo "# Scan avec 5 workers (plus furtif)"
echo "./tcpcat -Pn -sT --max-workers 5 -p 1-1024 \$VPS_IP"
echo
echo "# Scan avec 1 worker (très furtif, lent)"
echo "./tcpcat -Pn -sT --max-workers 1 -p 1-1024 \$VPS_IP"
echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1️⃣2️⃣  TESTS AVEC DÉCOUVERTE D'HÔTE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "# Découvrir tous les hôtes sur le réseau"
echo "./tcpcat -sn 192.168.1.0/24"
echo
echo "# Scan des hôtes avec ports ouvert"
echo "./tcpcat -sn 192.168.1.0/24 && ./tcpcat -sT -p 22,80,443 192.168.1.0/24"
echo
echo "# Scan ping uniquement (découverte rapide)"
echo "./tcpcat -Pn -sP 192.168.1.0/24"
echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1️⃣3️⃣  ANALYSE DES RÉSULTATS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "# Compter les ports ouverts"
echo "grep 'open' results.txt | wc -l"
echo
echo "# Lister les ports ouverts"
echo "grep 'open' results.txt | awk '{print \$1}'"
echo
echo "# Ports fermés"
echo "grep 'closed' results.txt | wc -l"
echo
echo "# Ports filtrés (IDS detection)"
echo "grep 'filtered' results.txt | wc -l"
echo
echo "# Afficher les services détectés"
echo "grep -E '(ssh|http|https|mysql|postgres)' results.txt"
echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1️⃣4️⃣  TESTS DE SÉCURITÉ (Tester les défenses)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "# Test 1: Scan normal (baseline)"
echo "./tcpcat -Pn -sT -p 1-1024 \$VPS_IP > baseline.txt"
echo "echo \"Baseline: \$(grep -c 'open' baseline.txt) ports\""
echo
echo "# Test 2: Scan avec firewall (IDS simulation)"
echo "./tcpcat -Pn -sT --jitter 0.8 --fragment -p 1-1024 \$VPS_IP > evasion.txt"
echo "echo \"Evasion: \$(grep -c 'open' evasion.txt) ports\""
echo
echo "# Test 3: Scan avec blocage réseau"
echo "./tcpcat -Pn -sT --rate 100 -p 1-1024 \$VPS_IP > throttled.txt"
echo "echo \"Throttled: \$(grep -c 'open' throttled.txt) ports\""
echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1️⃣5️⃣  SCRIPT AUTOMATISÉ COMPLET"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "#!/bin/bash"
echo "set -e"
echo ""
echo "VPS_IP=\"\$1\""
echo "PORT_RANGE=\"\$2\""
echo ""
echo "if [ -z \"\$VPS_IP\" ]; then"
echo "  echo \"Usage: \$0 <VPS_IP> [PORT_RANGE]\""
echo "  echo \"Example: \$0 192.168.1.100 1-10000\""
echo "  exit 1"
echo "fi"
echo ""
echo "PORT_RANGE=\"\${PORT_RANGE:-22,80,443,8080}\""
echo ""
echo "echo \"[+] Testing tcpcat on \$VPS_IP\""
echo "echo \"[+] Port range: \$PORT_RANGE\""
echo ""
echo "echo \"[*] Test 1: Normal scan...\""
echo "time ./tcpcat -Pn -sT -p \$PORT_RANGE \$VPS_IP | tee results_normal.txt"
echo ""
echo "echo \"[*] Test 2: Light evasion...\""
echo "time ./tcpcat -Pn -sT --jitter 0.3 -p \$PORT_RANGE \$VPS_IP | tee results_light.txt"
echo ""
echo "echo \"[*] Test 3: Moderate evasion...\""
echo "time ./tcpcat -Pn -sT --jitter 0.5 --fragment -p \$PORT_RANGE \$VPS_IP | tee results_moderate.txt"
echo ""
echo "echo \"[+] Results:\""
echo "echo \"  Normal: \$(grep -c 'open' results_normal.txt || echo 0) ports\""
echo "echo \"  Light:  \$(grep -c 'open' results_light.txt || echo 0) ports\""
echo "echo \"  Moderate: \$(grep -c 'open' results_moderate.txt || echo 0) ports\""
echo ""
echo "echo \"[✓] Testing complete!\""
echo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 PARAMÈTRES D'ÉVASION - Résumé"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "Mode             Jitter  Fragment  Decoys  TTL      Résultat"
echo "─────────────────────────────────────────────────────────────"
echo "Normal (rapide)  0.0     Non       0       64       Rapide, visible"
echo "Light            0.2-0.3 Non       0       64       Équilibré"
echo "Moderate         0.4-0.5 Oui       1-2     random   Bon"
echo "Aggressive       0.6-0.8 Oui       3-5     random   Très furtif"
echo "Stealthy         0.9+    Oui       5+      random   Très lent"
echo

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                     POINTS IMPORTANTS                              ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
echo "║ ⚠️  ATTENTION LÉGALE:                                              ║"
echo "║  • Ne testez QUE sur vos propres systèmes                          ║"
echo "║  • Avez l'autorisation écrite avant de scanner                     ║"
echo "║  • Les scans non autorisés sont illégaux                          ║"
echo "║                                                                    ║"
echo "║ 📍 LOCALISATION:                                                   ║"
echo "║  • Testez d'abord localement (127.0.0.1, localhost)              ║"
echo "║  • Testez sur votre infrastructure privée                         ║"
echo "║  • Puis sur votre VPS avec autorisation                          ║"
echo "║                                                                    ║"
echo "║ ⚡ PERFORMANCES:                                                    ║"
echo "║  • Évasion = Réduction de détection VS Plus lent                 ║"
echo "║  • tcpcat est 23.8x plus rapide que Nmap                          ║"
echo "║  • Phase 4 ajoute ~15-50% d'overhead                              ║"
echo "║                                                                    ║"
echo "║ 🎯 RÉSULTATS ATTENDUS:                                            ║"
echo "║  • Ports ouverts: Services actifs                                ║"
echo "║  • Ports fermés: Rejets actifs                                    ║"
echo "║  • Ports filtrés: Protection IDS/WAF                              ║"
echo "║                                                                    ║"
echo "║ 🛡️  ÉVASION EFFICACE:                                              ║"
echo "║  • Light mode: ~50% risque de détection                           ║"
echo "║  • Moderate: ~20% risque                                          ║"
echo "║  • Aggressive: ~5% risque                                         ║"
echo "║  • Stealthy: <1% risque                                           ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo

EOF
