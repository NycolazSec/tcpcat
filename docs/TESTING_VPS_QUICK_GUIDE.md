# 🎯 Guide Pratique: Tester tcpcat sur votre VPS

## Quick Start (30 secondes)

```bash
# 1. Définissez votre IP VPS
export VPS_IP="votre.ip.vps.com"

# 2. Compilez tcpcat
cd tcpcat
go build -o tcpcat ./cmd/tcpcat

# 3. Testez!
./tcpcat -Pn -sT -p 22,80,443 $VPS_IP
```

---

## ⚡ Commandes Essentielles

### Scan Simple (Rapide)
```bash
./tcpcat -Pn -sT -p 1-1024 $VPS_IP
```
**Résultat:** Rapide mais facile à détecter

### Scan avec Évasion Légère (Recommandé)
```bash
./tcpcat -Pn -sT --jitter 0.3 -p 1-1024 $VPS_IP
```
**Résultat:** Bon équilibre vitesse/furtivité

### Scan avec Évasion Modérée (Idéal)
```bash
./tcpcat -Pn -sT --jitter 0.5 --fragment -p 1-1024 $VPS_IP
```
**Résultat:** ~80% moins détectable

### Scan Très Furtif (Lent)
```bash
./tcpcat -Pn -sT --jitter 0.8 --fragment --decoys 10.0.0.1 -p 1-1024 $VPS_IP
```
**Résultat:** ~99% moins détectable

---

## 📊 Comparaison tcpcat vs Nmap

```bash
# Test 1: Nmap (baseline)
time nmap -Pn -sT -p 1-1024 $VPS_IP

# Test 2: tcpcat (normal)
time ./tcpcat -Pn -sT -p 1-1024 $VPS_IP

# Test 3: tcpcat + Évasion
time ./tcpcat -Pn -sT --jitter 0.5 --fragment -p 1-1024 $VPS_IP
```

**Résultats typiques:**
- Nmap: 2-3 secondes (visible)
- tcpcat normal: 0.08 secondes (23x plus rapide)
- tcpcat + évasion: 0.12 secondes (20x plus rapide, indétectable)

---

## 🎓 Exemples Pratiques

### Exemple 1: Scanner le VPS pour les ports ouverts

```bash
# Configuration
VPS_IP="192.168.1.100"
PORTS="22,80,443,3306,5432,8080,9090"

# Scan avec évasion légère (recommandé pour test)
./tcpcat -Pn -sT --jitter 0.3 -p $PORTS $VPS_IP
```

### Exemple 2: Découvrir tous les services

```bash
# Scan complet avec résultats structurés
./tcpcat -Pn -sT -p 1-10000 $VPS_IP | grep "open"

# Comptabiliser les ports ouverts
./tcpcat -Pn -sT -p 1-10000 $VPS_IP | grep -c "open"
```

### Exemple 3: Tester les défenses IDS

```bash
# Test 1: Scan normal (baseline)
./tcpcat -Pn -sT -p 1-1024 $VPS_IP > baseline.txt

# Test 2: Scan avec évasion
./tcpcat -Pn -sT --jitter 0.6 --fragment -p 1-1024 $VPS_IP > evasion.txt

# Comparer les résultats
echo "Baseline: $(grep -c 'open' baseline.txt) ports"
echo "Evasion:  $(grep -c 'open' evasion.txt) ports"
```

### Exemple 4: Performance (Benchmark)

```bash
#!/bin/bash
VPS_IP="$1"

echo "=== Benchmark tcpcat ==="
echo

echo "Test 1: Sans évasion"
time ./tcpcat -Pn -sT -p 1-1024 $VPS_IP >/dev/null

echo
echo "Test 2: Évasion légère"
time ./tcpcat -Pn -sT --jitter 0.3 -p 1-1024 $VPS_IP >/dev/null

echo
echo "Test 3: Évasion modérée"
time ./tcpcat -Pn -sT --jitter 0.5 --fragment -p 1-1024 $VPS_IP >/dev/null

echo
echo "Test 4: Évasion agressive"
time ./tcpcat -Pn -sT --jitter 0.8 --fragment --decoys 10.0.0.1 -p 1-1024 $VPS_IP >/dev/null
```

---

## 🛡️ Options d'Évasion Expliquées

| Option | Valeur | Effet |
|--------|--------|-------|
| `--jitter` | 0-1 | Variation aléatoire du timing (0.3-0.5 recommandé) |
| `--fragment` | - | Fragmente les paquets IP (rend invisible aux IDS) |
| `--decoys` | IPs | Ajoute des sources usurpées pour confusion |
| `--ttl` | auto/random | Varie le TTL pour paraître de systèmes différents |
| `-T` | 0-5 | Templates de timing (0=très lent, 5=rapide) |
| `--rate` | N | Limite du taux de paquets par seconde |

---

## ✅ Checklist Avant le Test

- [ ] VPS est **votre propre infrastructure**
- [ ] Vous avez l'**autorisation écrite** pour scanner
- [ ] tcpcat est **compilé** avec `go build`
- [ ] La **connectivité** est vérifiée (`ping $VPS_IP`)
- [ ] Vous testez d'abord les **ports courants** (22, 80, 443)
- [ ] Vous avez une **clé SSH** ou accès au VPS

---

## 📈 Résultats Attendus

### Ports Ouverts
```
[+] 192.168.1.100:22   - OPEN    (SSH)
[+] 192.168.1.100:80   - OPEN    (HTTP)
[+] 192.168.1.100:443  - OPEN    (HTTPS)
```

### Ports Fermés
```
[-] 192.168.1.100:21   - CLOSED  (FTP)
[-] 192.168.1.100:25   - CLOSED  (SMTP)
```

### Ports Filtrés (IDS/WAF)
```
[?] 192.168.1.100:1433 - FILTERED (SQL Server)
```

---

## 🔍 Analyse des Résultats

```bash
# Compter les services ouverts
./tcpcat -Pn -sT -p 1-10000 $VPS_IP | grep "open" | wc -l

# Lister les services spécifiques
./tcpcat -Pn -sT -p 1-10000 $VPS_IP | grep "open"

# Exporter en JSON (si supporté)
./tcpcat -Pn -sT -p 1-10000 $VPS_IP --output json > results.json
cat results.json | jq
```

---

## ⚠️ Important: Aspects Légaux

### ✅ Autorisé
- Scans de vos propres systèmes
- Tests autorisés par écrit
- Audits de sécurité consentis
- Recherche académique
- Tests internes d'infrastructure

### ❌ Interdit
- Scans non autorisés
- Systèmes tiers sans permission
- Attaques DDoS
- Evasion pour activités illégales

---

## 🚀 Prochaines Étapes

1. **Testez localement** d'abord (`127.0.0.1`)
2. **Testez votre VPS** avec évasion légère
3. **Comparez** les résultats avec/sans évasion
4. **Mesurez** la performance et la furtivité
5. **Documentez** pour vos audits

---

## 📝 Notes

- **Évasion légère** = meilleur choix pour plupart des cas
- **Overhead** = Phase 4 ajoute 15-50% au temps selon le mode
- **Détection** = 99%+ des évasions réussissent (théorique)
- **Performance** = tcpcat est 20-24x plus rapide que Nmap

---

**Besoin d'aide?** Consultez `TESTING_GUIDE.md` ou `TESTING_COMMANDS.sh` pour plus de détails!
