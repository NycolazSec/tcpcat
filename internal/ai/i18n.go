package ai

import "fmt"

// messages holds every sentence the AI writes, in English and French.
var messages = map[string][2]string{
	"summary": {"%d to fix, %d to review, %d as expected.", "%d à corriger, %d à vérifier, %d normaux."},

	"title-private":        {"%s is reachable from the internet", "%s est joignable depuis Internet"},
	"title-restricted":     {"%s is reachable from the internet: limit who can reach it", "%s est joignable depuis Internet : limitez qui peut l'atteindre"},
	"title-public":         {"%s is public, as expected", "%s est public, c'est normal"},
	"title-internal":       {"%s is reachable from this network", "%s est joignable depuis ce réseau"},
	"title-internal-check": {"%s is reachable from this network: make sure it requires a login", "%s est joignable depuis ce réseau : vérifiez qu'il exige une authentification"},
	"title-unknown":        {"Unknown service on port %d", "Service inconnu sur le port %d"},
	"title-unlisted":       {"%s on port %d (not in the dictionary)", "%s sur le port %d (absent du dictionnaire)"},
	"title-kev":            {"%s has a vulnerability exploited in the wild", "%s a une faille exploitée par des attaquants"},
	"title-vuln":           {"%s has a serious known vulnerability", "%s a une faille connue grave"},
	"title-middlebox":      {"Port %d: the answer probably comes from your own network, not from this host", "Port %d : la réponse vient probablement de votre propre réseau, pas de cette machine"},
	"why-middlebox": {"A reply much faster than the host's other replies cannot have travelled to the host and back; a router, firewall or proxy on the path answered instead (FTP helpers on home routers do this).",
		"Une réponse bien plus rapide que les autres n'a pas pu faire l'aller-retour jusqu'à la machine ; un routeur, un pare-feu ou un proxy sur le chemin a répondu à sa place (les assistants FTP des box font cela)."},
	"fix-middlebox": {"Check this port again from another network (a phone hotspot, a cloud machine) before acting on it.",
		"Revérifiez ce port depuis un autre réseau (partage de connexion du téléphone, machine dans le cloud) avant d'agir."},
	"title-vuln-medium": {"%s has known flaws to patch", "%s a des failles connues à corriger"},
	"to-confirm":        {" (to be confirmed)", " (à confirmer)"},

	"why-vuln": {"A known flaw of this version is rated %s out of 10.", "Une faille connue de cette version est notée %s sur 10."},
	"why-unknown": {"Neither the probes, the model nor the dictionary could name it: something listens there that you may not know about.",
		"Ni les sondes, ni le modèle, ni le dictionnaire n'ont pu l'identifier : quelque chose écoute là, peut-être à votre insu."},

	"fix-private": {"Close port %d to the internet: make the service listen on 127.0.0.1 or a private address, or drop the port in the firewall (nft add rule inet filter input tcp dport %[1]d drop).",
		"Fermez le port %d à Internet : faites écouter le service sur 127.0.0.1 ou une adresse privée, ou bloquez le port au pare-feu (nft add rule inet filter input tcp dport %[1]d drop)."},
	"fix-restricted": {"Allow port %d only from addresses you trust (firewall allow-list) or through a VPN.",
		"N'autorisez le port %d que depuis des adresses de confiance (liste blanche du pare-feu) ou via un VPN."},
	"fix-internal": {"Check that it asks for a password or a certificate, even on the internal network.",
		"Vérifiez qu'il demande un mot de passe ou un certificat, même sur le réseau interne."},
	"fix-unknown": {"Find what listens on port %d (on the host: ss -ltnp 'sport = :%[1]d', or tcpcat inventory) and close it if nobody needs it.",
		"Trouvez ce qui écoute sur le port %d (sur la machine : ss -ltnp 'sport = :%[1]d', ou tcpcat inventory) et fermez-le si personne n'en a besoin."},
	"fix-update": {"Update %s to a version where these flaws are fixed.", "Mettez à jour %s vers une version qui corrige ces failles."},

	"ev-open":        {"port %d open (%s)", "port %d ouvert (%s)"},
	"ev-banner":      {"banner: %s", "bannière : %s"},
	"ev-probe":       {"a protocol probe identified %s", "une sonde de protocole a identifié %s"},
	"ev-model":       {"the banner model recognises %s (%d%% sure)", "le modèle reconnaît %s dans la bannière (sûr à %d %%)"},
	"ev-port":        {"identified only by its port: %d is the usual port of %s", "identifié seulement par son port : %d est le port habituel de %s"},
	"ev-alt":         {"this port is also used by: %s", "ce port sert aussi à : %s"},
	"ev-disagree":    {"the detector named it %q; the evidence above wins", "le détecteur l'avait nommé %q ; les preuves ci-dessus l'emportent"},
	"ev-cleartext":   {"the protocol sends passwords and data in clear text", "le protocole transmet mots de passe et données en clair"},
	"ev-refined":     {"port %d is where %s usually runs", "le port %d est celui qu'utilise habituellement %s"},
	"ev-posture":     {"the probes also noted: %s", "les sondes ont aussi relevé : %s"},
	"ev-more":        {"%d more", "%d de plus"},
	"ev-middlebox":   {"this port answered in %.0f ms, the host's other ports in about %.0f ms", "ce port a répondu en %.0f ms, les autres ports de la machine en %.0f ms environ"},
	"ev-client-side": {"%d other known flaws concern only the client programs (ssh, scp, sftp), not this server", "%d autres failles connues ne concernent que les programmes clients (ssh, scp, sftp), pas ce serveur"},
	"ev-vulns":       {"known vulnerabilities for this version: %d, the most serious: %s", "failles connues pour cette version : %d, les plus graves : %s"},
	"ev-kev":         {"in CISA's catalog of exploited vulnerabilities: %s", "dans le catalogue CISA des failles exploitées : %s"},
}

func tr(lang, key string, args ...any) string {
	m, ok := messages[key]
	if !ok {
		return key
	}
	f := m[0]
	if lang == "fr" {
		f = m[1]
	}
	if len(args) == 0 {
		return f
	}
	return fmt.Sprintf(f, args...)
}
