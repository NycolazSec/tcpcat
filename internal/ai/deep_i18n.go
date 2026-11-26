package ai

func init() {
	for k, v := range map[string][2]string{
		"title-internal-verified": {"%s is reachable from this network and refuses anonymous clients", "%s est joignable depuis ce réseau et refuse les clients anonymes"},
		"progress":                {"checking %d (%s)…", "je vérifie %d (%s)…"},

		"chk-ssh-none":     {"accepts logins with no authentication at all", "accepte les connexions sans aucune authentification"},
		"fix-ssh-none":     {"Require public-key authentication on this server immediately.", "Exigez tout de suite une authentification par clé sur ce serveur."},
		"chk-ssh-password": {"accepts password logins (%s): bots can try to guess them", "accepte la connexion par mot de passe (%s) : des robots peuvent essayer de les deviner"},
		"fix-ssh-password-openssh": {"In /etc/ssh/sshd_config set PasswordAuthentication no and KbdInteractiveAuthentication no, then systemctl reload ssh (keep a session open while you test).",
			"Dans /etc/ssh/sshd_config, mettez PasswordAuthentication no et KbdInteractiveAuthentication no, puis systemctl reload ssh (gardez une session ouverte pendant le test)."},
		"fix-ssh-password-other": {"Turn off password and keyboard-interactive logins in this SSH server's settings and keep keys only.",
			"Désactivez la connexion par mot de passe et keyboard-interactive dans la configuration de ce serveur SSH, et gardez seulement les clés."},
		"fix-ssh-password-wings": {"Wings checks SFTP passwords against the panel, so players need them: keep them, but require strong passwords and two-factor authentication on the panel, or move players to SSH keys (Pterodactyl 1.11 and later).",
			"Wings vérifie les mots de passe SFTP auprès du panneau, les joueurs en ont donc besoin : gardez-les, mais exigez des mots de passe solides et la double authentification sur le panneau, ou faites passer les joueurs aux clés SSH (Pterodactyl 1.11 et plus)."},
		"chk-ssh-keys": {"only accepts key-based logins: nothing to guess", "n'accepte que les clés : rien à deviner"},
		"chk-ssh-weak": {"still offers weak algorithms: %s", "propose encore des algorithmes faibles : %s"},
		"fix-ssh-weak-openssh": {"Add to /etc/ssh/sshd_config: %s, then systemctl reload ssh.",
			"Ajoutez dans /etc/ssh/sshd_config : %s, puis systemctl reload ssh."},
		"fix-ssh-weak-go": {"Remove them from the server's algorithm lists (with Go's x/crypto/ssh: ServerConfig.KeyExchanges and ServerConfig.MACs).",
			"Retirez-les des listes d'algorithmes du serveur (avec x/crypto/ssh en Go : ServerConfig.KeyExchanges et ServerConfig.MACs)."},

		"chk-kubelet-401": {"refuses anonymous requests", "refuse les requêtes anonymes"},
		"chk-kubelet-403": {"accepts anonymous requests but denies them (anonymous-auth is on; turning it off is safer)",
			"accepte les requêtes anonymes mais les refuse (anonymous-auth est activé ; le désactiver est plus sûr)"},
		"chk-kubelet-200": {"answers anonymous requests: anyone reaching it can list pods and run commands in them",
			"répond aux requêtes anonymes : quiconque l'atteint peut lister les pods et y exécuter des commandes"},
		"fix-kubelet": {"Set --anonymous-auth=false and --authorization-mode=Webhook on the kubelet, and close 10250 to everything but the control plane.",
			"Réglez --anonymous-auth=false et --authorization-mode=Webhook sur le kubelet, et fermez le 10250 à tout sauf au plan de contrôle."},
		"chk-api-401":       {"refuses anonymous requests", "refuse les requêtes anonymes"},
		"chk-api-403":       {"accepts anonymous requests but denies them", "accepte les requêtes anonymes mais les refuse"},
		"chk-api-200":       {"answers anonymous API discovery", "répond aux requêtes anonymes de découverte de l'API"},
		"fix-api-anonymous": {"Start the API server with --anonymous-auth=false, or remove the RBAC bindings that grant system:anonymous.", "Lancez le serveur d'API avec --anonymous-auth=false, ou retirez les droits RBAC accordés à system:anonymous."},
		"chk-docker-open":   {"answers without authentication: whoever reaches it is root on the host", "répond sans authentification : quiconque l'atteint est root sur la machine"},
		"chk-es-open":       {"returns cluster information without authentication", "renvoie les informations du cluster sans authentification"},
		"chk-redis-open":    {"answered INFO without a password", "a répondu à INFO sans mot de passe"},
		"chk-auth-required": {"asks for a password before anything else", "exige un mot de passe avant toute chose"},

		"chk-http-redirect": {"redirects to HTTPS", "redirige vers HTTPS"},
		"chk-http-ip-404": {"answers 404 to the bare IP address: the reverse proxy only serves your domain names. Check the HTTPS redirect with your domain",
			"répond 404 à l'adresse IP seule : le reverse proxy ne sert que vos noms de domaine. Vérifiez la redirection HTTPS avec votre domaine"},
		"chk-http-plain":    {"serves pages without encryption", "sert des pages sans chiffrement"},
		"fix-http-redirect": {"Redirect every plain-HTTP request to HTTPS (301) and add Strict-Transport-Security.", "Redirigez toute requête HTTP vers HTTPS (301) et ajoutez Strict-Transport-Security."},

		"chk-tls-traefik-default": {"serves Traefik's default certificate: expected when reached by IP, but check that your domain gets its real certificate",
			"sert le certificat par défaut de Traefik : normal par adresse IP, mais vérifiez que votre domaine reçoit bien son vrai certificat"},
		"chk-tls-self-signed": {"uses a self-signed certificate: browsers show a warning", "utilise un certificat auto-signé : les navigateurs affichent une alerte"},
		"fix-tls-cert":        {"Use a certificate from a public CA (Let's Encrypt is free).", "Utilisez un certificat d'une autorité publique (Let's Encrypt est gratuit)."},
		"chk-tls-expiry":      {"its certificate expires in %d days", "son certificat expire dans %d jours"},
		"fix-tls-renew":       {"Renew the certificate, and automate renewals.", "Renouvelez le certificat, et automatisez les renouvellements."},
		"chk-tls-modern":      {"negotiates TLS 1.3 with a post-quantum key exchange", "négocie TLS 1.3 avec un échange de clés post-quantique"},
		"chk-tls-weak":        {"still accepts TLS 1.0 or 1.1", "accepte encore TLS 1.0 ou 1.1"},
		"fix-tls-weak":        {"Accept TLS 1.2 and 1.3 only.", "N'acceptez que TLS 1.2 et 1.3."},

		"chk-wings-auth": {"confirmed: Pterodactyl Wings, which requires a token for every request", "confirmé : Pterodactyl Wings, qui exige un jeton pour chaque requête"},
		"ev-wings":       {"its API answered with Wings' own error message", "son API a répondu avec le message d'erreur propre à Wings"},

		"prof-pterodactyl": {"a Pterodactyl game-hosting node", "un nœud d'hébergement de jeux Pterodactyl"},
		"prof-minecraft":   {"running Minecraft servers", "avec des serveurs Minecraft"},
		"prof-mail":        {"a mail server", "un serveur de mail"},
		"prof-web":         {"serving websites", "qui sert des sites web"},
		"prof-k3s":         {"under Kubernetes (k3s)", "sous Kubernetes (k3s)"},
		"prof-k8s":         {"under Kubernetes", "sous Kubernetes"},
		"prof-traefik":     {"behind the Traefik reverse proxy", "derrière le reverse proxy Traefik"},
		"prof-os":          {"on %s", "sur %s"},
		"prof-generic":     {"a machine exposing %d services", "une machine qui expose %d services"},

		"good-private-closed": {"none of the %d sensitive ports tested (databases, Docker, Kubernetes, admin tools...) is reachable",
			"aucun des %d ports sensibles testés (bases de données, Docker, Kubernetes, outils d'administration…) n'est joignable"},
		"plan-many-ssh": {"%d SSH entry points face the internet: each is a door to defend. Keep the one you administer with, limit the others to known addresses",
			"%d accès SSH font face à Internet : chacun est une porte à défendre. Gardez celui qui sert à l'administration, limitez les autres à des adresses connues"},
	} {
		messages[k] = v
	}
}
