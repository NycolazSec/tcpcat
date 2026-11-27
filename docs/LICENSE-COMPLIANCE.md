# Conformité de licence : détecter et traiter une intégration non déclarée

[English version](LICENSE-COMPLIANCE.en.md)

> **Modèle, pas avis juridique.** Faites relire les courriers ci-dessous par votre
> avocat avant envoi.

## 1. Ce qui est une infraction, et ce qui n'en est pas

| Situation | Obligation |
|---|---|
| Une entreprise utilise tcpcat **en interne** (pentest, audit de son réseau ou de celui de ses clients autorisés) | **Aucune.** L'AGPL l'autorise, y compris à titre commercial. |
| Une entreprise **modifie** tcpcat et l'utilise en interne | Aucune. |
| Une entreprise **distribue** tcpcat (seul, dans un produit, une appliance, une image, une VM) | Fournir le code source complet correspondant sous AGPL-3.0. |
| Une entreprise propose tcpcat **modifié** à des tiers **en service réseau** | Publier le code modifié sous AGPL-3.0 (§13). |

Le déclencheur est la **distribution** ou le **service à des tiers**, jamais la
simple présence de tcpcat sur un réseau : un scan tcpcat observé dans des logs ne
prouve aucune infraction.

## 2. Repérer tcpcat dans un produit distribué

Uniquement sur des artefacts que vous avez le droit d'examiner : un produit acheté,
un firmware ou une image publiés par l'éditeur, un paquet téléchargé.

```bash
scripts/find-tcpcat.sh firmware-extrait/      # répertoire (fichiers > 100 Ko)
scripts/find-tcpcat.sh ./binaire-suspect      # un fichier
```

Code de sortie : `0` rien trouvé, `1` indicateurs trouvés. Le script cherche des
indicateurs **forts**, propres au projet :
- le chemin de module Go (`github.com/NycolazSec/tcpcat`), que le *build info*
  conserve même dans un binaire strippé ;
- le message de licence : `License: GNU AGPL-3.0`, ou `tcpcat.io/oem` de la v1.4.2
  à la v1.10.0 ;
- les textes d'aide des options (`--license`, `--update`, `--web`).

Limites à connaître :
- Un éditeur qui **recompile en changeant le nom de module et les textes** échappe
  au script. C'est un détecteur de cas courants, pas une preuve d'absence.
- Un résultat positif est un **indice** : vérifiez à la main (`go version -m <fichier>`,
  `strings`, exécution en environnement isolé) avant d'écrire à qui que ce soit.
- La version compte : jusqu'à `v1.4.1`, tcpcat est sous **Apache 2.0**, qui autorise
  la redistribution propriétaire. Comparez la version trouvée avec `v1.4.1`.
  (Le binaire indique sa version avec `--version` ; le build info donne la version du module.)

## 3. Constituer le dossier

Avant tout courrier, conservez :
- le fichier examiné et son empreinte (`shasum -a 256`) ;
- la sortie du script ;
- la source (URL de téléchargement, date) ;
- la version identifiée ;
- la preuve de distribution, ou d'offre de service à des tiers.

## 4. Procédure

1. **Courrier de mise en conformité** (modèle A), ton cordial : beaucoup de cas sont
   des oublis. Laissez **30 jours**.
2. L'issue acceptable : ils **publient le code source complet correspondant** sous
   AGPL-3.0, ou ils **cessent la distribution** du produit.
3. Sans réponse : **relance recommandée** puis avocat (modèle B).

**Pourquoi 30 jours :** l'AGPL-3.0 (§8) prévoit que la licence d'un contrevenant est
rétablie définitivement s'il reçoit une première notification et corrige la
violation dans les 30 jours. Le courrier doit donc être une **notification claire** :
il fixe le point de départ et évite toute contestation.

### Modèle A — mise en conformité (premier courrier)

> **Objet : tcpcat — conformité de licence (AGPL-3.0) — [Produit]**
>
> Bonjour,
>
> Je suis Nicolas Blondelle, auteur et titulaire des droits d'auteur sur le logiciel
> tcpcat (https://github.com/NycolazSec/tcpcat).
>
> En examinant [produit / version / date / source], j'ai relevé la présence de tcpcat
> [version X] : [indicateurs constatés]. Le produit est [distribué / proposé en service
> à des tiers] sans que je trouve de publication du code source correspondant.
>
> tcpcat est publié sous licence AGPL-3.0. Pour régulariser, je vous remercie de
> publier le code source complet correspondant de [produit] sous AGPL-3.0, ou de
> cesser sa distribution.
>
> Je vous remercie de me répondre **sous 30 jours** à compter de la réception de ce
> message. Je reste disponible pour en discuter.
>
> Ce message vaut notification de manquement au sens de l'article 8 de l'AGPL-3.0.
> Tous mes droits sont réservés.
>
> Cordialement,
> Nicolas Blondelle (NycolazSec) — support@tcpcat.io

### Modèle B — relance / mise en demeure (à valider par un avocat)

> **Objet : tcpcat — second courrier — [Produit]**
>
> Suite à mon courrier du [date], resté sans réponse / sans régularisation à ce jour,
> je vous informe que la poursuite de la distribution de [produit] comprenant tcpcat
> sans respecter l'AGPL-3.0 porte atteinte à mes droits d'auteur.
>
> Je vous demande, **sous [15] jours**, de [cesser la distribution] ou de publier le
> code source complet correspondant sous AGPL-3.0. À défaut, je me réserve le droit
> d'engager toute action utile, notamment sur le fondement des articles L. 122-6 et
> L. 335-3 du Code de la propriété intellectuelle.
>
> [Signature] — [LRAR / e-mail avec accusé de réception]

## 5. Bon à savoir

- Les contributions sont acceptées sous AGPL-3.0, sans accord de licence de
  contributeur (CLA) : chaque contributeur garde le droit d'auteur sur le code qu'il
  a écrit. Vous pouvez faire valoir l'AGPL sur votre propre code ; les auteurs des
  autres parties détiennent les droits sur les leurs et peuvent se joindre à une
  action.
- Ce guide ne dépend d'aucun marquage des paquets réseau : l'usage interne étant
  légal, la présence de tcpcat sur un réseau ne prouve rien.
