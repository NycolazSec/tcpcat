# Conformité de licence : détecter et traiter une intégration non déclarée

[English version](LICENSE-COMPLIANCE.en.md)

> **Modèle, pas avis juridique.** Les courriers ci-dessous suivent la logique de
> la double licence AGPL-3.0 / OEM. Faites-les relire par votre avocat avant envoi,
> comme `COMMERCIAL-LICENSE.md`.

## 1. Ce qui est une infraction, et ce qui n'en est pas

| Situation | Licence requise ? |
|---|---|
| Une entreprise utilise tcpcat **en interne** (pentest, audit de son réseau ou de celui de ses clients autorisés) | **Non.** L'AGPL l'autorise, y compris à titre commercial. |
| Une entreprise **modifie** tcpcat et l'utilise en interne | Non. |
| Une entreprise **distribue** tcpcat (seul, dans un produit, une appliance, une image, une VM) sans publier son code sous AGPL | **Oui** : licence OEM, ou conformité à l'AGPL. |
| Une entreprise propose tcpcat (modifié) à des tiers **en service réseau** sans publier ses modifications | **Oui** (AGPL §13) : licence OEM, ou publication du code. |

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
indicateurs **forts**, propres au projet : chemin de module Go
(`github.com/NycolazSec/tcpcat`, conservé dans le *build info* même binaire
strippé), message de licence (`tcpcat.io/oem`), textes d'aide des options
(`--license`, `--update`, `--web`).

Limites à connaître :
- Un éditeur qui **recompile en changeant le nom de module et les textes** échappe
  au script. C'est un détecteur de cas courants, pas une preuve d'absence.
- Un résultat positif est un **indice** : vérifiez à la main (`go version -m <fichier>`,
  `strings`, exécution en environnement isolé) avant d'écrire à qui que ce soit.
- La version compte : jusqu'à `v1.4.1`, tcpcat est sous **Apache 2.0**, qui autorise
  la redistribution propriétaire. Comparez la version trouvée avec `v1.4.1`.
  (Le binaire indique sa version avec `--version` ; le build info donne la version du module.)

## 3. Constituer le dossier

Avant tout courrier, conservez : le fichier examiné et son empreinte (`shasum -a 256`),
la sortie du script, la source (URL de téléchargement, date), la version identifiée,
et la preuve de distribution ou d'offre de service à des tiers.

## 4. Procédure

1. **Courrier de mise en conformité** (modèle A), ton cordial : beaucoup de cas sont
   des oublis. Laissez **30 jours**.
2. Deux issues acceptables : ils **publient leur source** sous AGPL, ou ils
   **prennent la licence commerciale** (formule selon leur taille, voir `/oem`).
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
> à des tiers] sans que je trouve de publication du code source correspondant ni de
> licence commerciale associée.
>
> tcpcat est publié sous licence AGPL-3.0, avec une licence commerciale (OEM) pour
> l'intégration dans un produit propriétaire (https://tcpcat.io/oem). Vous pouvez
> régulariser de deux façons :
> 1. publier le code source complet correspondant de [produit] sous AGPL-3.0 ; ou
> 2. souscrire une licence commerciale (formules et conditions : https://tcpcat.io/oem).
>
> Je vous remercie de me répondre **sous 30 jours** à compter de la réception de ce
> message, en m'indiquant l'option retenue. Je reste disponible pour en discuter.
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
> sans respecter l'AGPL-3.0 ni détenir de licence commerciale porte atteinte à mes
> droits d'auteur.
>
> Je vous demande, **sous [15] jours**, de [cesser la distribution] ou de régulariser
> selon l'une des deux options indiquées dans mon précédent message. À défaut, je me
> réserve le droit d'engager toute action utile, notamment sur le fondement des
> articles L. 122-6 et L. 335-3 du Code de la propriété intellectuelle.
>
> [Signature] — [LRAR / e-mail avec accusé de réception]

### Modèle C — audit (clients sous licence commerciale)

La section 4 du contrat (`COMMERCIAL-LICENSE.md`) prévoit la tenue de registres de
distribution et un audit sur préavis écrit raisonnable.

> **Objet : Licence tcpcat n° [clé] — demande de vérification de conformité**
>
> Conformément à l'article 4 de notre contrat de licence commerciale, je vous remercie
> de me transmettre, sous [30] jours, le relevé des distributions de [produit]
> contenant tcpcat depuis le [date] (volumes, versions, formule). Un audit sur pièces
> pourra être convenu à une date de votre choix dans les [60] jours.
>
> Nicolas Blondelle — support@tcpcat.io

## 5. Bon à savoir

- Vous seul détenez les droits sur votre code (seul auteur humain du dépôt), ce qui
  vous permet de faire valoir l'AGPL **et** de vendre la licence commerciale.
- Si des contributeurs externes ajoutent du code, demandez un accord de cession ou de
  licence (CLA) **avant** de fusionner : sinon vous ne pourrez plus relicencier ce code.
- Ce guide ne dépend d'aucun marquage des paquets réseau : l'usage interne étant
  légal, la présence de tcpcat sur un réseau ne prouve rien.
