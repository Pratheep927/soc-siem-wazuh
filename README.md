# SOC maison avec Wazuh

Un SOC complet monté en local pour comprendre comment fonctionne vraiment la
détection d'attaques. Wazuh d'un côté, une appli volontairement vulnérable de
l'autre, et tout ce qu'il y a entre les deux.

> Lab isolé. DVWA et le script d'attaque ne doivent viser que cette stack, rien
> d'autre.

## Pourquoi j'ai fait ça

En cours on parle de SIEM, de règles de corrélation, de MITRE ATT&CK. Mais tant
qu'on n'a pas vu une alerte se déclencher pour de vrai, ça reste abstrait. Je
voulais monter la chaîne complète : une attaque, la détection, la réaction, la
notification. Et surtout comprendre ce qui casse quand ça ne marche pas.

## Ce que ça fait

J'envoie une injection SQL sur DVWA. Wazuh la repère grâce à une règle que j'ai
écrite, la classe en niveau 12 (critique), déclenche un bannissement de l'IP, et
envoie une alerte sur Slack. Le tout en moins d'une seconde.

## L'archi

```
   moi qui attaque (curl)
          |
          v
    +-----------+   logs apache   +---------------+
    |   DVWA    | --------------> | Wazuh Manager |
    | (la cible)|  volume docker  |  (le cerveau) |
    +-----------+                 +-------+-------+
                                          |
                    +---------------------+------------------+
                    v                     v                  v
             +-------------+      +--------------+   +-------------+
             |   Indexer   |      |  ban auto    |   |    Slack    |
             | (le stockage|      |  (firewall)  |   |  (l'alerte) |
             +------+------+      +--------------+   +-------------+
                    v
             +-------------+
             |  Dashboard  |
             +-------------+
```

Quatre conteneurs :
- **wazuh.manager** : reçoit les logs, applique les règles, décide
- **wazuh.indexer** : stocke les alertes (c'est un OpenSearch, ça bouffe de la RAM)
- **wazuh.dashboard** : l'interface web
- **dvwa** : l'appli vulnérable qui sert de cible

## Installation

```bash
# les certifs TLS (une seule fois)
docker compose -f generate-indexer-certs.yml run --rm generator

# on lance tout
docker compose up -d

# la cible
docker run -d --name dvwa --network single-node_default \
  -p 8080:80 -v dvwa-logs:/var/log/apache2 vulnerables/web-dvwa:latest
```

Dashboard sur `https://localhost` (admin / SecretPassword), DVWA sur
`http://localhost:8080`.

Il faut `vm.max_map_count=262144` sur l'hôte sinon l'indexer démarre pas.

## Mes règles de détection

Elles sont dans `local_rules.xml`. La plage 100000+ c'est celle réservée aux
règles perso.

| ID | Niveau | Ce qu'elle détecte |
|---|---|---|
| 100020 | 5 | une tentative de login sur DVWA |
| 100021 | 10 | 6 tentatives en 60s depuis la même IP = brute force |
| 100031 | 12 | injection SQL dans l'URL |

La 100021 est la plus intéressante à mon avis. Une tentative de login ratée
c'est banal, personne ne s'en soucie. Six en une minute depuis la même adresse,
c'est plus la même histoire. C'est ça une règle de corrélation : on ne regarde
pas l'événement, on regarde le motif.

```xml
<rule id="100021" level="10" frequency="6" timeframe="60">
  <if_matched_sid>100020</if_matched_sid>
  <same_source_ip />
  <description>CLOUDS: Brute-force web DVWA detecte</description>
  <mitre><id>T1110.001</id></mitre>
</rule>
```

## La réponse automatique

Dès qu'une alerte dépasse le niveau 10, Wazuh bannit l'IP source pendant 300
secondes.

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <level>10</level>
  <timeout>300</timeout>
</active-response>
```

J'ai mis un timeout et pas un ban définitif exprès. Si quelqu'un spoofe l'IP
d'un partenaire légitime, un ban permanent couperait ce partenaire. L'attaquant
aurait réussi un DoS en se servant de ma propre défense. Mieux vaut 5 minutes.

Dans mon lab le ban s'arrête sur `172.19.0.1` parce que c'est la gateway du
réseau Docker et Wazuh refuse de bannir les IP d'infra. C'est logique — sinon le
conteneur se coupe du réseau tout seul. Mais toute la chaîne avant fonctionne,
on voit bien la commande `add` et la vérif de l'IP dans les logs.

## Les faux positifs

Une fois les règles en place, je me suis rendu compte que le dashboard se
remplissait d'alertes qui n'en étaient pas. Le healthcheck de Docker tape sur
`login.php` toutes les 30 secondes depuis `127.0.0.1` : ma règle de tentative de
login se déclenchait dessus. La supervision qui interroge `/server-status` pareil.
Résultat, du bruit qui noie les vraies alertes.

C'est exactement le problème d'un vrai SOC : un analyste qui reçoit 200 alertes
par jour dont 195 fausses finit par toutes les ignorer, y compris la bonne. Donc
j'ai écrit des règles d'exclusion, en niveau 0 (Wazuh n'alerte pas sur le niveau
0), dans `local_rules.xml` :

```xml
<rule id="100090" level="0">
  <if_sid>100020</if_sid>
  <srcip>127.0.0.1</srcip>
  <url>login.php</url>
  <description>Healthcheck local sur login.php - ignore</description>
</rule>
```

Le principe : je ne supprime pas la règle de détection, je lui dis juste « ce
motif précis, dans ce contexte précis, ce n'est pas une menace ». Une tentative
de login depuis `127.0.0.1` sur le healthcheck, oui. La même tentative depuis une
IP externe, l'alerte se déclenche normalement. C'est ça le tuning d'un SIEM : pas
couper la détection, mais la rendre assez fine pour ne parler que quand ça compte.

| ID | Niveau | Ce qu'elle fait |
|---|---|---|
| 100090 | 0 | ignore le healthcheck local sur login.php |
| 100091 | 0 | ignore la supervision (/server-status, /health, /ping) |
| 100092 | 0 | ignore un échec d'auth isolé (le motif brute-force reste, lui) |

## Aller plus loin : la détection sur le cloud (Entra ID / M365)

Un ingénieur DevSecOps à qui j'ai montré le projet m'a fait une remarque : monter
Wazuh sur une appli web c'est bien, mais aujourd'hui les attaques qui comptent
visent l'identité — les comptes Microsoft 365, l'Azure AD (rebaptisé Entra ID).
Le password spraying sur les tenants M365, c'est le pain quotidien des SOC en
2026. J'ai donc étendu le projet à cette source.

Le principe est le même que pour les logs Apache : Entra ID produit des
`SignInLogs` au format JSON, Wazuh sait les décoder nativement, et j'écris mes
règles par-dessus. Chaque échec de connexion porte un `errorCode` : `50126` c'est
un mauvais mot de passe, `50074` un échec de MFA. Ce sont ces codes que je
surveille.

Je n'ai pas de vrai tenant Microsoft (ça coûte un abonnement, et surtout je ne
voulais pas exposer de vraies identités). J'ai donc rejoué des logs au format
exact documenté par Microsoft, injectés dans Wazuh. La détection, elle, est
réelle — c'est le même moteur, les mêmes règles, qui tourneraient à l'identique
sur un vrai tenant branché via le module `azure`.

Mes règles (`entra_rules.xml`, plage 110000) :

| ID | Niveau | Ce qu'elle détecte | MITRE |
|---|---|---|---|
| 110000 | 3 | un événement de connexion Entra ID | — |
| 110010 | 5 | un échec d'authentification (errorCode 50126) | T1110 |
| 110011 | 8 | un échec de MFA — possible compte déjà compromis | T1621 |
| 110020 | 12 | **password spraying** : 5 échecs en 120s depuis la même IP | T1110.003 |

La 110020 est le cœur du sujet, et c'est encore une règle de corrélation. Un
échec de mot de passe isolé, tout le monde en fait. Cinq échecs en deux minutes
depuis la même IP, sur des comptes différents, c'est la signature d'un attaquant
qui teste un mot de passe courant sur tout l'annuaire. Je l'ai testée avec
`wazuh-logtest` en injectant cinq événements : les quatre premiers sortent en
niveau 5, et le cinquième bascule en niveau 12 avec le mapping T1110.003. Exactement
le comportement attendu.

```xml
<rule id="110020" level="12" frequency="5" timeframe="120">
  <if_matched_sid>110010</if_matched_sid>
  <same_field>azure.properties.ipAddress</same_field>
  <description>Entra ID: PASSWORD SPRAY detecte depuis $(azure.properties.ipAddress)</description>
  <mitre><id>T1110.003</id></mitre>
</rule>
```

Le distinguo que j'assume en entretien : je fais de la **détection** sur des logs
d'identité, pas de l'administration d'un tenant M365. Je ne prétends pas gérer
Entra ID en production ; je montre que je sais transformer ses journaux en
alertes exploitables. C'est le métier d'un analyste SOC.

## Analyse d'IoC : qualifier l'IP de l'attaquant

Détecter une attaque c'est bien, mais un analyste doit aussi savoir dire *qui*
frappe. J'ai donc pris l'IP source de mon scénario de password spraying
(`45.155.205.99`) et je l'ai qualifiée en croisant plusieurs sources de
renseignement ouvertes (AbuseIPDB, VirusTotal, Shodan).

Ce que j'ai trouvé, et pourquoi c'est intéressant :

| Élément | Résultat |
|---|---|
| Source | Ce qu'elle dit |
|---|---|
| AbuseIPDB | 990 reports, 37 sources indépendantes (2020-2022), score actuel 0 % |
| VirusTotal | 0/89, aucun vendeur ne la classe malveillante aujourd'hui |
| Shodan | aucun service exposé actuellement (no information available) |
| Hébergeur | Cloud Technologies LLC (Cloud.ru), datacenter, AS208677 |
| Pays | Russie (Moscou) |
| Catégories signalées | Port Scan majoritaire, Hacking, tentatives de connexion |

Le point qui m'a appris quelque chose : **mes deux sources n'étaient pas
d'accord**. AbuseIPDB affichait 990 signalements mais un score actuel de 0 % ;
VirusTotal la donnait totalement propre. En le lisant vite, on conclurait « IP
inoffensive ». C'est plus subtil que ça, et comprendre pourquoi, c'est le cœur
du métier.

Les deux ont raison, parce qu'elles ne mesurent pas la même chose. VirusTotal
agrège surtout des blocklists **en temps réel** : un 0/89 signifie « pas sur une
liste noire active en ce moment ». AbuseIPDB est de la remontée communautaire
**historique** : ses 990 reports sont un journal du passé, qui subsiste même une
fois l'activité arrêtée. Le score AbuseIPDB décroît d'ailleurs dans le temps, et
cette IP n'avait plus été signalée depuis quatre ans — d'où le retour à zéro.

La lecture correcte n'est donc pas « une source se trompe », mais : cette IP a un
**passé hostile documenté** (scan et hacking depuis un datacenter russe) et
n'est **plus active ni blocklistée aujourd'hui**. Risque actuel faible, mais ce
n'est pas une IP de confiance : son historique justifierait une surveillance
renforcée si elle réapparaissait.

Shodan complète le tableau : il n'a aucun service exposé enregistré sur cette IP,
ce qui confirme qu'elle est dormante aujourd'hui. Les trois sources convergent
donc, sous trois angles différents : une IP au passé hostile documenté, mais
inactive et non exposée à l'heure actuelle.

La leçon que je retiens : un indicateur ne se lit pas sur un seul chiffre ni sur
une seule source. Il faut croiser, comprendre ce que chaque source mesure, et
regarder le contexte (une IP en datacenter n'a pas le même sens qu'une IP
résidentielle). Une fois recontextualisée, cette IP est cohérente avec le
comportement que ma règle 110020 avait détecté : de la reconnaissance, pas un
utilisateur légitime.

## Les galères

### Les certificats (le pire)

Le manager voulait pas se connecter à l'indexer :

```
x509: certificate is valid for demo.indexer, not wazuh.indexer
```

Sauf que j'avais vérifié le fichier, et le nom dedans était bien
`wazuh.indexer`. J'ai tourné en rond un bon moment là-dessus.

Ce qui m'a débloqué : au lieu de relire le fichier, aller voir ce que l'indexer
présente vraiment sur le réseau.

```bash
openssl s_client -connect wazuh.indexer:9200 -servername wazuh.indexer \
  | openssl x509 -noout -text | grep -A1 'Subject Alternative Name'
# -> DNS:demo.indexer
```

Et là c'était clair : il servait pas mon certificat. En fait je montais les
certifs dans `/usr/share/wazuh-indexer/certs/` alors que l'indexer lit
`/usr/share/wazuh-indexer/config/certs/`. Du coup mon montage écrasait rien du
tout, et le service utilisait tranquillement ses certificats de démo intégrés à
l'image.

Le truc que je retiens : un service qui démarre sans erreur, ça veut pas dire
qu'il est bien configuré. Sur du TLS, faut regarder ce qui passe sur le réseau,
pas ce que le fichier de conf raconte.

### La règle qui matchait pas

Ma règle d'injection SQL se déclenchait jamais. Pourtant le log arrivait bien, je
le voyais dans `access.log` :

```
GET /vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20user,password%20FROM%20users--
```

J'ai mis un moment à voir : mon regex cherchait `union\s+select`, avec un espace.
Sauf que dans une URL les espaces sont encodés en `%20`. Donc y'avait aucun
espace à trouver. J'ai corrigé en prenant les trois formes possibles :

```
(union(\s|\+|%20)+select|...)
```

Ce qui m'a marqué c'est que ça plante en silence. Aucune erreur nulle part. La
règle existe, le log arrive, l'attaque passe, et le dashboard reste vide. Tu
crois que t'es protégé alors que non. C'est le pire truc qui puisse arriver sur
un SIEM.

### L'agent qu'on peut pas installer

Au départ je voulais mettre un agent Wazuh dans le conteneur DVWA, c'est la
méthode normale. Impossible : l'image est basée sur Debian Stretch, une version
tellement vieille que les dépôts APT renvoient des 404.

```
E: Failed to fetch http://deb.debian.org/debian/dists/stretch/... 404 Not Found
```

Du coup j'ai changé de méthode : un volume Docker partagé entre DVWA et le
manager, et le manager lit directement les logs. Pas d'agent, mais ça marche.

## Scan des images

J'ai passé Trivy sur les images pour voir ce qu'elles contiennent :

| Image | Base | Total | HIGH | CRITICAL | Secrets |
|---|---|---|---|---|---|
| `vulnerables/web-dvwa` | Debian 9.5 (EOL) | 805 | 551 | 254 | 1 |
| `wazuh/wazuh-manager:4.14.7` | Amazon Linux 2023 | — | — | 0 | — |

805 contre 0, c'est parlant. Trivy le dit lui-même dans son warning : Debian 9
est en fin de vie, plus aucun correctif. Les CVE s'accumulent et personne les
corrigera jamais. C'est d'ailleurs exactement pour ça que j'ai pas pu installer
l'agent.

Il a aussi trouvé une clé privée en dur dans l'image
(`/etc/ssl/private/ssl-cert-snakeoil.key`). Une image Docker c'est public, donc
si cette clé servait vraiment, tout le trafic chiffré avec serait déchiffrable.
Là c'est une clé de démo Debian donc sans valeur, mais le principe est le même.

## Ce que je retiens

- Le choix de l'image de base, c'est la décision de sécurité qui compte le plus
- Une règle de détection, faut la tester avec de vraies charges avant de compter
  dessus
- Vérifier le réel, pas la config

## Les limites

Faut être honnête, c'est un lab :

- mono-nœud, aucune HA
- pas de gestion de rétention des index
- les logs Entra ID sont rejoués, pas issus d'un vrai tenant (le moteur de
  détection, lui, est réel et prêt à brancher via le module `azure`)
- le tuning des faux positifs est amorcé (3 règles d'exclusion) mais sur un vrai
  parc il y aurait des dizaines de cas à traiter

## Stack

Wazuh 4.14.7, OpenSearch, Docker Compose, DVWA, décodeur JSON Azure/Entra ID.
