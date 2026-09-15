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
- une seule source de logs, en vrai y'en a des dizaines
- pas de gestion de rétention des index
- j'ai quasiment pas travaillé les faux positifs, alors que c'est le gros du
  boulot dans un vrai SOC

## Stack

Wazuh 4.14.7, OpenSearch, Docker Compose, DVWA.
