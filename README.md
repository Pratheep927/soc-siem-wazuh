# SOC open-source — SIEM/XDR conteneurisé

Déploiement d'une chaîne complète de détection et de réponse aux incidents de
sécurité, du log brut jusqu'à la notification de l'analyste, entièrement
conteneurisée et reproductible.

> **Environnement de laboratoire isolé.** La cible vulnérable et les scripts
> d'attaque ne doivent viser que cette stack locale.

---

## Sommaire

- [Architecture](#architecture)
- [Composants](#composants)
- [Déploiement](#déploiement)
- [Règles de détection personnalisées](#règles-de-détection-personnalisées)
- [Réponse automatisée](#réponse-automatisée)
- [Alerting](#alerting)
- [Analyse de vulnérabilités des images](#analyse-de-vulnérabilités-des-images)
- [Difficultés rencontrées](#difficultés-rencontrées)
- [Limites et pistes d'amélioration](#limites-et-pistes-damélioration)

---

## Architecture

```
   Attaquant (curl / navigateur)
            │
            ▼
   ┌─────────────────┐   logs Apache   ┌──────────────────┐
   │      DVWA       │ ──────────────▶ │  Wazuh Manager   │
   │ (cible vulnér.) │  volume Docker  │ (décodeurs+règles)│
   └─────────────────┘                 └────────┬─────────┘
                                                │
                          ┌─────────────────────┼──────────────────┐
                          ▼                     ▼                  ▼
                   ┌─────────────┐      ┌──────────────┐   ┌─────────────┐
                   │   Indexer   │      │ Active-Resp. │   │   Slack     │
                   │ (OpenSearch)│      │ firewall-drop│   │  webhook    │
                   └──────┬──────┘      └──────────────┘   └─────────────┘
                          ▼
                   ┌─────────────┐
                   │  Dashboard  │
                   └─────────────┘
```

Toutes les communications inter-composants sont chiffrées en TLS avec une PKI
dédiée (autorité racine + un certificat par service).

---

## Composants

| Composant | Rôle |
|---|---|
| **Wazuh Manager** | Cœur du SIEM : décode les logs, applique les règles de corrélation, déclenche les réponses |
| **Wazuh Indexer** | Stockage et indexation des alertes (OpenSearch) |
| **Wazuh Dashboard** | Interface de visualisation, filtres, mapping MITRE ATT&CK |
| **Filebeat** | Transport TLS des alertes du manager vers l'indexer |
| **DVWA** | Application volontairement vulnérable servant de cible d'entraînement |

Stack : Wazuh 4.14.7 · OpenSearch · Docker Compose v2

---

## Déploiement

### Prérequis

- Docker Engine + plugin Docker Compose v2
- 8 Go RAM minimum (l'indexer est gourmand)
- `vm.max_map_count=262144` sur l'hôte

### Mise en route

```bash
# 1. Générer la PKI (une seule fois)
docker compose -f generate-indexer-certs.yml run --rm generator

# 2. Démarrer la stack
docker compose up -d

# 3. Démarrer la cible
docker run -d --name dvwa --network single-node_default \
  -p 8080:80 -v dvwa-logs:/var/log/apache2 vulnerables/web-dvwa:latest
```

Dashboard : `https://localhost` · Cible : `http://localhost:8080`

### Collecte des logs

Les logs Apache de DVWA sont partagés avec le manager via un volume Docker
nommé, puis déclarés comme sources dans `ossec.conf` :

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/dvwa/access.log</location>
</localfile>
```

---

## Règles de détection personnalisées

Trois règles écrites dans `local_rules.xml` (plage 100000+, réservée aux règles
utilisateur), chacune mappée sur MITRE ATT&CK.

| ID | Niveau | Type | Détection | MITRE |
|---|---|---|---|---|
| `100020` | 5 | Atomique | Tentative d'authentification sur `login.php` | — |
| `100021` | 10 | **Corrélation** | 6 tentatives en 60 s depuis la même IP → brute-force | T1110.001 |
| `100031` | 12 | Atomique | Motifs d'injection SQL dans l'URL | T1190 |

### Exemple : règle de corrélation (brute-force)

```xml
<rule id="100021" level="10" frequency="6" timeframe="60">
  <if_matched_sid>100020</if_matched_sid>
  <same_source_ip />
  <description>CLOUDS: Brute-force web DVWA detecte</description>
  <mitre><id>T1110.001</id></mitre>
  <group>web,attack,authentication_failures,</group>
</rule>
```

L'intérêt : un échec d'authentification isolé est banal, six en une minute
depuis la même source constituent un motif d'attaque. C'est la différence entre
une règle atomique et une règle de corrélation.

### Exemple : détection d'injection SQL

```xml
<rule id="100031" level="12">
  <if_sid>31100,31101,31103,31104,31106,31108,31164</if_sid>
  <regex type="pcre2">(?i)(union(\s|\+|%20)+select|or(\s|\+|%20)+1=1|sleep\(|information_schema)</regex>
  <description>CLOUDS: Injection SQL confirmee - niveau critique</description>
  <mitre><id>T1190</id></mitre>
</rule>
```

### Alerte produite

```json
{
  "rule": {
    "level": 12,
    "description": "CLOUDS: Injection SQL confirmee - niveau critique",
    "id": "100031",
    "mitre": {
      "id": ["T1190"],
      "tactic": ["Initial Access"],
      "technique": ["Exploit Public-Facing Application"]
    }
  },
  "data": { "srcip": "172.19.0.1", "url": "/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT..." },
  "location": "/var/log/dvwa/access.log"
}
```

Les tags de conformité (PCI DSS 6.5.1, RGPD IV_35.7.d, NIST 800-53 SI.4) sont
hérités automatiquement des groupes de règles.

---

## Réponse automatisée

Toute alerte de niveau ≥ 10 déclenche un bannissement temporaire de l'IP source
via le script natif `firewall-drop` :

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <level>10</level>
  <timeout>300</timeout>
</active-response>
```

Le `timeout` de 300 s est délibéré : un bannissement permanent déclenché par une
IP usurpée constituerait un déni de service auto-infligé.

### Trace d'exécution

```
active-response/bin/firewall-drop: Starting
active-response/bin/firewall-drop: {"command":"add", ... "srcip":"172.19.0.1",
   "rule":{"level":12,"id":"100031"}}
active-response/bin/firewall-drop: {"command":"check_keys","keys":["172.19.0.1"]}
```

En laboratoire, le bannissement s'interrompt sur `172.19.0.1` : Wazuh protège
par liste blanche les IP d'infrastructure, ici la passerelle du réseau Docker.
Bannir sa propre gateway isolerait le conteneur. Le comportement est correct.

---

## Alerting

Notification Slack via webhook entrant pour toute alerte de niveau ≥ 10 :

```xml
<integration>
  <name>slack</name>
  <hook_url>https://hooks.slack.com/services/...</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

Le message reçu contient la description de la règle, le log brut, l'agent, la
source et l'identifiant de règle avec son niveau.

---

## Analyse de vulnérabilités des images

Scan des images de la stack avec [Trivy](https://trivy.dev) (Aqua Security).

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image --severity HIGH,CRITICAL vulnerables/web-dvwa:latest
```

### Résultats

| Image | Base | Total | HIGH | CRITICAL | Secrets |
|---|---|---|---|---|---|
| `vulnerables/web-dvwa:latest` | Debian 9.5 (EOL) | **805** | 551 | **254** | 1 |
| `wazuh/wazuh-manager:4.14.7` | Amazon Linux 2023 | — | — | **0** | — |

Deux enseignements :

**L'obsolescence de la base est le facteur dominant.** Trivy signale
explicitement `This OS version is no longer supported by the distribution` :
Debian 9 ne reçoit plus de correctifs, d'où l'accumulation. L'image officielle
Wazuh, maintenue sur Amazon Linux 2023, ne présente aucune vulnérabilité
critique.

**Un secret est embarqué dans l'image.** Le scanner de secrets détecte une clé
privée TLS en dur dans `/etc/ssl/private/ssl-cert-snakeoil.key`. Une clé
committée dans une image est distribuée à quiconque la télécharge — un cas
classique de fuite de secret par la chaîne de build.

Ce résultat recoupe une difficulté rencontrée pendant le déploiement : les
dépôts APT de Debian Stretch renvoient des 404, rendant toute installation de
paquet impossible dans le conteneur (voir ci-dessous).

---

## Difficultés rencontrées

### Certificats TLS : le mauvais chemin de montage

**Symptôme.** Le manager refusait obstinément de se connecter à l'indexer :

```
x509: certificate is valid for demo.indexer, not wazuh.indexer
```

Le certificat sur le disque était pourtant correct, et son `Subject Alternative
Name` valait bien `wazuh.indexer`.

**Diagnostic.** Vérifier le fichier ne suffit pas : il faut inspecter le
certificat *réellement présenté sur le réseau*.

```bash
docker run --rm --network single-node_default alpine sh -c \
  "apk add --no-cache openssl -q && echo | \
   openssl s_client -connect wazuh.indexer:9200 -servername wazuh.indexer 2>/dev/null | \
   openssl x509 -noout -text | grep -A1 'Subject Alternative Name'"
# → DNS:demo.indexer
```

L'indexer servait donc un autre certificat que celui monté.

**Cause.** Les certificats étaient montés dans
`/usr/share/wazuh-indexer/certs/`, alors que l'indexer lit
`/usr/share/wazuh-indexer/config/certs/`. Le montage n'écrasait rien ; le
service utilisait silencieusement ses certificats de démonstration intégrés.

**Enseignement.** Un service qui démarre sans erreur n'est pas un service
correctement configuré. Sur une chaîne TLS, seul le certificat observé côté
réseau fait foi.

### Faux négatif sur URL encodée

La première version de la règle 100031 ne se déclenchait pas sur une injection
pourtant présente dans les logs. Le motif recherché était `union\s+select` —
avec un espace littéral. Or les URL arrivent encodées :

```
GET /vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20user,password%20FROM%20users--
```

Il n'y a pas d'espace, mais `%20`. Correction du regex pour couvrir les trois
formes rencontrées :

```
(union(\s|\+|%20)+select|...)
```

Un faux négatif de ce type ne produit aucune erreur visible : la règle existe,
le log arrive, et l'attaque passe. C'est le mode de défaillance le plus
dangereux d'un SIEM.

### Agent impossible dans la cible

L'installation d'un agent Wazuh dans le conteneur DVWA a échoué : l'image repose
sur Debian Stretch, archivée, dont les dépôts renvoient des 404. L'approche a
été changée pour du log shipping via volume Docker partagé, sans agent.

---

## Limites et pistes d'amélioration

Ce projet est un laboratoire, pas une infrastructure de production. Les écarts
assumés :

- **Mono-nœud** : pas de haute disponibilité ni de cluster indexer
- **Une seule source de logs** (Apache) ; une infrastructure réelle en agrège
  des dizaines
- **Pas de gestion du cycle de vie** des index (rétention, rollover)
- **Secrets en clair** dans les fichiers de configuration
- **Peu de travail sur les faux positifs**, qui constituent l'essentiel de la
  charge d'un SOC réel

Pistes suivantes : passage en multi-nœuds, intégration d'un WAF en amont
(ModSecurity/OWASP CRS) avec ses logs en source supplémentaire, et intégration
du scan Trivy dans un pipeline CI/CD bloquant.
