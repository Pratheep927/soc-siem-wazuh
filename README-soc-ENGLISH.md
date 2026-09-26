# Home-made SOC with Wazuh

A complete SOC built locally to understand how attack detection really works.
Wazuh on one side, a deliberately vulnerable app on the other, and everything in
between.

> Isolated lab. DVWA and the attack script must only target this stack, nothing
> else.

## Why I did this

In class we talk about SIEMs, correlation rules, MITRE ATT&CK. But until you've
seen an alert fire for real, it stays abstract. I wanted to build the full
chain: an attack, the detection, the response, the notification. And above all,
to understand what breaks when it doesn't work.

## What it does

I send an SQL injection to DVWA. Wazuh catches it thanks to a rule I wrote,
classifies it as level 12 (critical), triggers an IP ban, and sends an alert to
Slack. All in under a second.

## The architecture

```
   me attacking (curl)
          |
          v
    +-----------+   apache logs   +---------------+
    |   DVWA    | --------------> | Wazuh Manager |
    | (the target)|  docker volume|  (the brain)  |
    +-----------+                 +-------+-------+
                                          |
                    +---------------------+------------------+
                    v                     v                  v
             +-------------+      +--------------+   +-------------+
             |   Indexer   |      |   auto ban   |   |    Slack    |
             | (the storage)|     |  (firewall)  |   | (the alert) |
             +------+------+      +--------------+   +-------------+
                    v
             +-------------+
             |  Dashboard  |
             +-------------+
```

Four containers:
- **wazuh.manager**: receives the logs, applies the rules, decides
- **wazuh.indexer**: stores the alerts (it's an OpenSearch, it eats RAM)
- **wazuh.dashboard**: the web interface
- **dvwa**: the vulnerable app used as a target

## Installation

```bash
# the TLS certificates (once only)
docker compose -f generate-indexer-certs.yml run --rm generator

# start everything
docker compose up -d

# the target
docker run -d --name dvwa --network single-node_default \
  -p 8080:80 -v dvwa-logs:/var/log/apache2 vulnerables/web-dvwa:latest
```

Dashboard on `https://localhost` (admin / SecretPassword), DVWA on
`http://localhost:8080`.

You need `vm.max_map_count=262144` on the host or the indexer won't start.

## My detection rules

They're in `local_rules.xml`. The 100000+ range is the one reserved for custom
rules.

| ID | Level | What it detects |
|---|---|---|
| 100020 | 5 | a login attempt on DVWA |
| 100021 | 10 | 6 attempts in 60s from the same IP = brute force |
| 100031 | 12 | SQL injection in the URL |

Rule 100021 is the most interesting one in my opinion. A failed login attempt is
mundane, nobody cares. Six in one minute from the same address is a different
story. That's what a correlation rule is: you don't look at the event, you look
at the pattern.

```xml
<rule id="100021" level="10" frequency="6" timeframe="60">
  <if_matched_sid>100020</if_matched_sid>
  <same_source_ip />
  <description>CLOUDS: Brute-force web DVWA detecte</description>
  <mitre><id>T1110.001</id></mitre>
</rule>
```

## The automated response

As soon as an alert goes above level 10, Wazuh bans the source IP for 300
seconds.

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <level>10</level>
  <timeout>300</timeout>
</active-response>
```

I set a timeout rather than a permanent ban on purpose. If someone spoofs the IP
of a legitimate partner, a permanent ban would cut off that partner. The
attacker would have pulled off a DoS using my own defence. Five minutes is
better.

In my lab the ban stops on `172.19.0.1` because that's the Docker network
gateway and Wazuh refuses to ban infrastructure IPs. That makes sense, otherwise
the container would cut itself off from the network. But the whole chain before
that works, you can clearly see the `add` command and the IP check in the logs.

## False positives

Once the rules were in place, I realised the dashboard was filling up with
alerts that weren't really alerts. The Docker healthcheck hits `login.php` every
30 seconds from `127.0.0.1`: my login attempt rule was firing on it. Same thing
with the monitoring that queries `/server-status`. The result is noise that
drowns out the real alerts.

That's exactly the problem in a real SOC: an analyst who gets 200 alerts a day,
195 of them false, ends up ignoring all of them, including the real one. So I
wrote exclusion rules, at level 0 (Wazuh doesn't alert on level 0), in
`local_rules.xml`:

```xml
<rule id="100090" level="0">
  <if_sid>100020</if_sid>
  <srcip>127.0.0.1</srcip>
  <url>login.php</url>
  <description>Healthcheck local sur login.php - ignore</description>
</rule>
```

The principle: I don't delete the detection rule, I just tell it "this specific
pattern, in this specific context, is not a threat". A login attempt from
`127.0.0.1` on the healthcheck, yes. The same attempt from an external IP, the
alert fires normally. That's what SIEM tuning is: not cutting detection off, but
making it precise enough to only speak up when it matters.

| ID | Level | What it does |
|---|---|---|
| 100090 | 0 | ignores the local healthcheck on login.php |
| 100091 | 0 | ignores monitoring (/server-status, /health, /ping) |
| 100092 | 0 | ignores an isolated auth failure (the brute-force pattern still fires) |

## Going further: cloud detection (Entra ID / M365)

A DevSecOps engineer I showed the project to made a remark: running Wazuh on a
web app is fine, but today the attacks that matter target identity - Microsoft
365 accounts, Azure AD (renamed Entra ID). Password spraying against M365
tenants is the daily bread of SOCs in 2026. So I extended the project to that
source.

The principle is the same as for Apache logs: Entra ID produces `SignInLogs` in
JSON, Wazuh knows how to decode them natively, and I write my rules on top. Each
failed sign-in carries an `errorCode`: `50126` is a wrong password, `50074` an
MFA failure. Those are the codes I watch.

I don't have a real Microsoft tenant (it costs a subscription, and above all I
didn't want to expose real identities). So I replayed logs in the exact format
documented by Microsoft, injected into Wazuh. The detection itself is real - it's
the same engine, the same rules, that would run identically on a real tenant
plugged in via the `azure` module.

My rules (`entra_rules.xml`, 110000 range):

| ID | Level | What it detects | MITRE |
|---|---|---|---|
| 110000 | 3 | an Entra ID sign-in event | - |
| 110010 | 5 | an authentication failure (errorCode 50126) | T1110 |
| 110011 | 8 | an MFA failure - possibly an already compromised account | T1621 |
| 110020 | 12 | **password spraying**: 5 failures in 120s from the same IP | T1110.003 |

Rule 110020 is the heart of the matter, and it's again a correlation rule. An
isolated password failure, everyone has those. Five failures in two minutes from
the same IP, on different accounts, is the signature of an attacker testing a
common password against the whole directory. I tested it with `wazuh-logtest` by
injecting five events: the first four come out at level 5, and the fifth flips
to level 12 with the T1110.003 mapping. Exactly the expected behaviour.

```xml
<rule id="110020" level="12" frequency="5" timeframe="120">
  <if_matched_sid>110010</if_matched_sid>
  <same_field>azure.properties.ipAddress</same_field>
  <description>Entra ID: PASSWORD SPRAY detecte depuis $(azure.properties.ipAddress)</description>
  <mitre><id>T1110.003</id></mitre>
</rule>
```

The distinction I stand by in interviews: I do **detection** on identity logs,
not administration of an M365 tenant. I don't claim to manage Entra ID in
production; I'm showing that I know how to turn its logs into actionable alerts.
That's a SOC analyst's job.

## IoC analysis: qualifying the attacker's IP

Detecting an attack is one thing, but an analyst also has to be able to say
*who* is knocking. So I took the source IP from my password spraying scenario
(`45.155.205.99`) and qualified it by cross-referencing several open source
intelligence sources (AbuseIPDB, VirusTotal, Shodan).

What I found, and why it's interesting:

| Source | What it says |
|---|---|
| AbuseIPDB | 990 reports, 37 independent sources (2020-2022), current score 0% |
| VirusTotal | 0/89, no vendor flags it as malicious today |
| Shodan | no service currently exposed (no information available) |
| Hosting provider | Cloud Technologies LLC (Cloud.ru), datacenter, AS208677 |
| Country | Russia (Moscow) |
| Reported categories | Mostly Port Scan, Hacking, connection attempts |

The thing that taught me something: **my sources didn't agree**. AbuseIPDB showed
990 reports but a current score of 0%; VirusTotal called it completely clean.
Reading that quickly, you'd conclude "harmless IP". It's more subtle than that,
and understanding why is the heart of the job.

Both are right, because they don't measure the same thing. VirusTotal mostly
aggregates **real-time** blocklists: a 0/89 means "not on an active blocklist
right now". AbuseIPDB is **historical** community reporting: its 990 reports are
a log of the past, which remains even once the activity has stopped. The
AbuseIPDB score also decays over time, and this IP hadn't been reported for four
years, hence the return to zero.

So the correct reading isn't "one source is wrong", it's: this IP has a
**documented hostile past** (scanning and hacking from a Russian datacenter) and
is **no longer active nor blocklisted today**. Current risk is low, but it's not
a trusted IP either: its history would justify closer monitoring if it
reappeared.

Shodan completes the picture: it has no exposed service recorded on this IP,
which confirms it's dormant today. So all three sources converge, from three
different angles: an IP with a documented hostile past, but inactive and not
exposed at the moment.

The lesson I take from it: an indicator can't be read off a single number or a
single source. You have to cross-reference, understand what each source
measures, and look at the context (an IP in a datacenter doesn't mean the same
thing as a residential IP). Once put back in context, this IP is consistent with
the behaviour my rule 110020 had detected: reconnaissance, not a legitimate
user.

## The struggles

### The certificates (the worst one)

The manager wouldn't connect to the indexer:

```
x509: certificate is valid for demo.indexer, not wazuh.indexer
```

Except I had checked the file, and the name in it really was `wazuh.indexer`. I
went round in circles on that one for a good while.

What unblocked me: instead of re-reading the file, going to look at what the
indexer actually presents on the network.

```bash
openssl s_client -connect wazuh.indexer:9200 -servername wazuh.indexer \
  | openssl x509 -noout -text | grep -A1 'Subject Alternative Name'
# -> DNS:demo.indexer
```

And there it was clear: it wasn't serving my certificate. In fact I was mounting
the certs in `/usr/share/wazuh-indexer/certs/` while the indexer reads
`/usr/share/wazuh-indexer/config/certs/`. So my mount was overwriting nothing at
all, and the service was quietly using the demo certificates baked into the
image.

What I take from it: a service that starts without an error doesn't mean it's
correctly configured. With TLS, you have to look at what goes over the network,
not at what the config file claims.

### The rule that wouldn't match

My SQL injection rule never fired. Yet the log was arriving fine, I could see it
in `access.log`:

```
GET /vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20user,password%20FROM%20users--
```

It took me a while to see it: my regex was looking for `union\s+select`, with a
space. Except in a URL spaces are encoded as `%20`. So there was no space to
find. I fixed it by covering the three possible forms:

```
(union(\s|\+|%20)+select|...)
```

What struck me is that it fails silently. No error anywhere. The rule exists,
the log arrives, the attack goes through, and the dashboard stays empty. You
think you're protected when you're not. That's the worst thing that can happen
to a SIEM.

### The agent you can't install

At first I wanted to put a Wazuh agent inside the DVWA container, that's the
normal method. Impossible: the image is based on Debian Stretch, a version so
old that the APT repositories return 404s.

```
E: Failed to fetch http://deb.debian.org/debian/dists/stretch/... 404 Not Found
```

So I changed approach: a Docker volume shared between DVWA and the manager, and
the manager reads the logs directly. No agent, but it works.

## Image scanning

I ran Trivy on the images to see what they contain:

| Image | Base | Total | HIGH | CRITICAL | Secrets |
|---|---|---|---|---|---|
| `vulnerables/web-dvwa` | Debian 9.5 (EOL) | 805 | 551 | 254 | 1 |
| `wazuh/wazuh-manager:4.14.7` | Amazon Linux 2023 | - | - | 0 | - |

805 against 0 says a lot. Trivy says it itself in its warning: Debian 9 is end
of life, no more patches. CVEs pile up and nobody will ever fix them. That's
also exactly why I couldn't install the agent.

It also found a hardcoded private key in the image
(`/etc/ssl/private/ssl-cert-snakeoil.key`). A Docker image is public, so if that
key were actually in use, all traffic encrypted with it would be decryptable.
Here it's a Debian demo key so it's worthless, but the principle is the same.

## What I take away

- The choice of base image is the security decision that matters most
- A detection rule has to be tested with real payloads before you rely on it
- Check reality, not the config

## Limitations

Let's be honest, this is a lab:

- single node, no HA
- no index retention management
- the Entra ID logs are replayed, not from a real tenant (the detection engine
  itself is real and ready to plug in via the `azure` module)
- false positive tuning has been started (3 exclusion rules) but on a real
  estate there would be dozens of cases to handle

## Stack

Wazuh 4.14.7, OpenSearch, Docker Compose, DVWA, Azure/Entra ID JSON decoder.
