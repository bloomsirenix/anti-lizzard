# findings — mail.manikineko.nl (2026-10-12)

Log/activity scan of the SSH server `daisy@mail.manikineko.nl` (Debian 13,
Proxmox host + mail/nginx/azuracast/pve). Below are the known abusers with
evidence. All are now listed in `know baddies.txt` / `full_noughtylist.txt`
(and `baddies with asn codes`); their hosting/criminal ASNs are in `bad_asn`,
compliant provider ASNs in `commonabused_cspasns.txt`.

## SSH brute force — /var/log/auth.log*

IPs with >=3 failed password/invalid-user attempts. Fail2ban (jails: sshd,
recidive) independently banned many of them repeatedly — corroborating proof.

| attempts | ip | asn | whois |
|---:|---|---|---|
| 13104 | 103.64.129.163 | AS150609 | TELEINDIA NETWORKS, IN |
| 1001 | 117.157.77.71 | AS9808 | China Mobile, CN |
| 998 | 103.8.59.250 | AS45707 | Prime Link Communication, ID |
| 50 | 114.202.2.168 | AS9318 | SK Broadband, KR |
| 50 | 103.18.6.159 | AS131392 | GMO-Z.com Runsystem, VN |
| 46 | 5.8.177.229 | AS31261 | GARS-AS Moscow, RU |
| 26 | 116.48.143.166 | AS4760 | HKT, HK |
| 23 | 81.9.49.147 | AS16345 | BEE-AS, RU |
| 19 | 187.109.102.218 | AS28158 | Ampernet Telecom, BR |

`Invalid user` events alone: 9,793.

### repeat offenders (fail2ban ban count)

banned 6-7x each: 45.179.46.58 (AS269077 BR), 209.45.73.18 (AS3132 PE),
200.194.238.229 (AS11844 BR), 187.120.47.227 (AS262685 BR),
186.81.59.100 (AS10620 CO), 181.49.138.21 + 181.49.35.161 (AS14080
Telmex Colombia), 181.209.31.2 (AS52361 ARSAT AR), 133.247.139.187
(AS131923 JP), 198.46.177.116 (AS36352 ColoCrossing), 196.196.41.130
(AS57858 SC), plus ~30 more banned 3-6x (full list in `know baddies.txt`).

## web scanners — /var/log/nginx/access.log*

| ip | asn | evidence |
|---|---|---|
| 80.94.95.211 | AS204428 SS-NET BG | `GET /laravel/.env`, `/.env.save`, `/.env.production`, `/.env.prod`, `/.env.local` x20 each |
| 45.148.10.238 | AS48090 DMZHOST GB | `POST /`, `/.env` variants, `/test.php`, `/sys_phpinfo.php` |
| 45.138.12.10 | AS218785 TC-DATACENTER HK | `GET /.git/HEAD`, `/wp-config.php.*`, `/rest/api/1.0/...` |
| 213.209.159.154 | AS208137 FPS12 RO | `/web/.env`, `/test/.env`, `/system/.env`, `/staging/.env`, `/src/.env` |
| 185.177.72.23 | AS211590 BUCKLOG FR | service probe sweep (kibana/yarn endpoints) |
| 13.70.107.184 | AS8075 Azure | webshell probes: `/myglu.php`, `/bnmtp.php`, `/yich.php`, wp-content paths |
| 104.208.73.227 | AS8075 Azure | `/wp-includes/ID3/about.php`, theme index probes |
| 65.109.93.137 | AS24940 Hetzner | 21k `GET /` + `/wp-login.php`, `/.git/config`, `//xmlrpc.php?rsd` |
| 34.123.129.130 / 34.124.251.251 | AS396982 GCP | `/api/config`, `/read-document`, graphql probes, `400` floods |

## port/protocol scanners — /var/log/ufw.log*

| ip | asn | evidence |
|---|---|---|
| 87.106.201.203 | AS8560 IONOS | 763 hits on DPT=5060 (SIP) |
| 172.110.223.179 | AS23470/AS47154 | 689 hits DPT=5060 + SIP-adjacent ports |
| 185.233.247.245 | AS206119 VEGANET | DPT=5060 SIP + port sweep |
| 79.124.62.230/.134/.126 | AS207812 DM_AUTO BG | DPT=3389 (RDP) x37, 7547 (TR-069), 135, 8089 |
| 109.205.211.21/.23/.25/.27/.29 | AS201814 MEVSPACE PL | coordinated /24 port sweep (sequential high ports) |
| 170.64.224.25 | AS14061 DigitalOcean | 1439 hits on DPT=23 (telnet — IoT/botnet sweep) |
| 45.13.212.84 | AS215929 DATACAMPUS HK | sequential high-port sweep |
| 31.220.88.42 | AS51167 Contabo | sequential high-port sweep |
| 194.50.16.198 | AS49870 NL | multi-port probes (808, 6969, 3121, ...) |

note: heavy `/listen/*` 502 traffic was verified to be legitimate radio
listeners retrying a dead azuracast mount — NOT added.

## huddleverse.io — malicious doxbin-connected platform

resolved 2026-10-12:

- `api.huddleverse.io` → CNAME `huddlehumans-prod-us-api-lb-1408614842.us-west-2.elb.amazonaws.com`
  → `54.186.165.41`, `32.190.235.41` (AS16509 AWS, us-west-2 ELB, DNS TTL 60 — IPs rotate)
- apex `huddleverse.io` → `15.197.225.128`, `3.33.251.168` (AS16509 AWS Global Accelerator)
- NS: `ns69/ns70.domaincontrol.com` (GoDaddy)

All 4 IPs added to the block lists. AS16509 is compliant (AWS), so it stays in
`commonabused_cspasns.txt` — the platform's IPs are blocked individually.
Re-resolve the CNAME periodically to catch ELB rotation:

    dig +short huddlehumans-prod-us-api-lb-1408614842.us-west-2.elb.amazonaws.com A

## method

- sources: `zcat -f /var/log/{auth,fail2ban,mail,ufw}.log*`, nginx access logs, pveproxy
- ASN/prefix lookups: Team Cymru bulk whois (`whois.cymru.com`)
- ASN blocklist: Spamhaus ASN-DROP (`spamhaus.org/drop/asndrop.json`, 431 ASNs)
  merged with documented bulletproof hosts (Aeza/Hypercore/Silent Connection/
  Stark/Proton66/Prospero/Pfcloud/Mevspace/DM_AUTO...)
- totals this scan: 99 new IPs, 64 new ASNs, 2 hostile /24s (109.205.211.0/24,
  79.124.62.0/24)
