# Threat Modelling SOP — Behavioural, Patch-Resistant TTPs
### *Novel Tradecraft Research · Proof-of-Concept Laboratory · Detection Engineering Pipeline*

**Author:** Ala Dabat | [github.com/azdabat](https://github.com/azdabat)  
**Version:** 2025-12  
**License:** [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode)  
**Framework:** [Minimum Truth Detection Framework](https://github.com/azdabat/Minimum-Truth-Detection-Framework-ADX-Validated-Composite-Rules)

---

> *"Most enterprise detection strategies revolve around signatures, IOCs, and individual CVEs.*  
> *Those no longer provide meaningful defence against modern adversaries.*  
> *This repository models the behaviour — because the behaviour never changes."*

---

> [!IMPORTANT]
> **Research & Proof-of-Concept Only**
>
> This repository is a **Threat Modelling Laboratory** — not a production deployment pack.
> Logic stored here represents experimental SOPs, behavioural research, and POC detection
> approaches. Rules are **not** ADX-validated or tuned for production noise levels.
>
> **Migration Path:**
> Once logic is validated, refined, and normalised, it is promoted to the
> **[Minimum Truth Detection Framework — ADX-Validated Composite Rules](https://github.com/azdabat/Minimum-Truth-Detection-Framework-ADX-Validated-Composite-Rules)**
> repository where it becomes a production composite with full HunterDirective output.

---

## Table of Contents

- [Mission Statement](#mission-statement)
- [The Problem This Repository Solves](#the-problem-this-repository-solves)
- [Methodology](#methodology)
- [The POC-to-Production Pipeline](#the-poc-to-production-pipeline)
- [Threat Ecosystems Covered](#threat-ecosystems-covered)
- [Threat Modelling Framework — The SOP](#threat-modelling-framework--the-sop)
- [Multi-Surface Observability Model](#multi-surface-observability-model)
- [Repository Structure](#repository-structure)
- [Outputs](#outputs)
- [Roadmap](#roadmap)

---

## Mission Statement

```
To model, understand, and detect modern adversaries through their behaviour — not their payloads.

To provide SOC, IR, and Threat Hunting teams with a reusable methodology that captures
adversary intent, tradecraft, and kill-chain progression across all common attack ecosystems.

To build the research pipeline that feeds production-grade detection engineering.
```

**Three operational objectives:**

```mermaid
graph TD
    O1["🔬 Threat Modelling\nDecompose attacks into behavioural stages\nobservable across endpoint, identity,\nnetwork, and cloud telemetry"]
    O2["🎯 Core Hunt Development\nProduce patch-resistant behavioural POCs\nthat surface the earliest detectable stages\nacross multiple attack families"]
    O3["⚙️ Operational Alignment\nGive analysts repeatable playbooks,\nMITRE mappings, and pivot paths\nthat reduce investigation time"]

    O1 --> Pipeline["Detection Engineering Pipeline\nPOC → Validated → Production Composite"]
    O2 --> Pipeline
    O3 --> Pipeline

    style O1 fill:#1F4E79,color:#fff
    style O2 fill:#1F4E79,color:#fff
    style O3 fill:#1F4E79,color:#fff
    style Pipeline fill:#006400,color:#fff
```

---

## The Problem This Repository Solves

### Why Signatures and IOCs Fail Modern Adversaries

```mermaid
graph LR
    subgraph Old["❌ Signature-Based Model (Broken)"]
        S1["Vendor publishes IOC\nFile hash / IP / domain"]
        S2["SOC adds to blocklist"]
        S3["Attacker changes payload\nNew hash in minutes"]
        S4["IOC stale — attack continues"]
        S1 --> S2 --> S3 --> S4 --> S1
    end

    subgraph New["✅ Behavioural Model (This Repository)"]
        B1["Model the adversary's\nrequired actions"]
        B2["Build detection anchored\non those actions"]
        B3["Attacker changes payload\nbehaviour unchanged"]
        B4["Detection fires regardless\nof tool or hash"]
        B1 --> B2 --> B3 --> B4 --> B2
    end
```

Modern sophisticated adversaries — ransomware crews, nation-state APTs, identity-first
intruders — operate on a simple operational principle: **rotate the tool, preserve the
tradecraft**. New payload, same behaviour. New infrastructure, same technique.

A detection anchored on a file hash dies the moment the attacker recompiles. A detection
anchored on the **sequence of actions an attacker must perform** never becomes stale.

This is the philosophical foundation of every model in this repository.

### Attack Categories That Cannot Be Solved With Signatures

| Attack Category | Why Signatures Fail | Behavioural Anchor |
|----------------|--------------------|--------------------|
| Ransomware ecosystems | New encryptor binary on every campaign | Backup deletion → mass file rename sequence |
| Identity intrusions | No malware — uses legitimate credentials | Anomalous logon path + admin tool deployment |
| Steganographic loaders | Payload inside signed image file | Browser parent → image load → script spawn chain |
| LOLBIN post-exploitation | Uses Windows-signed binaries | Signed binary + anomalous argument + network callback |
| BYOVD driver chains | Byte-flipped driver — unique hash every time | Sideload → driver stage → service → kernel load |
| MFA fatigue / coercion | No technical exploit | Authentication anomaly + MFA response pattern |
| Token abuse | Legitimate OAuth tokens — no malware | Token scope anomaly + lateral cloud movement |

---

## Methodology

### Four Principles

```mermaid
mindmap
  root((Behavioural\nThreat Modelling))
    Behaviour Over Indicators
      Credentials abuse pattern
      Lateral movement chain
      Backup destruction sequence
      LOLBIN admin tool abuse
      Cloud identity impersonation
    Kill-Chain Pattern Modelling
      MITRE ATT&CK mapping
      Lockheed Cyber Kill Chain
      Behavioural sequences over time
      Cross-surface telemetry correlation
    Patch-Resistant Modelling
      Ransomware behaviour chains
      Identity-first intrusions
      Steganographic loader chains
      Living-off-the-land post-exploitation
      MFT and trusted tool abuse
    Multi-Surface Observability
      Endpoint MDE
      Identity Entra ID
      Network telemetry
      Cloud Apps M365
      Perimeter logs
```

### Principle 1 — Behaviour Over Indicators

Threat actors routinely change payloads, hosting providers, infrastructure, and loaders.
What they **cannot easily change** are their behaviours:

- Credential access patterns (LSASS, DCSync, Kerberoasting)
- Lateral movement sequences (SMB → WMI → WinRM fallback chains)
- Pre-ransomware preparation (shadow deletion, backup destruction, recovery disable)
- Abuse of legitimate administrative tools (PsExec, RMMs, WMI, RDP)
- Cloud and identity impersonation sequences (token abuse, OAuth consent, MFA coercion)

Every model in this repository is anchored on these **immutable behavioural constants**.

### Principle 2 — Kill-Chain Pattern Modelling

Every attack, regardless of tooling, follows a detectable pattern:

```
A valid account misused outside normal hours
  → A host enumerating AD shortly after a new login
  → Admin tools deployed to multiple hosts in a short window
  → Backup deletion executed
  → Mass file rename begins
```

This is a **behavioural kill chain** — detectable at multiple points, regardless of which
specific tools the attacker used for each stage. We map these patterns using MITRE ATT&CK,
the Lockheed Cyber Kill Chain, and cross-surface telemetry correlation.

### Principle 3 — Patch-Resistant Threat Modelling

Some attack ecosystems are structurally resistant to patching:

```mermaid
graph TD
    subgraph Unpatchable["Attack Categories That Patching Cannot Solve"]
        U1["Ransomware deployment\nBehaviour is constant\nPayload is variable"]
        U2["Identity-first intrusions\nNo exploit — valid credentials\nPatch surfaces nothing"]
        U3["Steganographic loaders\nPayload in signed image\nNo known-bad file"]
        U4["Living-off-the-land\nSigned Windows binaries\nNo malicious executable"]
        U5["BYOVD driver chains\nSigned driver — valid cert\nByte-flipped hash always novel"]
    end

    subgraph Response["Behavioural Defence"]
        R1["Model the required action sequence\nDetect the sequence — not the tool\nPatch-resistant by design"]
    end

    Unpatchable --> Response
```

### Principle 4 — Multi-Surface Observability

High-value detection emerges from **cross-joining telemetry surfaces** — not from looking
at any single table in isolation.

| Surface | Primary Value | Key Telemetry |
|---------|--------------|---------------|
| **Endpoint (MDE)** | Process chains, LOLBins, file events, LSASS access, encryption patterns | DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents |
| **Identity (Entra ID)** | MFA reset, token abuse, valid credential anomalies, impossible travel | IdentityLogonEvents, IdentityQueryEvents, SigninLogs |
| **Network** | C2 beaconing, lateral movement, data staging, exfiltration | DeviceNetworkEvents, CommonSecurityLog |
| **Cloud Apps (M365)** | App impersonation, consent abuse, service principal creation | CloudAppEvents, OfficeActivity, AuditLogs |
| **Perimeter Logs** | Reverse proxy signals, webshell indicators, unusual POST patterns | Custom connector tables, WAF logs |

---

## The POC-to-Production Pipeline

This is the most important architectural concept in this repository.

```mermaid
graph LR
    subgraph Lab["🔬 This Repository — POC Laboratory"]
        L1["Attack ecosystem modelled\nfrom offensive perspective"]
        L2["Behavioural anchors identified\nMinimum truth candidates"]
        L3["POC query written\nBroad time windows\nHigh noise acceptable\nNot production-safe"]
        L4["Validated against:\n- Real attack telemetry\n- Empire C2 simulation\n- Atomic Red Team\n- Manual red team output"]
        L1 --> L2 --> L3 --> L4
    end

    subgraph Gate["Promotion Criteria"]
        G1["✅ At least one confirmed true positive\n✅ False positive pattern understood\n✅ Truth anchor clearly defined\n✅ Cousin surfaces identified\n✅ Noise suppression logic designed"]
    end

    subgraph Prod["⚙️ Production Repository — ADX-Validated Composites"]
        P1["POC refined into composite rule\nNarrow time windows\nScoring model added\nHunterDirective added\nNoise suppression applied\nADX-Docker validated"]
        P2["Published to:\nMinimum Truth Detection Framework\nADX-Validated Composite Rules"]
        P1 --> P2
    end

    Lab --> Gate --> Prod
```

**Why this separation matters:**

A POC query and a production rule serve completely different purposes. A POC explores
whether a technique is detectable and what the telemetry looks like. A production rule
must fire at the right time with the right confidence and give an analyst an actionable
directive. Collapsing these two phases produces rules that are either too noisy to trust
or too narrow to catch real attacks. The pipeline keeps them separate with a formal
promotion gate between them.

---

## Threat Ecosystems Covered

```mermaid
graph TD
    subgraph R["Ransomware Ecosystems"]
        R1["Black Basta / BlackSuit\nMulti-day intrusion patterns\nPsExec + RMM + credential abuse\nPre-encryption preparation chain"]
        R2["Medusa / Akira\nAutomated fleet encryption\nVSS destruction + bcdedit\nNetwork share targeting"]
    end

    subgraph I["Identity-First Intrusions"]
        I1["MFA Fatigue & Coercion\nHelpdesk social engineering\nMFA reset + valid account abuse\nNo malware — purely human"]
        I2["Token Abuse\nOAuth consent phishing\nRefresh token theft\nService principal creation"]
    end

    subgraph S["Steganographic Loaders"]
        S1["PNG/JPG Embedded Payloads\nImage-embedded .NET loaders\nBrowser parent spawn chain\nMemory-only execution"]
        S2["HTML Smuggling\nBase64 blob in HTML\nAutomatic browser download\nUser execution trigger"]
    end

    subgraph T["Trusted Tool Abuse"]
        T1["GoAnywhere / MFT\nTrusted transfer mechanisms\nPost-exploitation staging\nData exfiltration via legitimate channel"]
        T2["SharePoint Hybrid Abuse\nToken and app impersonation\nWebshell-less compromise\nPrivileged service abuse"]
    end

    subgraph N["Novel Tradecraft (Separate Repository)"]
        N1["SilverFox / ValleyRAT BYOVD\nDLL sideloading + kernel rootkit\nByte-flipping driver mutation\nEDR blinding chain"]
        N2["EtherRAT / React2Shell\nBlockchain C2 delivery\nIIS exploit chain\nCVE-2025-55182"]
        N3["Steganographic Loader Chains\nMulti-phase detection research\nMemory + image + chain sensors"]
    end
```

---

## Threat Modelling Framework — The SOP

### The Six-Step Model

```mermaid
flowchart TD
    S1["Step 1\nDefine the Attack Ecosystem\nWhich adversary category?\nWhich tooling family?\nWhich target environment?"] --> S2

    S2["Step 2\nMap Each Stage to MITRE\nTactic → Technique → Sub-technique\nExpected telemetry tables\nPivot fields and time windows"] --> S3

    S3["Step 3\nDetermine Observable Telemetry\nWhich logs exist for this technique?\nWhich often do NOT exist?\nWhat gaps can behaviour compensate?"] --> S4

    S4["Step 4\nBuild Behavioural Anchors\nNon-negotiable behaviours regardless\nof payload or tool variation\nThese become truth anchor candidates"] --> S5

    S5["Step 5\nConstruct POC Hunts Around Anchors\nHigh-signal, low-noise focus\nMulti-table correlation\nSequences within 30–120 minutes\nAnomaly relative to org baseline"] --> S6

    S6["Step 6\nValidate Against Real Attack Chains\nOperator workflow timing\nEvasion patterns\nKnown post-exploitation frameworks\nHost-to-host traversal patterns"]

    S6 -->|"Validated"| Pipeline["Promote to Production\nMinimum Truth Composite Rules"]
    S6 -->|"Needs refinement"| S4
```

### Step 2 Detail — MITRE Mapping Template

Every ecosystem is mapped at the full depth of MITRE — not just technique labels but
the specific observable telemetry, pivot fields, and sequence context.

**Example: Black Basta Ecosystem Mapping**

| Stage | MITRE ID | Technique | Observable | Table | Pivot Field |
|-------|----------|-----------|------------|-------|-------------|
| Initial Access | T1566.001 | Spear-phishing attachment | Office macro spawning wscript | DeviceProcessEvents | InitiatingProcessFileName |
| Credential Access | T1003.001 | LSASS MiniDump | comsvcs.dll + MiniDump in CL | DeviceProcessEvents | ProcessCommandLine |
| Lateral Movement | T1021.002 | SMB PsExec | services.exe spawning cmd/ps | DeviceProcessEvents | InitiatingProcessFileName |
| Lateral Movement | T1219 | AnyDesk / ScreenConnect | Known RMM binary from user path | DeviceProcessEvents | FolderPath |
| Defense Evasion | T1562.001 | Shadow copy deletion | vssadmin delete + bcdedit /set | DeviceProcessEvents | FileName |
| Impact | T1486 | Data encryption | Mass file rename with new extension | DeviceFileEvents | FileName |

### Step 4 Detail — Behavioural Anchor Examples

```mermaid
graph LR
    subgraph Anchors["Immutable Behavioural Anchors"]
        A1["LSASS access\nalways precedes\ndomain escalation"]
        A2["Backup deletion\nalways precedes\nransomware encryption"]
        A3["New RMM agent install\nalways precedes\noperator hands-on-keyboard"]
        A4["Script → LOLBin chain\nalways precedes\nin-memory payload delivery"]
        A5["Mass file rename spike\nalways indicates\nactive encryption in progress"]
    end

    subgraph Detection["Detection Anchored On Behaviour"]
        D1["LSASS composite\nDetects all methods:\ncomsvcs, procdump, PS, direct"]
        D2["Pre-encryption composite\nvssadmin + bcdedit + wbadmin\nin short time window"]
        D3["RMM composite\nKnown RMM from user path\n+ first-seen on device"]
        D4["LOLBin stager composite\nScript + download + drop\nwithin 45-minute window"]
        D5["Encryption detection\nMass rename spike\n+ extension entropy analysis"]
    end

    A1 --> D1
    A2 --> D2
    A3 --> D3
    A4 --> D4
    A5 --> D5
```

---

## Multi-Surface Observability Model

The most sophisticated detections emerge from correlating observables across multiple
telemetry surfaces simultaneously. A signal that is noise on one surface becomes a
high-confidence indicator when correlated with a signal from another.

```mermaid
graph TD
    subgraph EP["Endpoint — MDE"]
        E1["PowerShell encoded command\nLow confidence alone"]
        E2["LSASS memory access\nHigh confidence — immediate action"]
        E3["RMM tool from unusual path\nMedium confidence"]
    end

    subgraph ID["Identity — Entra ID / Active Directory"]
        I1["New logon from first-seen country\nMedium confidence alone"]
        I2["Admin account suddenly active\nafter months of dormancy\nHigh confidence"]
        I3["MFA prompt accepted\nimmediately after MFA fatigue pattern\nHigh confidence"]
    end

    subgraph NW["Network"]
        N1["Low-volume HTTPS POST\nevery 60 seconds\nMedium confidence alone"]
        N2["Outbound to rare ASN\nfollowing script execution\nHigh confidence"]
    end

    subgraph Cloud["Cloud — M365 / Entra"]
        C1["New OAuth consent grant\nto suspicious application\nHigh confidence"]
        C2["Service principal created\nwith broad Graph permissions\nCRITICAL"]
    end

    E1 & I1 & N1 -->|"Cross-surface correlation:\nSame entity + same timeframe"| CRITICAL["CRITICAL CONFIDENCE\nAll three surfaces confirm\nsame adversary activity\nHigh-fidelity incident"]

    E2 & I2 --> HIGH["HIGH CONFIDENCE\nTwo independent surfaces\nconfirm same threat"]

    C2 --> CRITICAL
```

### Cross-Surface Correlation Examples

| Endpoint Signal | Identity Signal | Combined Confidence | Likely Scenario |
|----------------|-----------------|--------------------|--------------------|
| PowerShell encoded command | First-seen country logon same account | CRITICAL | Compromised account post-initial access |
| LSASS memory dump | Dormant admin account suddenly active | CRITICAL | Credential harvesting in progress |
| RMM tool deployed | MFA fatigue pattern on same account | CRITICAL | Black Basta-style hands-on-keyboard operator |
| Mass file rename spike | No identity anomaly | HIGH | Automated encryption — no hands-on operator |
| certutil download | New OAuth consent grant | HIGH | Payload delivery + persistence via app registration |

---

## Repository Structure

```plaintext
THREAT-MODELLING-SOP/
│
├── README.md                          ← This document
│
├── /Core-Hunts/                       ← POC hunt queries (not production)
│   ├── BlackBasta_Core.md             ← Ransomware behavioural chain POC
│   ├── Identity-Abuse_Core.md         ← MFA coercion + token abuse POC
│   ├── StegoLoader_Core.md            ← Steganographic loader chain POC
│   ├── GoAnywhere_Core.md             ← MFT trusted tool abuse POC
│   └── SharePoint_Core.md             ← Token + app impersonation POC
│
├── /Attack-Models/                    ← Offensive perspective breakdowns
│   ├── BlackBasta_AttackChain.md      ← Full Black Basta kill chain analysis
│   ├── IdentityAbuse_AttackChain.md   ← Identity-first intrusion model
│   ├── StegoLoader_AttackChain.md     ← Steganographic loader offensive model
│   ├── GoAnywhere_AttackChain.md      ← MFT post-exploitation model
│   └── SharePoint_AttackChain.md      ← SharePoint hybrid abuse model
│
├── /MITRE-Mapping/                    ← ATT&CK mapping tables
│   └── MITRE_MasterTable.md           ← Full cross-ecosystem MITRE index
│
└── /Promoted-To-Production/           ← Index of rules promoted to composite pack
    └── PROMOTION_LOG.md               ← POC → Production lineage record
```

---

## Outputs

This repository will produce the following artefacts across all threat ecosystems:

```mermaid
graph TD
    Research["Threat Research\n& Attack Modelling"] --> O1
    Research --> O2
    Research --> O3
    Research --> O4
    Research --> O5
    Research --> O6

    O1["📋 Core Hunts Pack\nBehavioural baseline POCs\nacross all ecosystems"]
    O2["🗺️ Attack Chain Models\nAdversary perspective breakdowns\nfor each ecosystem"]
    O3["🎯 MITRE Mapping Tables\nFull ATT&CK coverage with\ntelemetry and pivot field mapping"]
    O4["🔍 Analyst Investigative Guides\nStep-by-step investigation\npaths for each ecosystem"]
    O5["⚡ Advanced Scoring Engine\nRisk-based alerting logic\nfor complex chains"]
    O6["🔗 Kill-Chain Correlation Framework\nCross-surface, cross-session\nincident narrative stitching"]

    O1 & O2 & O3 & O4 & O5 & O6 --> Promote["Promotion Gate\nValidated POCs promoted to\nMinimum Truth Composite Rules"]
```

---

## Target Audience

```
👥 Senior SOC Analysts        — Threat context and hunt queries
🔍 Incident Responders        — Attack chain models and IR pivots
🎯 Threat Hunters             — Hypothesis-driven POC hunt library
⚙️  Detection Engineers       — POC-to-production promotion pipeline
🔴 Red Teamers (Blue Focus)   — Defensive insight into their own techniques
```

---

## Roadmap

```mermaid
gantt
    title Threat Modelling SOP — Delivery Roadmap
    dateFormat  YYYY-MM
    section Phase 1
    Core Hunts — All Ecosystems        :p1, 2025-12, 2026-02
    section Phase 2
    Advanced Behavioural Packs         :p2, after p1, 2026-04
    section Phase 3
    Kill-Chain Correlation Framework   :p3, after p2, 2026-06
    section Phase 4
    Identity & Cloud Threat Expansion  :p4, after p3, 2026-08
    section Phase 5
    Cross-Surface Analytics Engine     :p5, after p4, 2026-10
```

| Phase | Deliverable | Status |
|-------|-------------|--------|
| Phase 1 | Core Hunts for all behavioural ecosystems | 🟡 In Progress |
| Phase 2 | Advanced behavioural packs (scoring, chained sequences) | 🔴 Planned |
| Phase 3 | Full kill-chain correlation framework | 🔴 Planned |
| Phase 4 | Identity & cloud threat expansion (OAuth, token abuse) | 🔴 Planned |
| Phase 5 | Cross-surface analytics (endpoint + identity + cloud) | 🔴 Planned |

---

> [!NOTE]
> All content in this repository represents original threat research and proof-of-concept
> detection logic. Nothing here should be deployed directly to a production environment
> without ADX-Docker validation, noise profiling, and promotion through the pipeline
> documented above.

> [!TIP]
> **For production-ready detection rules**, visit the
> **[Minimum Truth Detection Framework — ADX-Validated Composite Rules](https://github.com/azdabat/Minimum-Truth-Detection-Framework-ADX-Validated-Composite-Rules)**
> repository where all promoted rules live.

---

*Author: Ala Dabat | [github.com/azdabat](https://github.com/azdabat)*  
*Licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode)*
