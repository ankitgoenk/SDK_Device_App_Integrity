# Privacy, Policy & Compliance

This SDK inspects the device environment and, in a limited way, which other apps are
installed. That is inherently privacy-sensitive and policy-sensitive. Getting it wrong risks
app removal from Google Play and regulatory exposure. Design accordingly.

## 1. Data minimisation rules (binding on every detector)

| Rule | Detail |
| --- | --- |
| **P1** | Never collect hardware or persistent identifiers: IMEI, serial, MAC, `ANDROID_ID`, advertising ID, SIM/subscriber data |
| **P2** | Never collect location, contacts, SMS, call logs, files, or clipboard |
| **P3** | Never collect a full installed-app inventory. Probe only a curated, documented list of packages tied to a specific threat |
| **P4** | Third-party package names leave the device only as `sha256(pkg)[0:16]` plus a threat category label. Clear names are permitted only in debug builds or with explicit host opt-in |
| **P5** | Evidence values are drawn from a documented, bounded key set per signal — never raw paths, dumps or user content |
| **P6** | The SDK performs no network IO. The host owns transport, consent and retention |
| **P7** | No persistent on-device storage of reports beyond an in-memory cache with a TTL |
| **P8** | Report payloads are capped (default 8 KB) and schema-validated before leaving the SDK |

CI check: a lint rule fails the build if a detector references a restricted API
(`TelephonyManager.getImei`, `Settings.Secure.ANDROID_ID`, `getInstalledPackages` without a
filter, location APIs).

## 2. Google Play policy

### `QUERY_ALL_PACKAGES`
Play treats it as a **restricted permission**: allowed only for a narrow set of use cases
(device search, antivirus, file managers, banking apps in specific contexts). Fraud/integrity
scanning is **not** a reliably accepted justification, and a declaration form is required.

**Our position:** the SDK never declares it. We ship an explicit `<queries>` list of the
packages we probe, with each entry documented in
[DETECTION_CATALOG.md](DETECTION_CATALOG.md). Hosts that already hold the permission for an
approved reason get broader coverage automatically; nobody adds it because of us.

### Accessibility services
Play forbids using `BIND_ACCESSIBILITY_SERVICE` for non-accessibility purposes. We do not
*implement* an accessibility service — we only read the list of *enabled* ones, which is
allowed. But:

- Never block or degrade a user solely because an accessibility service is enabled.
  Screen readers, switch access and magnification are assistive technology, and blocking them
  is both an accessibility failure and, in several jurisdictions, a legal risk.
- Prefer Play Integrity's `appAccessRiskVerdict` (Google's own capture/control assessment) or
  a curated list of known RAT packages over "any non-allow-listed service".
- Document this in the host's accessibility statement.

### Data safety declaration
If a host uploads reports, its Play Data Safety form should declare, at minimum:
- **Data type:** "App activity → Other app activity" and/or "Device or other IDs" if the host
  attaches its own device id.
- **Purpose:** Fraud prevention, security, and compliance.
- **Collection:** Required (not optional) if enforcement depends on it; encrypted in transit;
  state whether users may request deletion.

Provide integrators with the exact wording in the release notes (Phase 11 deliverable).

### Deceptive behaviour / malware policy
Everything the SDK does must be documented and defensible: no hidden data collection, no
undisclosed device fingerprinting, no dynamic code loading, no obfuscation of *behaviour*
(obfuscating *strings and constants* to resist reverse engineering is normal and acceptable;
hiding what the SDK does from the user or from Play is not).

## 3. GDPR / UK GDPR / India DPDP / CCPA

- **Lawful basis:** legitimate interest (fraud prevention and information security) is
  normally the right basis under GDPR Art. 6(1)(f), supported by Recital 49. It requires a
  documented Legitimate Interests Assessment — the host's job, but supply them a template.
- **Data controller:** the host app. The SDK vendor is at most a processor, and only if it
  ever receives data — which, by design (P6), it does not.
- **Transparency:** the host's privacy policy must describe the integrity checks and the
  categories of data collected.
- **Data subject rights:** reports must be deletable and exportable; that is why every report
  carries a `reportId` and the host controls storage.
- **Retention:** recommend ≤ 90 days for raw reports, longer only for aggregated risk
  features. Document it.
- **Automated decision-making:** if a report can, on its own, block a user from a service,
  GDPR Art. 22 may apply. Mitigate with human review paths and by never making the client
  verdict solely determinative — combine it with other risk inputs and provide an appeal
  route. This is a strong argument for "degrade and review" over "hard block".
- **Children's apps:** additional care; consider disabling `ENV_*` package probing entirely
  in apps targeting children.

## 4. Security of the pipeline

- Reports in transit: TLS with the host's certificate pinning.
- Reports at rest: encrypted, access-controlled, audited. Risk telemetry is attractive to
  attackers because it maps your defences.
- Never log full reports in host application logcat in release builds.
- Signing keys: Android Keystore, hardware-backed where available; backend verification keys
  rotated with `keyId` support.

## 5. Accessibility and fairness review (required before enforcement)

Before any integrator turns on enforcement, run through:

- [ ] Does any enforced signal correlate with assistive technology use?
- [ ] Does any enforced signal correlate with a region, OEM or price tier (e.g. sideload-heavy
      markets, `test-keys` ROMs on budget devices)?
- [ ] Is there a support path for a wrongly-blocked user, and can support see the `reportId`
      and the reason?
- [ ] Is there a remote kill switch for every enforced signal?
- [ ] Has the enforcement threshold been validated against at least one full release cycle of
      shadow-mode data?

An integrity SDK that disproportionately locks out users on cheap devices in one market is a
product failure even when every detection is technically correct.
