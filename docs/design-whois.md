# WHOIS Scan Results — Design Documentation

**Figma reference:** node `2346:2` — "MacBook Pro 16' - 18"
**Screen:** WHOIS tool results page (post-scan state) — CYBERSEC UI
**Viewport:** Desktop, 1512px design frame (content column ~1240px)

Shares the base shell (navbar, sidebar, scan input bar, upgrade card, other-options card) with the GeoIP results screen — see `design-geoip.md` for those shared tokens/components. This doc covers only what's new/different for WHOIS.

---

## 1. Screen Purpose

Shows the result of a completed WHOIS lookup for a domain (`scanme.nmap.org`). Displays registrar/registration data, a domain-age timeline, a health-score gauge, a risk overview, status/contact/nameserver detail, RDAP/related-data notes, and a raw WHOIS record viewer with a Formatted/Raw Text toggle.

Sidebar: **WHOIS** is the active nav item (filled purple pill) instead of Geo IP.

---

## 2. Layout Structure

```
┌───────────────┬─────────────────────────────────────────────────┐
│               │ SCAN INPUT BAR (shared component)                │
│  SIDEBAR      ├─────────────────────────────────────────────────┤
│  (WHOIS       │ SECTION 1: Hero / Summary                        │
│   active)     │   - domain title + share icon                    │
│               │   - status pills (WHOIS Retrieved, duration,     │
│               │     retrieved timestamp)                         │
│               │   - AI insight banner                            │
│               ├─────────────────────────────────────────────────┤
│               │ DOMAIN TIMELINE section                          │
│               │   - horizontal timeline bar w/ 4 milestone icons │
│               │     (Domain Age / Updated / Expires /            │
│               │     Until Expiry) + labels                       │
│               │   - 3 status cards: Status / Privacy /           │
│               │     Transfer Lock                                │
│               ├─────────────────────────────────────────────────┤
│               │ 2-column: Registrar Information | Registration   │
│               │ Information (key/value tables)                   │
│               ├─────────────────────────────────────────────────┤
│               │ 2-column: Domain Health Score (donut gauge +     │
│               │ checklist) | Risk Overview (icon + checklist)    │
│               ├─────────────────────────────────────────────────┤
│               │ 3-column: Status Information | Contact           │
│               │ Information | Server Names                      │
│               ├─────────────────────────────────────────────────┤
│               │ 2-column: RDAP/IANA Information | Related Data   │
│               ├─────────────────────────────────────────────────┤
│               │ Raw WHOIS Record panel                           │
│               │   - header: title + Formatted/Raw Text toggle    │
│               │   - monospace-style key:value dump (scroll area) │
│               │   - footer: terms-of-use note + "View Full       │
│               │     Terms ↗" button                               │
└───────────────┴─────────────────────────────────────────────────┘
```

---

## 3. Design Tokens (deltas from GeoIP screen)

Reuses the same base palette (`#3a1b57`→`#1a0d2e` bg gradient, `#201330` section surface, `#190f23` inset cards, `#ba9cff` accent, Satoshi type family). Additions specific to this screen:

| Token | Value | Usage |
|---|---|---|
| `--danger-text` | `#ff927c` | "Available: No" negative value |
| `--success-text` | `#7cff9a` / `#7cee79` | "Healthy" / "Excellent" / "Low Risk" status text, gauge stroke |
| `--warning-pill-bg` | `rgba(253,192,120,0.2)` | "Privacy Prohibited" badge background |
| `--warning-pill-text` | `#fdc078` | "Privacy Prohibited" badge text |
| `--raw-key-text` | `#ffca75` | Raw WHOIS record field-name color |
| `--raw-value-text` | `#aaaaaa` | Raw WHOIS record field-value color |
| `--code-surface` | `#201330` (inside `#190f23` outer panel) | Raw record scroll container background |
| `--toggle-active-bg` | `#ba9cff` | Formatted/Raw Text active toggle pill |

### Typography additions
- Health score gauge center value: 26.8px Satoshi Bold, white, with a smaller "/100" suffix at 13.4px.
- Status label under gauge ("Excellent" / "Low Risk"): 30px Satoshi Bold, `--success-text`.
- Raw WHOIS record: monospace-styled small text (~10–11px), field labels bold amber, values regular gray.

---

## 4. Component Inventory (new for this screen)

### 4.1 Domain Timeline
- Horizontal track/bar spanning the section width with 4 evenly-spaced milestone markers (icons), each with a 2-line label stack below: title (12px gray) + value (16px white) — first milestone ("Domain Age") additionally has a large green value line ("9985 days") and a "Since <date>" sub-label.
- Milestones: Domain Age, Updated, Expires, Until Expiry.
- Below the timeline: 3 equal-width summary cards (Status / Privacy / Transfer Lock), each with an icon badge, bold label, large value line, and small description line.

### 4.2 Registrar Information / Registration Information cards
- Two side-by-side glass cards, each with a purple-dot section header.
- Key/value rows with divider lines: Registrar, Registrar URL (purple link + external-open icon), Registry, IANA ID, Abuse email, Abuse Phone (left card) / Domain, Available, Creation Date, Updated Date, Expiration Date, Domain Age (days), Days Until Expiry, Expiry Status (colored), Protected (right card).
- Negative/critical values (e.g. "Available: No") render in `--danger-text`; healthy status values (e.g. "Expiry Status: Healthy") render in `--success-text`.

### 4.3 Domain Health Score card
- Circular/donut gauge (two overlapping arcs simulating a gauge fill) centered, with numeric score + "/100" in the middle.
- Below gauge: bold status word ("Excellent") in green + one-line description.
- Checklist below: 5 rows, each a check-circle icon + descriptive sentence (e.g. "Valid registration", "Domain is active", "Not expired", "Transfer lock is enabled", "Privacy protection is enabled").

### 4.4 Risk Overview card
- Large centered risk/radar icon.
- Bold status word ("Low Risk") in green + one-line description.
- Checklist below: 5 rows (same check-icon pattern) — privacy protection enabled, no suspicious domain status, transfer lock enabled, expiry >2 years away, domain active and healthy.

### 4.5 Status / Contact / Server Names row (3 cards)
- **Status Information:** Domain Status (purple link + external-open icon), DNSSEC, Status Explanation (paragraph).
- **Contact Information:** Registrant Organization, Registrant Country (+ flag icon), Registrant Email (purple link), Admin Contact (+ "Privacy Prohibited" badge w/ lock icon), Tech Contact (+ same badge).
- **Server Names:** list of nameservers (ns1–ns4…) each with a small green check icon, plus a "Total Servers" count row.

### 4.6 RDAP/IANA Information / Related Data row (2 cards)
- **RDAP/IANA Information:** RDAP Available (No), RDAP Error (e.g. "302 Redirect"), IANA TLD.
- **Related Data:** repeated "Available: No" + "Reason: <paragraph>" blocks (e.g. historical WHOIS requires a paid provider) — appears twice (two related-data lookups).

### 4.7 Raw WHOIS Record panel
- Header row: "RAW WHOIS RECORD" title (purple) + a two-state segmented toggle ("Formatted" active / "Raw Text").
- Scrollable dark inset panel containing a monospace-styled key:value dump (Domain Name, Registry Domain ID, Registrar URL, Updated/Creation/Expiry dates, Registrar, IANA ID, Abuse contact email/phone, Domain Status, Name Servers ×N, DNSSEC, "last update of WHOIS database" footer line).
- Footer strip (subtle background): info icon + Terms-of-Use heading + description paragraph + "View Full Terms ↗" pill button (white, opens external link).

---

## 5. Interaction Notes (inferred)
- Formatted/Raw Text toggle switches the panel body between the parsed key/value view (used elsewhere on the page) and this literal raw-record dump — likely just re-renders the same panel content, not a separate fetch.
- External-link icons (Registrar URL, Domain Status, "View Full Terms") open in a new tab.
- Health Score gauge percentage and Risk Overview level should be computed server-side or derived client-side from the WHOIS response; do not hardcode "92/100" or "Low Risk".
- Privacy-protected contact fields ("Privacy Prohibited" badge) should render only when the registrar/registry actually redacts that field — don't fabricate placeholder emails.

---

## 6. Data Contract (fields the UI expects from the backend)

```ts
interface WhoisResult {
  target: string;
  status: "completed" | "failed" | "running";
  scanDurationSeconds: number;
  retrievedAt: string; // ISO timestamp, displayed as "May 20, 2025 11:02:29 PM"
  aiSummary: string;

  timeline: {
    domainAgeDays: number;
    registeredSince: string; // ISO date
    updatedDate: string;
    expiresDate: string;
    daysUntilExpiry: number;
  };

  registrar: {
    name: string;
    url: string;
    registry: string;
    ianaId: string;
    abuseEmail: string;
    abusePhone: string;
  };

  registration: {
    domain: string;
    available: boolean;
    creationDate: string;
    updatedDate: string;
    expirationDate: string;
    domainAgeDays: number;
    daysUntilExpiry: number;
    expiryStatus: "Healthy" | "Warning" | "Critical";
    protected: boolean;
  };

  healthScore: {
    score: number; // 0-100
    label: "Excellent" | "Good" | "Fair" | "Poor";
    summary: string;
    checks: Array<{ label: string; passed: boolean }>;
  };

  riskOverview: {
    level: "Low Risk" | "Medium Risk" | "High Risk";
    summary: string;
    checks: Array<{ label: string; passed: boolean }>;
  };

  statusInfo: {
    domainStatus: string;
    domainStatusUrl?: string;
    dnssec: string;
    statusExplanation: string;
  };

  contactInfo: {
    registrantOrganization: string;
    registrantCountry: string; // ISO country code for flag
    registrantEmail: string;
    adminContactRedacted: boolean;
    techContactRedacted: boolean;
  };

  serverNames: {
    nameservers: string[];
    totalServers: number;
  };

  rdap: {
    available: boolean;
    error?: string;
    ianaTld: string;
  };

  relatedData: Array<{
    available: boolean;
    reason: string;
  }>;

  rawRecord: string; // full raw WHOIS text blob
  termsUrl: string;
  termsSummary: string;
}
```