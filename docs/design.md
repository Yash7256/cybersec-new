# GeoIP Scan Results — Design Documentation

**Figma reference:** node `2290:37` — "MacBook Pro 16' - 16"
**Screen:** GeoIP tool results page (post-scan state) — CYBERSEC UI
**Viewport:** Desktop, 1512px design frame (content column ~1240px, 20px side gutters scaled)

---

## 1. Screen Purpose

Shows the result of a completed GeoIP lookup for a target (`scanme.nmap.org`). Displays resolved IP, ISP/ASN/org, geolocation, network/security/DNS metadata, all resolved IPs, provider info, and export/share actions. Sidebar provides navigation to the other 9 recon tools plus account/upgrade actions.

---

## 2. Layout Structure

```
┌─────────────────────────────────────────────────────────────────┐
│ NAVBAR (logo left, Sign In / Log In right)                       │
├───────────────┬─────────────────────────────────────────────────┤
│               │ SCAN INPUT BAR (target + Run Scan button)        │
│  SIDEBAR      ├─────────────────────────────────────────────────┤
│  - Tool nav   │ SECTION 1: Hero / Summary                        │
│    (10 items) │   - domain title + share icon                    │
│  - Upgrade    │   - status pills (Lookup Completed, IP, time,    │
│    to Pro     │     cache source)                                │
│    card       │   - AI insight banner                            │
│  - Saved      │   - 6 stat cards (IP, ASN, ISP, Org, Type,       │
│    Reports /  │     Confidence w/ progress bar)                  │
│    History /  ├─────────────────────────────────────────────────┤
│    Settings / │ LOCATION section                                 │
│    Help       │   - left: details table (Country…UTC offset) +  │
│               │     "Open in Google Maps / Earth" links          │
│               │   - right: static map image                      │
│               │   - below: 3 info cards (Network / Security /    │
│               │     DNS)                                          │
│               ├─────────────────────────────────────────────────┤
│               │ ALL RESOLVED IPs section (list card)             │
│               ├─────────────────────────────────────────────────┤
│               │ PROVIDER INFORMATION section (2 cards)           │
│               ├─────────────────────────────────────────────────┤
│               │ EXPORT & SHARE section (4 action cards)          │
└───────────────┴─────────────────────────────────────────────────┘
```

Sidebar is fixed-width (~306px content + padding), main content area fills remainder with a consistent ~1240px max content width.

---

## 3. Design Tokens

### Color Palette
| Token | Value | Usage |
|---|---|---|
| `--bg-gradient-start` | `#3a1b57` | Page background gradient top |
| `--bg-gradient-mid` | `#130c20` | Page background gradient mid (3.9%) |
| `--bg-gradient-end` | `#1a0d2e` | Page background gradient bottom |
| `--surface-card` | `#201330` | Section container background (LOCATION, PROVIDER, SHARE, ALL RESOLVED IPs, SECTION 1) |
| `--surface-inset` | `#190f23` | Nested/inner cards (stat cards, info cards, list items, export buttons) |
| `--accent-primary` | `#ba9cff` | Section headings, active nav item bg, links, primary button gradient start |
| `--accent-primary-dark` | `#8b5cf6` | Primary button gradient end |
| `--accent-secondary` | `#3a1b57` → `#150c24` | Scan input bar gradient |
| `--text-primary` | `#ffffff` | Primary text/values |
| `--text-secondary` | `#aaaaaa` | Labels/secondary text |
| `--text-muted` | `rgba(255,255,255,0.8)` | Inactive nav item text |
| `--border-subtle` | `rgba(255,255,255,0.14)` | Outer card borders |
| `--border-medium` | `rgba(255,255,255,0.27)` | Nav items, input bar border |
| `--border-strong` | `rgba(255,255,255,0.5)` | Stat card borders, table container border |
| `--success` | `#57c254` | "Lookup Completed" dot/text, Edge/CDN pill, confidence bar fill |
| `--success-bg` | `rgba(87,194,84,0.29)` | Edge/CDN pill background |
| `--warning-bg` | `#46351e` | IPv4 tag background |
| `--warning-text` | `#ffd38a` | IPv4 tag text |
| `--info-bg` | `#24324a` | Provider tag (Akamai) background |
| `--info-text` | `#a9c7ff` | Provider tag text |
| `--upgrade-accent` | `#ff9a3c` | "Upgrade to Pro" heading |

### Typography
- **Font family:** `Satoshi` (Regular / Medium / Bold / Light weights); logo uses `Melete Light`.
- **Section headings** (LOCATION, PROVIDER INFORMATION, EXPORT & SHARE, ALL RESOLVED IPs): 25px, Satoshi Medium, `--accent-primary`, uppercase where noted.
- **Domain title (hero):** 35px, Satoshi Medium, white.
- **Stat card value:** ~15px, Satoshi Medium, white.
- **Stat card label:** ~10px, Satoshi Bold, white, uppercase-ish icon label.
- **Body/table text:** 13–15px, Satoshi Regular, white (values) / `#aaa` (labels).
- **Nav item text:** 21px, Satoshi Regular.

### Radii & Borders
- Outer section cards: `12px` radius, `1px` border `rgba(255,255,255,0.14)`.
- Inner cards (stat/info cards): `10–12px` radius, `~0.5px` border `rgba(255,255,255,0.5)` or `0.27` opacity variants.
- Pills/tags/nav buttons: fully rounded (`9999px`).
- Nav sidebar items: `20px` radius.

### Spacing
- Section vertical rhythm: large sections separated by ~40–60px gaps.
- Card internal padding: ~25–30px.
- Grid gaps between stat cards / info cards: ~19–20px.

---

## 4. Component Inventory

### 4.1 Top Navbar
- Logo mark + "CYBERSEC" wordmark (left).
- "Sign In" (glassmorphic outline pill button) + "Log In" (white gradient filled pill button) — right aligned.

### 4.2 Sidebar Navigation
- 10 tool nav items, icon + label, pill-shaped (20px radius), full width:
  1. Unified Scan (location-fill icon)
  2. **Geo IP** — active state: `#ba9cff` filled background, dark text
  3. WHOIS
  4. Subdomains
  5. Port Scanner
  6. Ping
  7. Traceroute
  8. HTTP Headers
  9. SSL Check
  10. Web App Scanner
- "Upgrade to Pro" promo card: gradient background, heading (orange), description, gradient pill CTA button "Upgrade Now".
- Secondary nav group: Saved Reports, Scan History, Settings, Help & Docs (icon + label rows) + copyright footer text.

### 4.3 Scan Input Bar
- Rounded gradient input field showing target `scanme.nmap.org` with a clear/reset icon.
- "Run Scan →" gradient pill button (purple gradient, arrow icon rotated 90°).

### 4.4 Hero / Summary Card (Section 1)
- Domain title + external-link/share icon.
- Status pill row: "Lookup Completed" (green dot + check icon), IP address pill (location icon), duration pill (clock icon), cache-source pill (storage icon).
- AI insight banner: info icon + one-line summary text on a subtle gradient strip.
- 6 stat cards in a row: IP Address, ASN, ISP, Organization, IP Type, Confidence Score (with a horizontal progress bar under the confidence card, ~90% green fill).

### 4.5 LOCATION Section
- Left: key/value details table with divider lines — Country (+ flag icon), Continent, Region, City, Postal code, Coordinates, Timezone, UTC offset — followed by "Open in Google Maps" and "Open in Google Earth" links (icon + purple text).
- Right: static map image (rounded, bordered) showing pin/location context.
- Below (3-column row): Network Information card (ISP, Organization, ASN, ASN Domain, Calling Code), Security Information card (CDN, CDN Provider, Proxy, Hosting, Confidence, Location Accuracy), DNS Information card (Target, Resolved IPs list, Reverse DNS). Each card has a purple dot + uppercase label header.

### 4.6 ALL RESOLVED IPs Section
- List card containing one (or more) IP row entries. Each row:
  - Green status dot + IP address (bold, large).
  - Type tag ("IPv4", amber).
  - Provider tag ("Akamai", blue).
  - Right-aligned descriptive sentence.
  - Below: "Edge/CDN" pill (green) + country/flag, ASN, Org, City, Reverse DNS mini key-value grid.

### 4.7 PROVIDER INFORMATION Section
- Two side-by-side cards: "Provider" (building icon, value "IPWHOIS") and "Cached" (database icon, value "Yes").

### 4.8 EXPORT & SHARE Section
- Description line: "Download or share your scan report."
- 4 equal-width action cards in a row, each icon + label: Export PDF, Export JSON, Export CSV, Share report.

---

## 5. Interaction Notes (inferred, confirm with product)
- Sidebar active state = filled purple pill (Geo IP currently active).
- Run Scan button likely triggers new lookup; disabled/loading state not shown in this frame — recommend a spinner variant.
- "Open in Google Maps/Earth" links should open external URLs in a new tab using the resolved coordinates.
- Export buttons trigger file download (PDF/JSON/CSV) or open native share sheet / copy-link modal.
- Confidence Score bar width should be driven by the numeric confidence value returned by the API (currently visually ~90%).

---

## 6. Data Contract (fields the UI expects from the backend)

```ts
interface GeoIPResult {
  target: string;
  status: "completed" | "failed" | "running";
  resolvedIp: string;
  ipType: "IPv4" | "IPv6";
  scanDurationSeconds: number;
  cacheSource?: string; // e.g. "IPWHOIS"
  asn: string;
  isp: string;
  organization: string;
  proxyOrCdn: boolean;
  confidenceScore: "Low" | "Medium" | "High";
  aiSummary: string;
  location: {
    country: string; countryCode: string;
    continent: string; continentCode: string;
    region: string; city: string; postalCode: string;
    latitude: number; longitude: number;
    timezone: string; utcOffset: string;
  };
  network: { isp: string; organization: string; asn: string; asnDomain: string; callingCode: string };
  security: { cdn: boolean; cdnProvider: string; proxy: boolean; hosting: boolean; confidence: string; locationAccuracy: string };
  dns: { target: string; resolvedIps: string[]; reverseDns: string };
  resolvedIps: Array<{
    ip: string; type: "IPv4" | "IPv6"; provider: string; edgeCdn: boolean;
    country: string; countryCode: string; asn: string; org: string; city: string; reverseDns: string;
    summary: string;
  }>;
  provider: { name: string; cached: boolean };
}
```