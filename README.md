# 360° B2B Revenue-Leak, Passive OSINT, GEO & Contact Enricher (Zero-Cognitive-Load Edition)

**The only B2B lead enrichment Actor that tells you *exactly* who to call, what to pitch, and what to say — in plain English, in 3 seconds, with zero spreadsheets and zero manual analysis.**

> Type a niche like `"MedSpas in Austin"` or paste a list of domains. Get back a prioritized list of leads with their **tech stack, Meta/TikTok/Google ad-pixel leaks, 2026 AI-GEO (ChatGPT/Perplexity) readiness, DNS/DMARC email-security score, decision-maker emails & phones, an estimated deal value, and a ready-to-send cold email** — all generated automatically. No Clay enrichment waterfall needed. No browser automation. No blocks.

---

## 🔥 Why agencies are switching to this Actor

Every other "website scraper" or "lead finder" on Apify Store dumps raw HTML, raw headers, and raw emails on you and calls it a day. You still have to:
- Manually check 10 tabs per lead (BuiltWith, Facebook Ad Library, MXToolbox, Google's Rich Results Test, SecurityHeaders.com...)
- Manually figure out *which* leak is worth pitching
- Manually write the cold email
- Manually guess the deal size

**This Actor does all of that for you, per lead, automatically.** It was built specifically for:

- 📈 **SMMA / Paid Ads agencies** — instantly see who's "Bleeding Paid Traffic (No Retargeting)"
- 🤖 **AI Automation / Chatbot agencies** — instantly see who has zero live-chat or AI chatbot
- 🔍 **SEO & 2026 AI-GEO agencies** — instantly see who's invisible to ChatGPT, Perplexity & Google AI Overviews (missing `llms.txt`, schema.org, OpenGraph)
- 🛡️ **IT / Cybersecurity MSPs** — instantly see who has no DMARC/SPF (email spoofing risk) and missing security headers
- 🧊 **Cold Email / Clay.com / n8n / Make power users** — push every enriched lead straight into your automation with the built-in webhook

---

## ⚡ Zero Cognitive Load: 6 columns that do 100% of the thinking

The first columns in your dataset answer "is this worth my time?" before you even open the spreadsheet:

| Column | Example |
|---|---|
| `leadPriority` | `🔥 HOT LEAD (92/100)` |
| `estDealValue` | `$2,000 - $5,000/mo` |
| `threeSecondSummary` | `💰 Has Google Tag Manager, but MISSING Meta Pixel + No AI Chatbot + Invisible to ChatGPT Search` |
| `whatToPitch` | `Meta/TikTok Retargeting Pixel Setup + Paid Ads Management Retainer` |
| `oneClickColdEmail` | A ready-to-send, hyper-personalized email referencing their exact company name + top 2 revenue leaks |
| `oneClickLoomScript` | 3 bullets telling you exactly what to screen-record for a 60-second audit video |

Everything else (tech stack, pixels, DNS, headers, GEO score, contacts) is included too — it's just not the first thing you have to read.

---

## 🧠 How it works (zero effort input)

1. **Type a plain-English search** like `"Roofing contractors in Dallas"` — **no URLs required.** We auto-discover real business websites via passive search and automatically filter out directories (Yelp, Yellow Pages, Facebook, LinkedIn, Instagram, YouTube, Reddit, Wikipedia, BBB, Angi, TripAdvisor, Forbes, G2, Capterra, etc.) so you only get real, pitchable company domains.
2. **…or paste your own list of domains/URLs** — we'll audit exactly those.
3. **Pick your Agency Type** (All-in-One / Paid Ads / AI Automation / SEO-GEO / IT-Security) and the pitch, deal value and cold email auto-adjust to the service *you* sell.
4. Hit **Start**. Get a clean, prioritized dataset in minutes — export to CSV/Excel/JSON, or push live to **Clay, Make, or n8n** with the built-in webhook.

---

## 🔬 What gets audited for every lead (100% passive, 100% white-hat, zero blocks)

This Actor **never uses Playwright/Puppeteer** and **never scans ports or sends intrusive payloads**. It only reads what's publicly, passively available — standard HTTP responses, DNS records, and public text files. That means it's fast (no browser), cheap (low compute units), and essentially unblockable.

### 1. Auto-Search Discovery Engine
Smart multi-query DuckDuckGo discovery with automatic directory/aggregator filtering, so every result is a real, root business domain — not a Yelp listing.

### 2. 2-Hop Smart Internal Contact Crawler
We don't just scrape the homepage. We parse internal links and automatically crawl up to 2 extra high-value pages (`/contact`, `/about`, `/team`, `/support`, `/impressum`) in parallel to extract **3x more decision-maker emails, phones, WhatsApp links, and social profiles** (LinkedIn, Instagram, X/Twitter, Facebook, YouTube, TikTok). Emails are de-obfuscated (`[at]`, `(dot)`, `mailto:`) and junk/image/sentry/example emails are filtered out. High-value prefixes (`founder@`, `ceo@`, `owner@`, `info@`, `hello@`, `sales@`) are prioritized as the `bestEmail`.

### 3. Revenue-Leak, Tech-Stack & Ad-Pixel Matrix
- **CMS/Framework detection:** Shopify, WordPress, WooCommerce, Webflow, Wix, Squarespace, Framer, Next.js, or Custom.
- **Ad pixels & analytics:** Meta Pixel, TikTok Pixel, Google Tag Manager, GA4, Google Ads Conversion Tag, LinkedIn Insight Tag, Microsoft Clarity, Hotjar.
- **High-value leak flag:** if a site runs Google Ads/GTM but has **no Meta or TikTok Pixel**, it's flagged `"Bleeding Paid Traffic (No Retargeting)"` — an instant, provable pitch.
- **Conversion & automation tools:** Intercom, Tidio, Drift, Crisp, HubSpot, Zendesk, Tawk.to, LiveChat, Calendly, Klaviyo, Mailchimp, Stripe.

### 4. 2026 GEO (Generative Engine Optimization) & AI-Search Readiness Audit
The first Apify Actor built for the **AI Search era**. We check:
- `/llms.txt` presence (the emerging standard for LLM-readable sites)
- `robots.txt` rules for `GPTBot`, `ChatGPT-User`, `ClaudeBot`, `PerplexityBot`, and `Google-Extended` — are they blocking the exact bots that power ChatGPT Search, Claude, Perplexity and Google AI Overviews?
- `schema.org` structured data (`application/ld+json`) and OpenGraph tags
- A calculated `aiSearchReadinessScore` (0–100)

### 5. Passive Infrastructure, DNS & HTTP Security Header X-Ray
100% legal, 100% passive OSINT — no port scanning, no intrusive payloads:
- **DNS intelligence:** MX records → email provider (Google Workspace, Microsoft 365, Zoho, Proton, GoDaddy/Custom); SPF (`v=spf1`) and DMARC (`_dmarc.{domain}`) checks, flagging missing DMARC or weak `p=none` policies (email spoofing / deliverability risk — a goldmine pitch for IT/MSP agencies).
- **HTTP headers:** `server`, `x-powered-by`, Cloudflare detection (`cf-ray`), and missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).
- **`/.well-known/security.txt`** passive check.

### 6. Real-Time Webhook Push
Add your **Clay.com, Make.com, or n8n** webhook URL and every enriched lead is POSTed the instant it's ready — zero manual CSV downloading, zero copy-pasting.

---

## 🛠️ Input Parameters

| Field | Type | Description |
|---|---|---|
| `searchKeyword` | String | Plain-English niche + location, e.g. `"MedSpas in Austin"`. Leave blank if using `urls`. |
| `urls` | Array of strings | Paste domains/URLs directly to audit those exact sites. |
| `agencyFocus` | Enum | `all`, `smma_ads`, `ai_automation`, `seo_geo`, `cyber_it` — customizes `whatToPitch` and `oneClickColdEmail`. |
| `maxResults` | Integer | Max number of enriched leads to return (default `20`). |
| `crawlContactPages` | Boolean | Enable the 2-hop contact-page crawler (default `true`). |
| `maxSearchQueriesPerKeyword` | Integer | How many search-query variations to run in Search Keyword mode (default `3`). |
| `requestTimeoutSecs` | Integer | Per-request timeout guard so a dead/slow site never hangs the run (default `15`). |
| `proxyConfiguration` | Object | Apify Proxy config — recommended for larger runs. |
| `webhookUrl` | String | Optional. POST every enriched lead live to Clay/Make/n8n. |

---

## 📊 Sample Output (abridged)

```json
{
  "leadPriority": "🔥 HOT LEAD (85/100)",
  "companyName": "Glow MedSpa Austin",
  "domain": "glowmedspaaustin.com",
  "bestEmail": "info@glowmedspaaustin.com",
  "bestPhone": "+15125551234",
  "estDealValue": "$2,000 - $5,000/mo",
  "threeSecondSummary": "📉 Has Google Tag Manager, but MISSING Meta Pixel + 🤖 No AI chatbot + 🔎 Invisible to ChatGPT/Perplexity Search",
  "whatToPitch": "Meta/TikTok Retargeting Pixel Setup + Paid Ads Management Retainer",
  "oneClickColdEmail": "Subject: Quick find on Glow MedSpa Austin's website...",
  "oneClickLoomScript": "1) Screen-share glowmedspaaustin.com's homepage...",
  "linkedinUrl": "https://linkedin.com/company/glowmedspaaustin",
  "cmsPlatform": "WordPress",
  "emailProvider": "Google Workspace",
  "dmarcStatus": "Weak: Policy p=none (Spoofing Possible)",
  "aiSearchReadinessScore": 35
}
```

The Apify Console **Output** tab is pre-configured with an `overview` view so these decision-making columns show first, in order — no manual column reordering needed.

---

## 💰 Who this is for / ROI

- A single **HOT LEAD** closed at even the low end of `estDealValue` ($1,500–$2,000/mo retainer) pays for months of running this Actor.
- Run it once per niche per week, filter for `🔥 HOT LEAD`, and your SDR/cold-outreach team opens every call already knowing the pitch.
- Works perfectly as the first step in a **Clay.com enrichment waterfall**, an **n8n cold-email sequencer**, or a **Make.com CRM sync**.

---

## ❓ FAQ

**Does this use Playwright or a headless browser?**
No. 100% HTTP-based (`got-scraping` + `cheerio`) for speed, low cost, and near-zero block/fingerprinting risk.

**Is this legal?**
Yes. Everything collected is publicly available: homepage/contact-page HTML, public DNS records (MX/TXT), and standard HTTP response headers. No port scanning, no login bypass, no intrusive payloads — 100% passive OSINT.

**What if a website is down or unreachable?**
The Actor never hangs — a per-request timeout guard skips slow/dead sites gracefully and still returns a minimal record so you know to double-check the domain.

**Can I use this without any URLs at all?**
Yes — that's the whole point. Type a keyword like `"Roofing contractors in Dallas"` and the Actor finds and audits real businesses for you.

**Does it work for Clay.com / Make / n8n?**
Yes — set the `webhookUrl` input and every lead is pushed in real time as JSON the moment it's ready.

---

## 🏷️ Keywords
B2B Lead Generation · Clay.com Enrichment · Website Audit Tool · Meta Pixel Checker · TikTok Pixel Checker · Tech Stack Detector · DMARC/SPF Checker · Email Finder · Decision Maker Contact Finder · GEO (Generative Engine Optimization) Auditor · llms.txt Checker · ChatGPT Search Visibility · Cold Email Icebreaker Generator · Website Security Headers Scanner · SMMA Prospecting Tool · AI Chatbot Gap Finder · Apify Actor for Agencies
