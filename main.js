/**
 * 360° B2B Revenue-Leak, Passive OSINT, GEO & Contact Enricher (Zero-Cognitive-Load Edition)
 * --------------------------------------------------------------------------------------------
 * 100% white-hat, passive, zero-browser-fingerprint Apify Actor.
 *
 * Modules implemented in this single file:
 *  1. Auto-Search Discovery Engine (DuckDuckGo HTML, directory filtering)
 *  2. 2-Hop Smart Internal Contact Crawler (contact/about/team/support/impressum)
 *  3. Revenue-Leak, Tech-Stack & Ad-Pixel Matrix
 *  4. 2026 GEO / AI-Search Readiness Audit (llms.txt, robots.txt, schema.org, OpenGraph)
 *  5. Passive Infrastructure, DNS & HTTP Security Header X-Ray
 *  6. Real-Time Webhook Push (Clay.com / Make / n8n)
 *
 * No Playwright/Puppeteer is used anywhere -> fast, cheap, near-zero block risk.
 */

import { Actor, log } from 'apify';
import { gotScraping } from 'got-scraping';
import * as cheerio from 'cheerio';
import { resolveMx, resolveTxt } from 'node:dns/promises';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BLOCKED_DOMAINS = [
    'yelp.com', 'yellowpages.com', 'facebook.com', 'linkedin.com', 'instagram.com',
    'youtube.com', 'reddit.com', 'wikipedia.org', 'bbb.org', 'angi.com',
    'tripadvisor.com', 'forbes.com', 'g2.com', 'capterra.com', 'pinterest.com',
    'twitter.com', 'x.com', 'indeed.com', 'glassdoor.com', 'nextdoor.com',
    'thumbtack.com', 'houzz.com', 'manta.com', 'crunchbase.com', 'zoominfo.com',
    'maps.google.com', 'google.com', 'bing.com', 'duckduckgo.com', 'amazon.com',
    'ebay.com', 'etsy.com', 'medium.com', 'quora.com', 'tiktok.com', 'apple.com',
    'yahoo.com', 'foursquare.com', 'mapquest.com', 'superpages.com', 'local.com',
    'chamberofcommerce.com', 'bizapedia.com', 'opencorporates.com', 'alignable.com',
];

const AI_BOTS = ['GPTBot', 'ChatGPT-User', 'ClaudeBot', 'PerplexityBot', 'Google-Extended'];

const CONTACT_PAGE_REGEX = /(^|\/)(contact|about|team|our-team|meet-the-team|support|impressum)(\/|$|\.html?|-us)/i;

const EMAIL_REGEX = /[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+/g;
const OBFUSCATED_EMAIL_REGEX = /([a-zA-Z0-9._%+-]+)\s*[[(]?\s*(?:at|AT)\s*[\])]?\s*([a-zA-Z0-9.-]+)\s*[[(]?\s*(?:dot|DOT)\s*[\])]?\s*([a-zA-Z]{2,})/g;
const PHONE_REGEX = /(\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}(?:[-.\s]?\d{2,4})?/g;

const JUNK_EMAIL_SNIPPETS = [
    'sentry.io', 'wixpress.com', 'example.com', 'example.org', 'godaddy.com',
    'yourdomain', 'domain.com', 'w3.org', 'schema.org', 'wordpress.org',
    'cloudflare.com', 'noreply', 'no-reply', 'donotreply', 'test@test',
    'username@', 'youremail', 'name@', '.png', '.jpg', '.jpeg', '.gif', '.svg',
    '.webp', 'sentry-next', 'react-dom', 'placeholder', 'email@email', 'wixapps.net',
];

const PRIORITY_EMAIL_PREFIXES = [
    'founder@', 'ceo@', 'owner@', 'president@', 'coo@', 'hello@', 'info@',
    'sales@', 'contact@', 'admin@', 'support@', 'team@',
];

const CMS_SIGNATURES = [
    ['Shopify', ['cdn.shopify.com', 'myshopify.com', 'shopify.theme', '/s/files/1/']],
    ['WordPress + WooCommerce', ['woocommerce', 'wc-ajax']],
    ['WordPress', ['wp-content', 'wp-includes', 'wp-json']],
    ['Webflow', ['webflow.com', 'data-wf-site', 'data-wf-page']],
    ['Wix', ['wixstatic.com', 'parastorage.com', 'wix.com']],
    ['Squarespace', ['squarespace.com', 'squarespace-cdn.com', 'static1.squarespace.com']],
    ['Framer', ['framerusercontent.com', 'framer.app']],
    ['Next.js', ['__next_data__', '/_next/static']],
];

const PIXEL_SIGNATURES = [
    ['metaPixel', 'Meta Pixel (Facebook)', ['connect.facebook.net', 'fbq(']],
    ['tiktokPixel', 'TikTok Pixel', ['analytics.tiktok.com', 'ttq.load', 'ttq.track']],
    ['gtm', 'Google Tag Manager (GTM)', ['googletagmanager.com/gtm.js', 'gtm-']],
    ['ga4', 'Google Analytics 4 (GA4)', ['google-analytics.com/g/collect', 'gtag(', 'googletagmanager.com/gtag/js']],
    ['googleAds', 'Google Ads Conversion Tag', ['googleadservices.com', 'google.com/pagead', 'aw-conversion']],
    ['linkedinInsight', 'LinkedIn Insight Tag', ['snap.licdn.com', '_linkedin_partner_id']],
    ['msClarity', 'Microsoft Clarity', ['clarity.ms']],
    ['hotjar', 'Hotjar', ['static.hotjar.com']],
];

const CONVERSION_TOOL_SIGNATURES = [
    ['Intercom', ['widget.intercom.io', 'intercomcdn.com']],
    ['Tidio', ['code.tidio.co']],
    ['Drift', ['js.driftt.com']],
    ['Crisp', ['client.crisp.chat']],
    ['HubSpot', ['js.hs-scripts.com', 'js.hubspot.com', 'hs-analytics.net']],
    ['Zendesk', ['zdassets.com', 'zendesk.com']],
    ['Tawk.to', ['embed.tawk.to']],
    ['LiveChat', ['cdn.livechatinc.com']],
    ['Calendly', ['calendly.com']],
    ['Klaviyo', ['klaviyo.com', 'static.klaviyo.com']],
    ['Mailchimp', ['list-manage.com', 'chimpstatic.com']],
    ['Stripe', ['js.stripe.com']],
];

const DEFAULT_TIMEOUT_MS = 15000;

// ---------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Concurrency-limited map (no extra dependency needed). */
async function mapWithConcurrency(items, limit, iterator) {
    const results = new Array(items.length);
    let cursor = 0;
    const workerCount = Math.max(1, Math.min(limit, items.length));
    const workers = new Array(workerCount).fill(null).map(async () => {
        while (cursor < items.length) {
            const current = cursor++;
            try {
                results[current] = await iterator(items[current], current);
            } catch (err) {
                results[current] = { __error: err?.message || String(err) };
            }
        }
    });
    await Promise.all(workers);
    return results;
}

function toRootDomain(raw) {
    if (!raw) return null;
    let value = String(raw).trim();
    if (!value) return null;
    if (!/^https?:\/\//i.test(value)) value = `https://${value}`;
    try {
        const url = new URL(value);
        let host = url.hostname.toLowerCase();
        if (host.startsWith('www.')) host = host.slice(4);
        return host;
    } catch {
        return null;
    }
}

function isBlockedDomain(domain) {
    if (!domain) return true;
    return BLOCKED_DOMAINS.some((b) => domain === b || domain.endsWith(`.${b}`));
}

async function fetchPage(url, { proxyUrl, timeoutMs } = {}) {
    return gotScraping({
        url,
        timeout: { request: timeoutMs || DEFAULT_TIMEOUT_MS },
        retry: { limit: 1 },
        throwHttpErrors: false,
        maxRedirects: 5,
        headers: { 'accept-language': 'en-US,en;q=0.9' },
        ...(proxyUrl ? { proxyUrl } : {}),
    });
}

async function safeFetch(url, opts) {
    try {
        return await fetchPage(url, opts);
    } catch {
        return null;
    }
}

async function fetchHomepage(domain, opts) {
    for (const scheme of ['https', 'http']) {
        try {
            const res = await fetchPage(`${scheme}://${domain}`, opts);
            if (res && res.statusCode && res.statusCode < 500) {
                return { ...res, finalScheme: scheme };
            }
        } catch {
            // try next scheme
        }
    }
    return null;
}

function cleanCompanyName(rawTitle, domain) {
    if (!rawTitle) return domain ? capitalizeDomain(domain) : 'Unknown Company';
    let name = rawTitle
        .split(/[|\-–—:]/)[0]
        .replace(/\b(home|homepage|official site|welcome to)\b/gi, '')
        .trim();
    if (!name || name.length < 2) name = rawTitle.trim();
    if (name.length > 60) name = name.slice(0, 60).trim();
    return name || capitalizeDomain(domain);
}

function capitalizeDomain(domain) {
    if (!domain) return 'Unknown Company';
    const base = domain.split('.')[0];
    return base.charAt(0).toUpperCase() + base.slice(1);
}

// ---------------------------------------------------------------------------
// MODULE 1: Auto-Search Discovery Engine (DuckDuckGo HTML)
// ---------------------------------------------------------------------------

function resolveDuckDuckGoHref(href) {
    try {
        let normalized = href;
        if (normalized.startsWith('//')) normalized = `https:${normalized}`;
        if (normalized.startsWith('/')) normalized = `https://duckduckgo.com${normalized}`;
        const url = new URL(normalized);
        if (url.hostname.includes('duckduckgo.com')) {
            const uddg = url.searchParams.get('uddg');
            return uddg ? decodeURIComponent(uddg) : null;
        }
        return normalized;
    } catch {
        return null;
    }
}

async function discoverDomainsFromKeyword({ keyword, needed, maxQueries, proxyUrl, timeoutMs }) {
    const variants = [
        keyword,
        `${keyword} company`,
        `${keyword} official website`,
        `best ${keyword}`,
        `top ${keyword}`,
        `${keyword} near me`,
        `${keyword} services`,
    ].slice(0, Math.max(1, maxQueries));

    const found = new Set();
    for (const query of variants) {
        if (found.size >= needed) break;
        log.info(`🔎 [Discovery] Searching DuckDuckGo for: "${query}"`);
        const res = await safeFetch(
            `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}&kl=us-en`,
            { proxyUrl, timeoutMs },
        );
        if (!res || !res.body) {
            log.warning(`⚠️  No response for query "${query}"`);
            continue;
        }
        const $ = cheerio.load(res.body);
        $('a.result__a, a.result__url').each((_, el) => {
            const href = $(el).attr('href');
            if (!href) return;
            const resolved = resolveDuckDuckGoHref(href);
            const domain = toRootDomain(resolved);
            if (!domain || isBlockedDomain(domain)) return;
            found.add(domain);
        });
        await sleep(600 + Math.floor(Math.random() * 800));
    }
    return Array.from(found);
}

// ---------------------------------------------------------------------------
// MODULE 2: 2-Hop Smart Internal Contact Crawler
// ---------------------------------------------------------------------------

function findContactPageLinks($, baseUrl, maxLinks = 2) {
    const candidates = new Set();
    $('a[href]').each((_, el) => {
        const href = $(el).attr('href');
        if (!href || href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('#')) return;
        try {
            const resolved = new URL(href, baseUrl);
            if (resolved.hostname.replace(/^www\./, '') !== new URL(baseUrl).hostname.replace(/^www\./, '')) return;
            if (CONTACT_PAGE_REGEX.test(resolved.pathname)) {
                candidates.add(resolved.href);
            }
        } catch {
            // ignore invalid URLs
        }
    });
    return Array.from(candidates).slice(0, maxLinks);
}

async function crawlContactPages(links, opts) {
    const settled = await Promise.allSettled(links.map((link) => fetchPage(link, opts)));
    const pages = [];
    settled.forEach((result, idx) => {
        if (result.status === 'fulfilled' && result.value && result.value.body && result.value.statusCode < 400) {
            pages.push({ url: links[idx], html: result.value.body });
        }
    });
    return pages;
}

// ---------------------------------------------------------------------------
// Contact info extraction (emails / phones / socials) — used by Module 2
// ---------------------------------------------------------------------------

function isJunkEmail(email) {
    const lower = email.toLowerCase();
    return JUNK_EMAIL_SNIPPETS.some((snippet) => lower.includes(snippet));
}

function addEmailIfValid(raw, set) {
    if (!raw) return;
    const candidate = raw.trim().toLowerCase().replace(/^mailto:/, '');
    if (!EMAIL_REGEX.test(candidate)) return;
    EMAIL_REGEX.lastIndex = 0;
    if (isJunkEmail(candidate)) return;
    set.add(candidate);
}

function normalizePhone(raw) {
    return raw.replace(/[^\d+]/g, '').trim();
}

function extractContactInfo(pages) {
    const emails = new Set();
    const phones = new Set();
    const socials = {
        linkedinUrl: null,
        instagramUrl: null,
        twitterUrl: null,
        facebookUrl: null,
        youtubeUrl: null,
        tiktokUrl: null,
        whatsappUrl: null,
    };

    for (const page of pages) {
        let $;
        try {
            $ = cheerio.load(page.html);
        } catch {
            continue;
        }

        $('a[href^="mailto:" i]').each((_, el) => {
            const raw = ($(el).attr('href') || '').replace(/^mailto:/i, '').split('?')[0];
            addEmailIfValid(raw, emails);
        });

        $('a[href^="tel:" i]').each((_, el) => {
            const raw = ($(el).attr('href') || '').replace(/^tel:/i, '');
            if (raw) phones.add(normalizePhone(raw));
        });

        const bodyText = $('body').text().replace(/\s+/g, ' ');

        (bodyText.match(EMAIL_REGEX) || []).forEach((e) => addEmailIfValid(e, emails));

        let match;
        OBFUSCATED_EMAIL_REGEX.lastIndex = 0;
        while ((match = OBFUSCATED_EMAIL_REGEX.exec(bodyText)) !== null) {
            addEmailIfValid(`${match[1]}@${match[2]}.${match[3]}`, emails);
        }

        if (phones.size === 0) {
            (bodyText.match(PHONE_REGEX) || []).forEach((p) => {
                const digits = p.replace(/\D/g, '');
                if (digits.length >= 9 && digits.length <= 15) phones.add(p.trim());
            });
        }

        $('a[href]').each((_, el) => {
            const href = $(el).attr('href');
            if (!href) return;
            const low = href.toLowerCase();
            if (!socials.linkedinUrl && low.includes('linkedin.com/')) socials.linkedinUrl = href;
            if (!socials.instagramUrl && low.includes('instagram.com/')) socials.instagramUrl = href;
            if (!socials.twitterUrl && (low.includes('twitter.com/') || low.includes('x.com/'))) socials.twitterUrl = href;
            if (!socials.facebookUrl && low.includes('facebook.com/')) socials.facebookUrl = href;
            if (!socials.youtubeUrl && low.includes('youtube.com/')) socials.youtubeUrl = href;
            if (!socials.tiktokUrl && low.includes('tiktok.com/')) socials.tiktokUrl = href;
            if (!socials.whatsappUrl && (low.includes('wa.me/') || low.includes('api.whatsapp.com/'))) socials.whatsappUrl = href;
        });
    }

    return { emails: Array.from(emails), phones: Array.from(phones), socials };
}

function pickBestEmail(emails) {
    if (!emails.length) return null;
    for (const prefix of PRIORITY_EMAIL_PREFIXES) {
        const match = emails.find((e) => e.startsWith(prefix));
        if (match) return match;
    }
    return emails[0];
}

// ---------------------------------------------------------------------------
// MODULE 3: Revenue-Leak, Tech-Stack & Ad-Pixel Matrix
// ---------------------------------------------------------------------------

function detectCms(htmlLower) {
    for (const [name, signatures] of CMS_SIGNATURES) {
        if (signatures.some((s) => htmlLower.includes(s))) return name;
    }
    return 'Custom / Unknown';
}

function detectPixels(htmlLower) {
    const flags = {};
    const detectedNames = [];
    for (const [key, label, signatures] of PIXEL_SIGNATURES) {
        const detected = signatures.some((s) => htmlLower.includes(s));
        flags[key] = detected;
        if (detected) detectedNames.push(label);
    }
    return { flags, detectedNames };
}

function detectConversionTools(htmlLower) {
    const detected = [];
    for (const [name, signatures] of CONVERSION_TOOL_SIGNATURES) {
        if (signatures.some((s) => htmlLower.includes(s))) detected.push(name);
    }
    return detected;
}

// ---------------------------------------------------------------------------
// MODULE 4: 2026 GEO / AI-Search Readiness Audit
// ---------------------------------------------------------------------------

function parseRobotsGroups(robotsTxt) {
    const lines = robotsTxt
        .split(/\r?\n/)
        .map((l) => l.split('#')[0].trim())
        .filter(Boolean);
    const groups = [];
    let current = null;
    for (const line of lines) {
        const idx = line.indexOf(':');
        if (idx === -1) continue;
        const key = line.slice(0, idx).trim().toLowerCase();
        const value = line.slice(idx + 1).trim();
        if (key === 'user-agent') {
            if (!current || current.rulesStarted) {
                current = { agents: [], disallows: [], rulesStarted: false };
                groups.push(current);
            }
            current.agents.push(value.toLowerCase());
        } else if (key === 'disallow') {
            if (current) {
                current.disallows.push(value);
                current.rulesStarted = true;
            }
        } else if (key === 'allow') {
            if (current) current.rulesStarted = true;
        }
    }
    return groups;
}

function isBotBlocked(robotsTxt, botName) {
    if (!robotsTxt || !robotsTxt.trim()) return false;
    const groups = parseRobotsGroups(robotsTxt);
    const lower = botName.toLowerCase();
    let relevant = groups.filter((g) => g.agents.includes(lower));
    if (relevant.length === 0) relevant = groups.filter((g) => g.agents.includes('*'));
    if (relevant.length === 0) return false;
    return relevant.some((g) => g.disallows.some((d) => d.trim() === '/'));
}

async function checkGeoReadiness({ domain, $, opts }) {
    const [llmsRes, robotsRes] = await Promise.allSettled([
        safeFetch(`https://${domain}/llms.txt`, opts),
        safeFetch(`https://${domain}/robots.txt`, opts),
    ]);

    const llmsResponse = llmsRes.status === 'fulfilled' ? llmsRes.value : null;
    const llmsTxtFound = !!(
        llmsResponse &&
        llmsResponse.statusCode === 200 &&
        llmsResponse.body &&
        llmsResponse.body.trim().length > 20 &&
        !/<html/i.test(llmsResponse.body.slice(0, 200))
    );

    const robotsResponse = robotsRes.status === 'fulfilled' ? robotsRes.value : null;
    const robotsTxt = robotsResponse && robotsResponse.statusCode === 200 ? (robotsResponse.body || '') : '';

    const blockedBots = AI_BOTS.filter((bot) => isBotBlocked(robotsTxt, bot));
    const ldJsonFound = $('script[type="application/ld+json"]').length > 0;
    const ogTagsFound = $('meta[property^="og:"]').length > 0;

    let score = 0;
    if (llmsTxtFound) score += 35;
    score += Math.round(((AI_BOTS.length - blockedBots.length) / AI_BOTS.length) * 35);
    if (ldJsonFound) score += 20;
    if (ogTagsFound) score += 10;
    score = Math.max(0, Math.min(100, score));

    return { llmsTxtFound, blockedBots, ldJsonFound, ogTagsFound, aiSearchReadinessScore: score };
}

// ---------------------------------------------------------------------------
// MODULE 5: Passive Infrastructure, DNS & HTTP Security Header X-Ray
// ---------------------------------------------------------------------------

async function getEmailProvider(domain) {
    try {
        const records = await resolveMx(domain);
        if (!records || records.length === 0) return { provider: 'No MX Record Found (Email Risk)', raw: [] };
        const exchanges = records.map((r) => r.exchange.toLowerCase());
        let provider = 'Other / Custom Mail Server';
        if (exchanges.some((e) => e.includes('google.com') || e.includes('googlemail.com'))) provider = 'Google Workspace';
        else if (exchanges.some((e) => e.includes('outlook.com') || e.includes('protection.outlook.com'))) provider = 'Microsoft 365';
        else if (exchanges.some((e) => e.includes('zoho.com'))) provider = 'Zoho Mail';
        else if (exchanges.some((e) => e.includes('proton'))) provider = 'Proton Mail';
        else if (exchanges.some((e) => e.includes('secureserver.net') || e.includes('godaddy'))) provider = 'GoDaddy / Shared Hosting';
        return { provider, raw: exchanges };
    } catch {
        return { provider: 'No MX Record Found (Email Risk)', raw: [] };
    }
}

async function getSpfDmarc(domain) {
    let spfFound = false;
    try {
        const txtRecords = await resolveTxt(domain);
        const flat = txtRecords.map((t) => t.join(''));
        spfFound = flat.some((t) => /v=spf1/i.test(t));
    } catch {
        spfFound = false;
    }

    let dmarcStatus = 'Missing (High Risk - Spoofable)';
    try {
        const dmarcRecords = await resolveTxt(`_dmarc.${domain}`);
        const flat = dmarcRecords.map((t) => t.join(''));
        const dmarc = flat.find((t) => /v=dmarc1/i.test(t));
        if (dmarc) {
            const policyMatch = dmarc.match(/p=([a-zA-Z]+)/i);
            const policy = policyMatch ? policyMatch[1].toLowerCase() : 'none';
            if (policy === 'none') dmarcStatus = 'Weak: Policy p=none (Spoofing Possible)';
            else if (policy === 'quarantine') dmarcStatus = 'Configured (p=quarantine)';
            else if (policy === 'reject') dmarcStatus = 'Strong (p=reject)';
            else dmarcStatus = `Configured (p=${policy})`;
        }
    } catch {
        // leave default "Missing"
    }

    return { spfFound, dmarcStatus };
}

function auditSecurityHeaders(headers = {}) {
    const missing = [];
    if (!headers['strict-transport-security']) missing.push('HSTS');
    if (!headers['content-security-policy']) missing.push('CSP');
    if (!headers['x-frame-options']) missing.push('X-Frame-Options');
    if (!headers['x-content-type-options']) missing.push('X-Content-Type-Options');
    return {
        server: headers.server || 'Unknown',
        poweredBy: headers['x-powered-by'] || '',
        cloudflare: !!headers['cf-ray'],
        missingSecurityHeaders: missing,
    };
}

// ---------------------------------------------------------------------------
// Lead scoring + "Zero Cognitive Load" copy generation
// ---------------------------------------------------------------------------

function classifyAdLeak({ pixels }) {
    const hasPaidTraffic = pixels.flags.gtm || pixels.flags.googleAds || pixels.flags.ga4;
    const hasMeta = pixels.flags.metaPixel;
    const hasTikTok = pixels.flags.tiktokPixel;

    if (hasPaidTraffic && !hasMeta && !hasTikTok) {
        return { severity: 3, label: '🔴 Bleeding Paid Traffic (No Retargeting Pixel At All)', hasPaidTraffic };
    }
    if (hasPaidTraffic && !hasMeta) {
        return { severity: 2, label: '🟠 Missing Meta Pixel (partial retargeting leak)', hasPaidTraffic };
    }
    if (hasPaidTraffic && !hasTikTok) {
        return { severity: 1, label: '🟡 Missing TikTok Pixel (partial retargeting leak)', hasPaidTraffic };
    }
    if (!hasPaidTraffic) {
        return { severity: 0, label: '⚪ No paid-traffic tracking detected (not running ads yet)', hasPaidTraffic };
    }
    return { severity: 0, label: '✅ Fully pixeled (Meta + TikTok + GTM/GA4 present)', hasPaidTraffic };
}

function buildLeadIntelligence(record, agencyFocus) {
    const adLeak = classifyAdLeak(record);
    const noChatbot = record.conversionTools.length === 0;
    const noLlms = !record.geo.llmsTxtFound;
    const geoWeak = record.geo.aiSearchReadinessScore < 50;
    const dmarcWeak = record.dns.dmarcStatus.startsWith('Missing') || record.dns.dmarcStatus.startsWith('Weak');
    const secHeadersWeak = record.headers.missingSecurityHeaders.length >= 2;

    // ---- Score (0-100) ----
    let score = 20;
    if (adLeak.severity === 3) score += 20;
    else if (adLeak.severity >= 1) score += 10;
    if (noChatbot) score += 15;
    if (noLlms) score += 8;
    if (geoWeak) score += 7;
    if (dmarcWeak) score += 15;
    if (secHeadersWeak) score += 10;
    if (adLeak.hasPaidTraffic) score += 5;
    if (record.bestEmail) score += 5;
    score = Math.max(0, Math.min(100, score));

    let leadPriority;
    let dealTier;
    if (score >= 75) {
        leadPriority = `🔥 HOT LEAD (${score}/100)`;
        dealTier = [2000, 5000];
    } else if (score >= 45) {
        leadPriority = `🟡 WARM LEAD (${score}/100)`;
        dealTier = [800, 2500];
    } else {
        leadPriority = `❄️ COLD (${score}/100)`;
        dealTier = [250, 800];
    }
    const estDealValue = `$${dealTier[0].toLocaleString()} - $${dealTier[1].toLocaleString()}/mo`;

    // ---- 3-second summary ----
    const leakPhrases = [];
    if (adLeak.severity === 3) leakPhrases.push('💸 Running paid traffic but MISSING retargeting pixels (leaking ad spend)');
    else if (adLeak.severity === 2) leakPhrases.push('📉 Has Google Tag Manager, but MISSING Meta Pixel');
    else if (adLeak.severity === 1) leakPhrases.push('📉 Missing TikTok Pixel (partial retargeting leak)');
    if (noChatbot) leakPhrases.push('🤖 No AI chatbot / live-chat (losing after-hours leads)');
    if (noLlms) leakPhrases.push('🔎 Invisible to ChatGPT/Perplexity Search (no llms.txt)');
    if (dmarcWeak) leakPhrases.push('📧 Weak/missing DMARC (email spoofing risk)');
    if (secHeadersWeak) leakPhrases.push('🛡️ Missing key HTTP security headers');
    const threeSecondSummary = leakPhrases.length
        ? leakPhrases.slice(0, 3).join(' + ')
        : '✅ Solid technical foundation — pitch growth/scale, not fixes';

    // ---- What to pitch (customized by agency focus) ----
    const pitchOptions = {
        smma_ads: adLeak.severity > 0
            ? 'Meta/TikTok Retargeting Pixel Setup + Paid Ads Management Retainer'
            : 'Paid Ads Launch (Meta/TikTok/Google) — they have zero tracking today',
        ai_automation: noChatbot
            ? 'AI Chatbot + 24/7 Lead-Capture Automation Build'
            : 'Advanced AI Automation Upsell (lead routing, follow-up sequences, CRM sync)',
        seo_geo: (noLlms || geoWeak)
            ? '2026 AI-GEO Optimization Package (llms.txt + Schema.org) so ChatGPT/Perplexity/Gemini recommend them'
            : 'AI-GEO Authority Expansion (content + citations to dominate AI Overviews)',
        cyber_it: dmarcWeak
            ? 'Email Security Hardening (SPF/DKIM/DMARC) + Deliverability Audit'
            : 'Managed IT Security Retainer (header hardening, monitoring, patching)',
    };

    let whatToPitch;
    if (agencyFocus && agencyFocus !== 'all' && pitchOptions[agencyFocus]) {
        whatToPitch = pitchOptions[agencyFocus];
    } else if (adLeak.severity > 0) {
        whatToPitch = pitchOptions.smma_ads;
    } else if (noChatbot) {
        whatToPitch = pitchOptions.ai_automation;
    } else if (dmarcWeak) {
        whatToPitch = pitchOptions.cyber_it;
    } else if (noLlms || geoWeak) {
        whatToPitch = pitchOptions.seo_geo;
    } else if (secHeadersWeak) {
        whatToPitch = 'Website Security Header Hardening + Managed IT Check-up';
    } else {
        whatToPitch = 'Conversion Rate Optimization / Growth Retainer (they are already well set up)';
    }

    // ---- Cold email ----
    const topTwoLeaks = leakPhrases.slice(0, 2);
    const leakBullets = (topTwoLeaks.length ? topTwoLeaks : [threeSecondSummary])
        .map((l, i) => `${i + 1}) ${l.replace(/^[^\w]+/, '').trim()}`)
        .join('\n');

    const oneClickColdEmail = [
        `Subject: Quick find on ${record.companyName}'s website`,
        '',
        'Hi there,',
        '',
        `I was running a quick technical audit of ${record.domain} and found a couple of things that are likely costing you leads/revenue every month:`,
        '',
        leakBullets,
        '',
        `Quick fix on our end: ${whatToPitch}.`,
        '',
        'Worth a free 10-minute call this week, or I can just send you a 2-minute Loom walking through exactly what I found — whichever is easier for you?',
        '',
        'Best,',
        '[Your Name]',
        '[Your Agency]',
    ].join('\n');

    // ---- Loom script ----
    const oneClickLoomScript = [
        `1) Screen-share ${record.domain}'s homepage and point out: ${noChatbot ? 'there is no chat widget / way to capture after-hours leads' : 'the current chat/booking widget they use'}.`,
        `2) Open DevTools → Network/Elements and search for "fbq(" / "ttq.load" / "gtag(" to prove: ${threeSecondSummary}.`,
        `3) Search "${record.companyName}" inside ChatGPT or Perplexity live to show ${noLlms ? 'they do not show up because there is no llms.txt / weak structured data' : 'their current AI-search visibility'}, then close with: "${whatToPitch}".`,
    ].join('\n');

    return {
        leadScore: score,
        leadPriority,
        estDealValue,
        threeSecondSummary,
        whatToPitch,
        oneClickColdEmail,
        oneClickLoomScript,
        adPixelLeak: adLeak.label,
    };
}

// ---------------------------------------------------------------------------
// Per-target processing pipeline
// ---------------------------------------------------------------------------

async function processTarget(domain, { crawlContactPages: shouldCrawlContacts, agencyFocus, fetchOpts }) {
    const homepage = await fetchHomepage(domain, fetchOpts);
    if (!homepage || !homepage.body) {
        log.warning(`❌ Could not reach ${domain} — skipping full audit (DNS-only fallback).`);
        const [emailProviderInfo, spfDmarc] = await Promise.all([
            getEmailProvider(domain).catch(() => ({ provider: 'Unknown', raw: [] })),
            getSpfDmarc(domain).catch(() => ({ spfFound: false, dmarcStatus: 'Unknown' })),
        ]);
        return {
            leadPriority: '❄️ COLD (10/100)',
            companyName: capitalizeDomain(domain),
            domain,
            website: `https://${domain}`,
            bestEmail: null,
            bestPhone: null,
            estDealValue: '$250 - $500/mo (unreachable site — verify domain first)',
            threeSecondSummary: '🚫 Website unreachable or parked — verify before pitching',
            whatToPitch: 'Website Rebuild / Relaunch',
            oneClickColdEmail: `Hi,\n\nI noticed ${domain} appears to be down or unreachable right now — just flagging it in case that's unintentional, since it could be costing you leads daily.\n\nHappy to help get it back online or rebuilt properly.\n\nBest,\n[Your Name]`,
            linkedinUrl: null,
            instagramUrl: null,
            cmsPlatform: 'Unknown (site unreachable)',
            emailProvider: emailProviderInfo.provider,
            adPixelLeak: 'Unknown (site unreachable)',
            aiSearchReadinessScore: 0,
            dmarcStatus: spfDmarc.dmarcStatus,
            _unreachable: true,
        };
    }

    const htmlLower = homepage.body.toLowerCase();
    const $ = cheerio.load(homepage.body);
    const baseUrl = `${homepage.finalScheme}://${domain}`;

    const titleTag = $('title').first().text().trim() || $('meta[property="og:site_name"]').attr('content') || '';
    const companyName = cleanCompanyName(titleTag, domain);

    // ---- Module 2: 2-hop contact crawler ----
    let pages = [{ url: baseUrl, html: homepage.body }];
    if (shouldCrawlContacts) {
        const contactLinks = findContactPageLinks($, baseUrl, 2);
        if (contactLinks.length) {
            const contactPages = await crawlContactPages(contactLinks, fetchOpts);
            pages = pages.concat(contactPages);
        }
    }
    const { emails, phones, socials } = extractContactInfo(pages);
    const bestEmail = pickBestEmail(emails);
    const bestPhone = phones[0] || null;

    // ---- Module 3: Tech stack / pixels / conversion tools ----
    const cmsPlatform = detectCms(htmlLower);
    const pixels = detectPixels(htmlLower);
    const conversionTools = detectConversionTools(htmlLower);

    // ---- Module 4: GEO / AI-search readiness ----
    const geo = await checkGeoReadiness({ domain, $, opts: fetchOpts });

    // ---- Module 5: DNS + HTTP security headers ----
    const [emailProviderInfo, spfDmarc, securityTxtRes] = await Promise.all([
        getEmailProvider(domain).catch(() => ({ provider: 'Unknown', raw: [] })),
        getSpfDmarc(domain).catch(() => ({ spfFound: false, dmarcStatus: 'Unknown' })),
        safeFetch(`${baseUrl}/.well-known/security.txt`, fetchOpts),
    ]);
    const headersAudit = auditSecurityHeaders(homepage.headers);
    const securityTxtFound = !!(securityTxtRes && securityTxtRes.statusCode === 200);

    const record = {
        companyName,
        domain,
        website: baseUrl,
        bestEmail,
        bestPhone,
        allEmails: emails,
        allPhones: phones,
        linkedinUrl: socials.linkedinUrl,
        instagramUrl: socials.instagramUrl,
        twitterUrl: socials.twitterUrl,
        facebookUrl: socials.facebookUrl,
        youtubeUrl: socials.youtubeUrl,
        tiktokUrl: socials.tiktokUrl,
        whatsappUrl: socials.whatsappUrl,
        cmsPlatform,
        pixels,
        conversionTools,
        geo,
        dns: { emailProvider: emailProviderInfo.provider, mxRecords: emailProviderInfo.raw, spfFound: spfDmarc.spfFound, dmarcStatus: spfDmarc.dmarcStatus },
        headers: headersAudit,
        securityTxtFound,
    };

    const intelligence = buildLeadIntelligence(record, agencyFocus);

    return {
        leadPriority: intelligence.leadPriority,
        companyName: record.companyName,
        domain: record.domain,
        website: record.website,
        bestEmail: record.bestEmail,
        bestPhone: record.bestPhone,
        estDealValue: intelligence.estDealValue,
        threeSecondSummary: intelligence.threeSecondSummary,
        whatToPitch: intelligence.whatToPitch,
        oneClickColdEmail: intelligence.oneClickColdEmail,
        oneClickLoomScript: intelligence.oneClickLoomScript,
        adPixelLeak: intelligence.adPixelLeak,
        leadScore: intelligence.leadScore,
        linkedinUrl: record.linkedinUrl,
        instagramUrl: record.instagramUrl,
        twitterUrl: record.twitterUrl,
        facebookUrl: record.facebookUrl,
        youtubeUrl: record.youtubeUrl,
        tiktokUrl: record.tiktokUrl,
        whatsappUrl: record.whatsappUrl,
        allEmails: record.allEmails,
        allPhones: record.allPhones,
        cmsPlatform: record.cmsPlatform,
        techStack: { cms: record.cmsPlatform },
        adPixels: record.pixels.detectedNames,
        conversionTools: record.conversionTools,
        aiSearchReadinessScore: record.geo.aiSearchReadinessScore,
        llmsTxtFound: record.geo.llmsTxtFound,
        aiBotsBlocked: record.geo.blockedBots,
        hasSchemaOrgData: record.geo.ldJsonFound,
        hasOpenGraphTags: record.geo.ogTagsFound,
        emailProvider: record.dns.emailProvider,
        spfFound: record.dns.spfFound,
        dmarcStatus: record.dns.dmarcStatus,
        serverHeader: record.headers.server,
        poweredByHeader: record.headers.poweredBy,
        usesCloudflare: record.headers.cloudflare,
        missingSecurityHeaders: record.headers.missingSecurityHeaders,
        securityTxtFound: record.securityTxtFound,
        auditedAt: new Date().toISOString(),
    };
}

// ---------------------------------------------------------------------------
// MODULE 6: Real-time webhook push
// ---------------------------------------------------------------------------

async function pushToWebhook(webhookUrl, record) {
    try {
        await gotScraping.post({
            url: webhookUrl,
            json: record,
            timeout: { request: 10000 },
            throwHttpErrors: false,
        });
    } catch (err) {
        log.warning(`⚠️  Webhook push failed for ${record.domain}: ${err.message}`);
    }
}

// ---------------------------------------------------------------------------
// Main Actor entrypoint
// ---------------------------------------------------------------------------

async function run() {
    const input = (await Actor.getInput()) || {};
    const {
        searchKeyword = '',
        urls = [],
        agencyFocus = 'all',
        crawlContactPages: shouldCrawlContactPages = true,
        maxResults = 20,
        maxSearchQueriesPerKeyword = 3,
        requestTimeoutSecs = 15,
        webhookUrl = '',
        proxyConfiguration: proxyConfigInput = { useApifyProxy: true },
    } = input;

    const timeoutMs = Math.max(5000, requestTimeoutSecs * 1000);

    let proxyConfiguration;
    try {
        proxyConfiguration = await Actor.createProxyConfiguration(proxyConfigInput);
    } catch (err) {
        log.warning(`⚠️  Proxy configuration unavailable, continuing without proxy: ${err.message}`);
        proxyConfiguration = undefined;
    }
    const proxyUrl = proxyConfiguration ? await proxyConfiguration.newUrl() : undefined;
    const fetchOpts = { proxyUrl, timeoutMs };

    log.info('🚀 Starting 360° B2B Revenue-Leak, Passive OSINT, GEO & Contact Enricher');
    log.info(`⚙️  Settings → agencyFocus: ${agencyFocus} | maxResults: ${maxResults} | crawlContactPages: ${shouldCrawlContactPages}`);

    // ---- Build candidate domain list ----
    const candidateDomains = [];
    const seen = new Set();

    // Explicit user-pasted URLs are always honored, even if they'd otherwise be
    // filtered as a "directory" domain during auto-discovery (Module 1).
    for (const rawUrl of urls) {
        const domain = toRootDomain(rawUrl);
        if (domain && !seen.has(domain)) {
            seen.add(domain);
            candidateDomains.push(domain);
        }
    }

    if (candidateDomains.length < maxResults && searchKeyword && searchKeyword.trim()) {
        const needed = Math.max(0, maxResults - candidateDomains.length) * 2 + 5;
        const discovered = await discoverDomainsFromKeyword({
            keyword: searchKeyword.trim(),
            needed,
            maxQueries: maxSearchQueriesPerKeyword,
            proxyUrl,
            timeoutMs,
        });
        for (const domain of discovered) {
            if (!seen.has(domain) && !isBlockedDomain(domain)) {
                seen.add(domain);
                candidateDomains.push(domain);
            }
        }
        log.info(`🔎 Discovery found ${discovered.length} candidate domains for "${searchKeyword}"`);
    }

    if (candidateDomains.length === 0) {
        log.warning('⚠️  No URLs provided and no domains discovered from searchKeyword. Nothing to process.');
        return;
    }

    const workingSet = candidateDomains.slice(0, Math.max(maxResults * 2, maxResults));
    log.info(`📋 Processing up to ${workingSet.length} candidate domains (target: ${maxResults} enriched leads)...`);

    let successCount = 0;
    const counters = { hot: 0, warm: 0, cold: 0 };

    await mapWithConcurrency(workingSet, 5, async (domain) => {
        if (successCount >= maxResults) return null;
        log.info(`🔬 Auditing ${domain}...`);
        try {
            const record = await processTarget(domain, {
                crawlContactPages: shouldCrawlContactPages,
                agencyFocus,
                fetchOpts,
            });
            if (successCount >= maxResults) return null;
            successCount += 1;

            if (record.leadPriority?.includes('HOT')) counters.hot += 1;
            else if (record.leadPriority?.includes('WARM')) counters.warm += 1;
            else counters.cold += 1;

            await Actor.pushData(record);
            log.info(`✅ [${successCount}/${maxResults}] ${domain} → ${record.leadPriority}`);

            if (webhookUrl && webhookUrl.trim()) {
                await pushToWebhook(webhookUrl.trim(), record);
            }
            return record;
        } catch (err) {
            log.exception(err, `❌ Failed to process ${domain}`);
            return null;
        }
    });

    log.info('🏁 Run complete!');
    log.info(`📊 Summary → 🔥 Hot: ${counters.hot} | 🟡 Warm: ${counters.warm} | ❄️ Cold: ${counters.cold} | Total: ${successCount}`);
}

await Actor.init();

try {
    await run();
} catch (err) {
    log.exception(err, '💥 Fatal error in Actor run');
} finally {
    await Actor.exit();
}
