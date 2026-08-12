const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const tls = require('tls');
const https = require('https');
const http = require('http');

let freeDomains = [];
try {
  freeDomains = require('./free-email-domains.json');
} catch (e) {
  console.warn('[CustomerVerify] Could not load free-email-domains.json, continuing without it.');
}

const FREE_EMAIL_DOMAINS = new Set(freeDomains);
const DISPOSABLE_PATTERNS = ['tempmail', 'throwaway', 'guerrilla', 'mailinator', 'yopmail', 'sharklasers', 'guerrillamail', 'grr.la', 'dispostable', 'maildrop'];

class CustomerVerifyService {
  constructor(config = {}) {
    this.hunterApiKey = config.hunterApiKey || process.env.HUNTER_API_KEY;
    this.googleApiKey = config.googleApiKey || process.env.GOOGLE_API_KEY;
    
    const modes = [];
    if (!this.hunterApiKey) modes.push('Hunter.io');
    if (!this.googleApiKey) modes.push('Google');
    if (modes.length) {
      console.log(`[CustomerVerify] MOCK mode for: ${modes.join(', ')} — set API keys for live verification`);
    }

    const railwayDataDir = '/data';
    const localDataDir = path.join(__dirname, 'data');
    this.dataDir = fs.existsSync(railwayDataDir) ? railwayDataDir : localDataDir;
    
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }

    this.resultsFile = path.join(this.dataDir, 'verification-results.json');
    this.results = {};
    
    if (fs.existsSync(this.resultsFile)) {
      try {
        const fileContent = fs.readFileSync(this.resultsFile, 'utf8');
        this.results = JSON.parse(fileContent);
      } catch (err) {
        console.error('[CustomerVerify] Failed to load results JSON', err.message);
      }
    }
  }

  classifyEmail(email) {
    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return { status: 'fail', type: 'invalid', isDisposable: false };
    if (FREE_EMAIL_DOMAINS.has(domain)) return { status: 'fail', type: 'free', isDisposable: false };
    if (DISPOSABLE_PATTERNS.some(p => domain.includes(p))) return { status: 'fail', type: 'disposable', isDisposable: true };
    return { status: 'pass', type: 'business', isDisposable: false };
  }

  _mockEmailVerification(email) {
    return { status: 'pass', result: 'deliverable', score: 93, isDeliverable: true, smtpValid: true, mxRecords: true, source: 'mock' };
  }

  async verifyEmail(email) {
    if (!this.hunterApiKey) return this._mockEmailVerification(email);
    
    const url = `https://api.hunter.io/v2/email-verifier?email=${encodeURIComponent(email)}&api_key=${this.hunterApiKey}`;
    const resp = await fetch(url);
    const json = await resp.json();
    if (json.errors) throw new Error(json.errors[0]?.details || 'Hunter API error');
    
    const d = json.data;
    return {
      status: d.result === 'deliverable' ? 'pass' : (d.result === 'risky' ? 'warn' : 'fail'),
      result: d.result,
      score: d.score,
      isDeliverable: d.result === 'deliverable' || d.result === 'risky',
      smtpValid: d.smtp_check,
      mxRecords: d.mx_records,
      source: 'hunter.io'
    };
  }

  async verifyDomain(domain) {
    const results = {
      status: 'pass',
      hasMxRecords: false,
      hasARecord: false,
      hasValidSSL: false,
      sslIssuer: null,
      sslExpiry: null,
      websiteResponds: false,
      httpStatus: null,
      // WHOIS data
      domainAge: null,
      domainAgeYears: null,
      createdDate: null,
      expiryDate: null,
      registrar: null,
      // Website content analysis
      pageTitle: null,
      metaDescription: null,
      contentLength: null,
      isParkedDomain: false,
      hasRealContent: false,
      redirectUrl: null
    };

    // Run all checks in parallel
    await Promise.all([
      this._checkMx(domain, results),
      this._checkARecord(domain, results),
      this._checkSSL(domain, results),
      this._checkWebsite(domain, results),
      this._checkWhois(domain, results)
    ]);

    // Determine overall status
    const critical = [results.hasMxRecords, results.hasARecord || results.websiteResponds];
    const warnings = [results.isParkedDomain, results.domainAgeYears !== null && results.domainAgeYears < 0.08]; // < 1 month

    if (warnings.some(Boolean)) {
      results.status = 'warn';
    } else if (critical.every(Boolean) && results.hasRealContent) {
      results.status = 'pass';
    } else if (critical.some(Boolean)) {
      results.status = 'warn';
    } else {
      results.status = 'fail';
    }

    return results;
  }

  async _checkMx(domain, results) {
    try {
      const mx = await dns.resolveMx(domain);
      results.hasMxRecords = mx && mx.length > 0;
    } catch (e) { }
  }

  async _checkARecord(domain, results) {
    try {
      const addrs = await dns.resolve4(domain);
      results.hasARecord = addrs && addrs.length > 0;
    } catch (e) { }
  }

  async _checkSSL(domain, results) {
    try {
      const sslResult = await new Promise((resolve) => {
        const socket = tls.connect(443, domain, { servername: domain, timeout: 5000 }, () => {
          const cert = socket.getPeerCertificate();
          socket.destroy();
          resolve({
            valid: !socket.authorizationError,
            issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
            expiry: cert.valid_to
          });
        });
        socket.on('error', () => resolve(null));
        socket.setTimeout(5000, () => { socket.destroy(); resolve(null); });
      });
      if (sslResult) {
        results.hasValidSSL = sslResult.valid;
        results.sslIssuer = sslResult.issuer;
        results.sslExpiry = sslResult.expiry;
      }

      if (results.hasValidSSL) {
        try {
          const sslOrg = await new Promise((resolve) => {
            const socket = tls.connect(443, domain, { servername: domain, timeout: 4000 }, () => {
              const cert = socket.getPeerCertificate();
              socket.destroy();
              resolve(cert?.subject?.O || null);
            });
            socket.on('error', () => resolve(null));
            socket.setTimeout(4000, () => { socket.destroy(); resolve(null); });
          });
          if (sslOrg) results.sslOrganization = sslOrg;
        } catch (_) {}
      }
    } catch (e) { }
  }

  async _checkWebsite(domain, results) {
    try {
      const { statusCode, body, finalUrl } = await new Promise((resolve) => {
        const makeRequest = (url, redirectCount = 0) => {
          const mod = url.startsWith('https') ? https : http;
          const req = mod.get(url, { timeout: 10000, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; FelloVerify/1.0)' } }, (resp) => {
            // Follow redirects (up to 5)
            if ([301, 302, 303, 307, 308].includes(resp.statusCode) && resp.headers.location && redirectCount < 5) {
              let loc = resp.headers.location;
              if (loc.startsWith('/')) loc = new URL(loc, url).href;
              resp.resume();
              return makeRequest(loc, redirectCount + 1);
            }

            let data = '';
            resp.on('data', chunk => { if (data.length < 1000000) data += chunk; }); // Cap at 1MB for SPAs
            resp.on('end', () => resolve({ statusCode: resp.statusCode, body: data, finalUrl: url }));
          });
          req.on('error', () => {
            if (url.startsWith('https')) {
              makeRequest(`http://${domain}`, 0);
            } else {
              resolve({ statusCode: null, body: '', finalUrl: null });
            }
          });
          req.setTimeout(10000, () => { req.destroy(); resolve({ statusCode: null, body: '', finalUrl: null }); });
        };
        makeRequest(`https://${domain}`);
      });

      if (statusCode) {
        results.websiteResponds = statusCode >= 200 && statusCode < 400;
        results.httpStatus = statusCode;
        if (finalUrl && finalUrl !== `https://${domain}` && finalUrl !== `https://${domain}/`) {
          results.redirectUrl = finalUrl;
        }
      }

      // Check if redirect is same-domain (e.g., squareup.com -> squareup.com/us/en)
      if (results.redirectUrl) {
        try {
          const redirectHost = new URL(results.redirectUrl).hostname.replace(/^www\./, '');
          results.isSameDomainRedirect = (redirectHost === domain || redirectHost === `www.${domain}`);
        } catch (_) { results.isSameDomainRedirect = false; }
      }

      if (body) {
        results.contentLength = body.length;

        // Extract page title
        const titleMatch = body.match(/<title[^>]*>([^<]*)<\/title>/i);
        if (titleMatch) results.pageTitle = titleMatch[1].trim().substring(0, 200);

        // Extract meta description
        const descMatch = body.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)/i) ||
                          body.match(/<meta[^>]*content=["']([^"']*)[^>]*name=["']description["']/i);
        if (descMatch) results.metaDescription = descMatch[1].trim().substring(0, 300);

        // Detect parked/for-sale domains
        const lowerBody = body.toLowerCase();
        const parkedIndicators = [
          'this domain is for sale', 'buy this domain', 'domain is parked',
          'parked by', 'godaddy domain parking', 'sedoparking', 'domain parking',
          'this webpage is parked', 'hugedomains.com', 'dan.com', 'afternic',
          'domain may be for sale', 'make an offer', 'purchase this domain',
          'this domain name has been registered', 'under construction',
          'coming soon', 'page is under construction'
        ];
        const parkedHits = parkedIndicators.filter(p => lowerBody.includes(p));
        // Only flag as parked if multiple indicators OR if the page has very little content
        // (real sites with 700+ words that mention 'coming soon' are NOT parked)
        const textContent = body.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
                               .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
                               .replace(/<[^>]+>/g, ' ')
                               .replace(/\s+/g, ' ')
                               .trim();
        const wordCount = textContent.split(/\s+/).filter(w => w.length > 2).length;
        results.isParkedDomain = parkedHits.length >= 2 || (parkedHits.length >= 1 && wordCount < 100);
        if (parkedHits.length > 0) {
          results.parkedReason = parkedHits[0];
        }

        results.hasRealContent = !results.isParkedDomain && wordCount > 50 && !!results.pageTitle;
        results.wordCount = wordCount;
      }
    } catch (e) { }
  }

  async _checkWhois(domain, results) {
    try {
      const { execSync } = require('child_process');
      const whoisRaw = execSync(`whois ${domain.replace(/[^a-zA-Z0-9.-]/g, '')} 2>/dev/null`, {
        timeout: 10000,
        encoding: 'utf8',
        maxBuffer: 1024 * 512
      });

      // Parse creation date
      const createdMatch = whoisRaw.match(/Creation Date:\s*(.+)/i) ||
                           whoisRaw.match(/created:\s*(.+)/i) ||
                           whoisRaw.match(/Registration Date:\s*(.+)/i) ||
                           whoisRaw.match(/Created on:\s*(.+)/i);
      if (createdMatch) {
        const created = new Date(createdMatch[1].trim());
        if (!isNaN(created.getTime())) {
          results.createdDate = created.toISOString().split('T')[0];
          const ageMs = Date.now() - created.getTime();
          results.domainAgeYears = Math.round((ageMs / (365.25 * 24 * 60 * 60 * 1000)) * 10) / 10;
          if (results.domainAgeYears < 1) {
            const months = Math.round((ageMs / (30.44 * 24 * 60 * 60 * 1000)));
            results.domainAge = months <= 1 ? '< 1 month' : `${months} months`;
          } else {
            results.domainAge = `${results.domainAgeYears} years`;
          }
        }
      }

      // Parse expiry date
      const expiryMatch = whoisRaw.match(/Expir[a-z]* Date:\s*(.+)/i) ||
                          whoisRaw.match(/paid-till:\s*(.+)/i);
      if (expiryMatch) {
        const expiry = new Date(expiryMatch[1].trim());
        if (!isNaN(expiry.getTime())) {
          results.expiryDate = expiry.toISOString().split('T')[0];
        }
      }

      // Parse registrar
      const registrarMatch = whoisRaw.match(/Registrar:\s*(.+)/i);
      if (registrarMatch) {
        results.registrar = registrarMatch[1].trim().replace(/,?\s*(LLC|Inc\.?|Ltd\.?|Corp\.?)$/i, '').trim();
      }

    } catch (e) {
      // whois command failed or timed out — not critical
      console.warn(`[CustomerVerify] WHOIS lookup failed for ${domain}: ${e.message}`);
    }
  }

  _mockCompanyEnrichment(domain) {
    const companyName = domain.split('.')[0].charAt(0).toUpperCase() + domain.split('.')[0].slice(1);
    return {
      status: 'found',
      companyName: companyName,
      industry: 'Technology',
      employeeCount: '51-200',
      description: `Simulated mock company data for ${companyName}`,
      linkedinUrl: `https://linkedin.com/company/${companyName.toLowerCase()}`,
      twitterUrl: null,
      facebookUrl: null,
      country: 'United States',
      city: 'San Francisco',
      emailCount: 42,
      source: 'mock'
    };
  }

  async enrichCompany(domain) {
    if (!this.hunterApiKey) return this._mockCompanyEnrichment(domain);
    
    const url = `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(domain)}&api_key=${this.hunterApiKey}`;
    const resp = await fetch(url);
    const json = await resp.json();
    if (json.errors) return { status: 'unavailable', source: 'hunter.io' };
    
    const d = json.data;
    return {
      status: d.organization ? 'found' : 'unavailable',
      companyName: d.organization || null,
      industry: d.industry || null,
      employeeCount: d.company_type || null,
      description: d.description || null,
      linkedinUrl: d.linkedin || null,
      twitterUrl: d.twitter || null,
      facebookUrl: d.facebook || null,
      country: d.country || null,
      city: d.city || null,
      emailCount: d.total || 0,
      source: 'hunter.io'
    };
  }

  // ── Layer 5: Google Places Verification ────────────────────────────
  async verifyGooglePlaces(companyName, domain, altDomains = []) {
    const query = companyName || domain.split('.')[0];
    
    if (!this.googleApiKey) return this._mockGooglePlaces(query, domain);

    try {
      const fieldMask = 'places.displayName,places.formattedAddress,places.rating,places.userRatingCount,places.websiteUri,places.googleMapsUri,places.businessStatus,places.nationalPhoneNumber,places.regularOpeningHours';
      
      // Search with domain context first
      let places = await this._placesSearch(`"${query}" ${domain}`, fieldMask);
      
      // Fallback: try without domain
      if (!places.length) {
        places = await this._placesSearch(`${query} business`, fieldMask);
      }

      if (!places.length) {
        return { status: 'not_found', hasListing: false, domainMatch: false, source: 'google_places' };
      }

      // Find domain-matching result
      let bestMatch = null;
      let domainMatch = false;

      // Check all domains (primary + alternates from redirects)
      const allDomains = [domain, ...altDomains].map(d => d.toLowerCase());

      for (const place of places.slice(0, 5)) {
        const placeWebsite = (place.websiteUri || '').toLowerCase();
        if (allDomains.some(d => placeWebsite.includes(d))) {
          bestMatch = place;
          domainMatch = true;
          break;
        }
        if (!bestMatch) bestMatch = place;
      }

      const place = bestMatch;
      const placeWebsite = (place.websiteUri || '').toLowerCase();
      domainMatch = domainMatch || allDomains.some(d => placeWebsite.includes(d));

      // If we found a match with verified domain, return it
      if (domainMatch) {
        return {
          status: 'verified_match',
          hasListing: true,
          domainMatch: true,
          name: place.displayName?.text || place.displayName || null,
          address: place.formattedAddress || null,
          rating: place.rating || null,
          reviewCount: place.userRatingCount || 0,
          businessStatus: place.businessStatus || null,
          phone: place.nationalPhoneNumber || null,
          website: place.websiteUri || null,
          hasWebsite: !!place.websiteUri,
          hasHours: !!place.regularOpeningHours,
          mapsUrl: place.googleMapsUri || null,
          matchWarning: null,
          source: 'google_places'
        };
      }

      // No domain match — if the listing has a website on a different domain,
      // it's likely a different company entirely (e.g., myvenue.gr vs myvenue.com)
      // Don't show it, as it's misleading
      if (placeWebsite && !allDomains.some(d => placeWebsite.includes(d))) {
        return { status: 'not_found', hasListing: false, domainMatch: false, note: 'Google Places results did not match this domain', source: 'google_places' };
      }

      // Listing has no website — show it but flag as unverified
      return {
        status: 'unverified_match',
        hasListing: true,
        domainMatch: false,
        name: place.displayName?.text || place.displayName || null,
        address: place.formattedAddress || null,
        rating: place.rating || null,
        reviewCount: place.userRatingCount || 0,
        businessStatus: place.businessStatus || null,
        phone: place.nationalPhoneNumber || null,
        website: place.websiteUri || null,
        hasWebsite: !!place.websiteUri,
        hasHours: !!place.regularOpeningHours,
        mapsUrl: place.googleMapsUri || null,
        matchWarning: 'No website on listing to verify domain match',
        source: 'google_places'
      };
    } catch (e) {
      console.warn(`[CustomerVerify] Google Places error: ${e.message}`);
      return { status: 'error', error: e.message, source: 'google_places' };
    }
  }

  async _placesSearch(textQuery, fieldMask) {
    const url = 'https://places.googleapis.com/v1/places:searchText';
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Goog-Api-Key': this.googleApiKey,
        'X-Goog-FieldMask': fieldMask
      },
      body: JSON.stringify({ textQuery })
    });
    const json = await resp.json();
    return json.places || [];
  }

  _mockGooglePlaces(companyName, domain) {
    return {
      status: 'requires_api',
      hasListing: false,
      domainMatch: false,
      note: 'Google Places verification requires a GOOGLE_API_KEY to confirm physical business location.',
      source: 'mock'
    };
  }

  // ── Layer 6: Phone Number Validation ───────────────────────────────
  validatePhone(phone) {
    if (!phone) return { status: 'skipped', reason: 'No phone provided' };

    // Clean the phone number
    const cleaned = phone.replace(/[^0-9+]/g, '');
    
    const results = {
      status: 'pass',
      original: phone,
      cleaned: cleaned,
      isValid: false,
      type: 'unknown',
      isTollFree: false,
      isPremium: false,
      isVoIP: false,
      country: null,
      riskLevel: 'low'
    };

    // Basic length validation
    const digits = cleaned.replace(/^\+/, '');
    if (digits.length < 7 || digits.length > 15) {
      results.status = 'fail';
      results.type = 'invalid';
      results.riskLevel = 'high';
      return results;
    }
    results.isValid = true;

    // US/Canada number analysis
    const usNumber = digits.length === 10 ? digits : (digits.length === 11 && digits[0] === '1' ? digits.substring(1) : null);
    if (usNumber) {
      results.country = 'US/CA';
      const areaCode = usNumber.substring(0, 3);
      
      // Toll-free numbers
      const tollFree = ['800', '888', '877', '866', '855', '844', '833'];
      if (tollFree.includes(areaCode)) {
        results.type = 'toll_free';
        results.isTollFree = true;
        // Toll-free is somewhat positive for businesses
      }

      // Known VoIP/virtual number area codes and prefixes
      const voipIndicators = [
        '500', '521', '522', '523', '524', '525', '526', '527', '528', '529', '533',
        '544', '566', '577', '588'
      ];
      if (voipIndicators.includes(areaCode)) {
        results.type = 'voip';
        results.isVoIP = true;
        results.riskLevel = 'medium';
      }

      // Premium/adult numbers  
      if (areaCode === '900' || areaCode === '976') {
        results.type = 'premium';
        results.isPremium = true;
        results.riskLevel = 'high';
      }

      // If not flagged, assume landline/mobile
      if (results.type === 'unknown') {
        results.type = 'landline_or_mobile';
      }
    } else if (digits.startsWith('44')) {
      results.country = 'UK';
      results.type = 'international';
    } else if (digits.startsWith('61')) {
      results.country = 'AU';
      results.type = 'international';
    } else if (digits.length >= 10) {
      results.country = 'International';
      results.type = 'international';
    }

    // Known Google Voice patterns (area codes frequently used by GV)
    const gvAreaCodes = ['747', '934', '458', '725', '272', '564', '463', '743'];
    if (usNumber && gvAreaCodes.includes(usNumber.substring(0, 3))) {
      results.isVoIP = true;
      results.riskLevel = 'medium';
      results.type = 'possible_voip';
    }

    results.status = results.riskLevel === 'high' ? 'fail' : (results.riskLevel === 'medium' ? 'warn' : 'pass');
    return results;
  }

  // ── Layer 7: Online Presence Check ──────────────────────────────────
  // Scrapes the company's OWN website for social media links (no guessing slugs)
  // This guarantees we find the CORRECT profiles — the company linked to them.
  async checkSearchPresence(companyName, domain) {
    const socialPatterns = [
      { platform: 'LinkedIn', regex: /https?:\/\/(www\.)?linkedin\.com\/(company|in)\/[^\s"'<>]+/gi, icon: '💼' },
      { platform: 'Facebook', regex: /https?:\/\/(www\.)?(facebook|fb)\.com\/[^\s"'<>]+/gi, icon: '📘' },
      { platform: 'Instagram', regex: /https?:\/\/(www\.)?instagram\.com\/[^\s"'<>]+/gi, icon: '📷' },
      { platform: 'Twitter', regex: /https?:\/\/(www\.)?(twitter|x)\.com\/[^\s"'<>]+/gi, icon: '🐦' },
      { platform: 'YouTube', regex: /https?:\/\/(www\.)?youtube\.com\/(channel|c|@|user)\/[^\s"'<>]+/gi, icon: '🎬' },
      { platform: 'TikTok', regex: /https?:\/\/(www\.)?tiktok\.com\/@[^\s"'<>]+/gi, icon: '🎵' },
      { platform: 'Yelp', regex: /https?:\/\/(www\.)?yelp\.com\/biz\/[^\s"'<>]+/gi, icon: '⭐' },
      { platform: 'BBB', regex: /https?:\/\/(www\.)?bbb\.org\/[^\s"'<>]+/gi, icon: '🏅' },
      { platform: 'Glassdoor', regex: /https?:\/\/(www\.)?glassdoor\.com\/[^\s"'<>]+/gi, icon: '🏢' },
      { platform: 'Pinterest', regex: /https?:\/\/(www\.)?pinterest\.com\/[^\s"'<>]+/gi, icon: '📌' },
    ];

    try {
      // Fetch the company's homepage
      const pageUrl = `https://${domain}`;
      const html = await new Promise((resolve) => {
        const req = https.get(pageUrl, {
          timeout: 8000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Accept': 'text/html'
          }
        }, (resp) => {
          // Follow one redirect
          if (resp.statusCode >= 300 && resp.statusCode < 400 && resp.headers.location) {
            const redirectUrl = resp.headers.location.startsWith('http') ? resp.headers.location : `https://${domain}${resp.headers.location}`;
            resp.resume();
            const redirectMod = redirectUrl.startsWith('https') ? https : http;
            redirectMod.get(redirectUrl, { timeout: 8000, headers: { 'User-Agent': 'Mozilla/5.0' } }, (resp2) => {
              let data = '';
              resp2.on('data', chunk => { if (data.length < 200000) data += chunk; });
              resp2.on('end', () => resolve(data));
            }).on('error', () => resolve(''));
            return;
          }
          let data = '';
          resp.on('data', chunk => { if (data.length < 200000) data += chunk; });
          resp.on('end', () => resolve(data));
        });
        req.on('error', () => resolve(''));
        req.setTimeout(8000, () => { req.destroy(); resolve(''); });
      });

      if (!html || html.length < 100) {
        return { status: 'error', error: 'Could not fetch website', platformsFound: 0, details: [], source: 'website_scrape' };
      }

      // If homepage doesn't have social links, also check common subpages and linked JS
      let fullContent = html;

      // Extract and fetch linked JS files from the same domain (social links often in footer JS)
      const jsMatches = html.match(/src="(https?:\/\/[^"]*\.js[^"]*)"/gi) || [];
      const ownJsFiles = jsMatches
        .map(m => m.replace(/^src="/i, '').replace(/"$/, ''))
        .filter(u => u.includes(domain))
        .slice(0, 5);

      const jsFetches = ownJsFiles.map(jsUrl =>
        new Promise(resolve => {
          https.get(jsUrl, { timeout: 4000, headers: { 'User-Agent': 'Mozilla/5.0' } }, resp => {
            let d = ''; resp.on('data', c => { if (d.length < 50000) d += c; }); resp.on('end', () => resolve(d));
          }).on('error', () => resolve(''));
        })
      );

      // Also check /contact and /about pages + common subdomains
      const subpages = ['contact', 'about', 'about-us'].map(page =>
        new Promise(resolve => {
          https.get(`https://${domain}/${page}`, { timeout: 4000, headers: { 'User-Agent': 'Mozilla/5.0' } }, resp => {
            if (resp.statusCode >= 300 && resp.statusCode < 400) { resp.resume(); return resolve(''); }
            let d = ''; resp.on('data', c => { if (d.length < 100000) d += c; }); resp.on('end', () => resolve(d));
          }).on('error', () => resolve(''));
        })
      );

      // Check common subdomains (many companies put social links on subdomains)
      const subdomains = ['events', 'www', 'blog', 'shop'].map(sub =>
        new Promise(resolve => {
          https.get(`https://${sub}.${domain}`, { timeout: 5000, headers: { 'User-Agent': 'Mozilla/5.0' } }, resp => {
            // Follow one redirect
            if (resp.statusCode >= 300 && resp.statusCode < 400 && resp.headers.location) {
              const loc = resp.headers.location;
              resp.resume();
              // Don't follow if it redirects back to the main domain (we already have that)
              if (loc === `https://${domain}` || loc === `https://${domain}/` || loc === `https://www.${domain}/`) return resolve('');
              https.get(loc, { timeout: 4000, headers: { 'User-Agent': 'Mozilla/5.0' } }, resp2 => {
                let d = ''; resp2.on('data', c => { if (d.length < 2000000) d += c; }); resp2.on('end', () => resolve(d));
              }).on('error', () => resolve(''));
              return;
            }
            if (resp.statusCode >= 400) { resp.resume(); return resolve(''); }
            let d = ''; resp.on('data', c => { if (d.length < 2000000) d += c; }); resp.on('end', () => resolve(d));
          }).on('error', () => resolve(''));
        })
      );

      const extraContent = await Promise.all([...jsFetches, ...subpages, ...subdomains]);
      fullContent += '\n' + extraContent.join('\n');

      // Unescape common HTML/JSON escape patterns (Next.js, React SSR)
      fullContent = fullContent.replace(/\\"/g, '"').replace(/\\\//g, '/');

      // Extract social media links
      const foundProfiles = [];
      const seenPlatforms = new Set();

      for (const pattern of socialPatterns) {
        const matches = fullContent.match(pattern.regex) || [];
        for (const rawUrl of matches) {
          let url = rawUrl.replace(/['"<>\\]+$/, '').replace(/\/$/, '').replace(/\\u0026/g, '&');
          // Clean up common URL artifacts
          url = url.split('?')[0]; // Remove query params (viewAsMember, autoplay, etc.)
          // Skip generic platform homepages
          if (/^https?:\/\/(www\.)?(linkedin|facebook|fb|instagram|twitter|x|youtube|tiktok|yelp|bbb|glassdoor|pinterest)\.(com|org)\/?$/i.test(url)) continue;
          // Skip share/intent/sharer/embed links
          if (/\/(share|intent|sharer|dialog|embed)\b/i.test(url)) continue;

          if (!seenPlatforms.has(pattern.platform)) {
            seenPlatforms.add(pattern.platform);
            foundProfiles.push({
              platform: pattern.platform,
              url,
              icon: pattern.icon,
              exists: true,
              source: 'from_website'
            });
          }
        }
      }

      // Fallback: If website scrape found nothing, try Hunter.io domain search (has social profiles)
      if (foundProfiles.length === 0 && process.env.HUNTER_API_KEY) {
        try {
          const hunterUrl = `https://api.hunter.io/v2/domain-search?domain=${domain}&api_key=${process.env.HUNTER_API_KEY}`;
          const hunterResp = await fetch(hunterUrl, { signal: AbortSignal.timeout(6000) });
          const hunterJson = await hunterResp.json();
          const hd = hunterJson?.data || {};

          const hunterSocials = [
            { platform: 'LinkedIn', url: hd.linkedin, icon: '💼' },
            { platform: 'Facebook', url: hd.facebook, icon: '📘' },
            { platform: 'Twitter', url: hd.twitter, icon: '🐦' },
            { platform: 'Instagram', url: hd.instagram, icon: '📷' },
            { platform: 'YouTube', url: hd.youtube, icon: '🎬' },
          ];
          for (const s of hunterSocials) {
            if (s.url && !seenPlatforms.has(s.platform)) {
              seenPlatforms.add(s.platform);
              foundProfiles.push({
                platform: s.platform,
                url: s.url,
                icon: s.icon,
                exists: true,
                source: 'hunter.io'
              });
            }
          }
        } catch (_) { /* non-critical */ }
      }

      // If scraping found no profiles, try direct URL checks as fallback
      if (foundProfiles.length === 0) {
        const slug = (companyName || domain.split('.')[0]).toLowerCase().replace(/[^a-z0-9]/g, '');
        const slugDash = (companyName || domain.split('.')[0]).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
        const directChecks = [
          { platform: 'LinkedIn', url: `https://www.linkedin.com/company/${slugDash}`, icon: '💼' },
          { platform: 'Facebook', url: `https://www.facebook.com/${slug}`, icon: '📘' },
          { platform: 'Instagram', url: `https://www.instagram.com/${slug}`, icon: '📷' },
        ];
        
        const directResults = await Promise.all(directChecks.map(async (check) => {
          try {
            const resp = await fetch(check.url, {
              method: 'HEAD',
              redirect: 'manual',
              signal: AbortSignal.timeout(5000),
              headers: { 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36' }
            });
            // LinkedIn returns 200 for existing pages, 404 for non-existing
            // Facebook returns 302 to login for non-existing pages
            if (resp.status === 200) {
              return { ...check, exists: true, source: 'direct_check' };
            }
          } catch (_) {}
          return null;
        }));
        
        for (const r of directResults) {
          if (r) foundProfiles.push(r);
        }
      }

      const foundCount = foundProfiles.length;
      const source = foundProfiles.some(p => p.source === 'hunter.io') ? 'website_scrape + hunter.io' : 'website_scrape';

      return {
        status: foundCount >= 3 ? 'found' : (foundCount >= 1 ? 'limited' : 'not_found'),
        platformsFound: foundCount,
        platformsChecked: socialPatterns.length,
        hasLinkedIn: seenPlatforms.has('LinkedIn'),
        hasFacebook: seenPlatforms.has('Facebook'),
        hasInstagram: seenPlatforms.has('Instagram'),
        hasTwitter: seenPlatforms.has('Twitter'),
        hasYouTube: seenPlatforms.has('YouTube'),
        hasTikTok: seenPlatforms.has('TikTok'),
        hasYelp: seenPlatforms.has('Yelp'),
        hasBBB: seenPlatforms.has('BBB'),
        hasGlassdoor: seenPlatforms.has('Glassdoor'),
        details: foundProfiles,
        source
      };
    } catch (e) {
      console.warn(`[CustomerVerify] Online presence error: ${e.message}`);
      return { status: 'error', error: e.message, platformsFound: 0, details: [], source: 'website_scrape' };
    }
  }

  async checkEmailAuth(domain) {
    const results = { status: 'checked', hasSPF: false, hasDKIM: false, hasDMARC: false, score: 0, source: 'dns' };
    try {
      // Check SPF
      try {
        const txt = await dns.resolveTxt(domain);
        const spfRecord = txt.flat().find(r => r.startsWith('v=spf1'));
        if (spfRecord) {
          results.hasSPF = true;
          results.spfRecord = spfRecord.substring(0, 100);
        }
      } catch (_) {}

      // Check DMARC
      try {
        const dmarc = await dns.resolveTxt('_dmarc.' + domain);
        const dmarcRecord = dmarc.flat().find(r => r.startsWith('v=DMARC1'));
        if (dmarcRecord) {
          results.hasDMARC = true;
          const policyMatch = dmarcRecord.match(/p=(\w+)/);
          results.dmarcPolicy = policyMatch ? policyMatch[1] : 'unknown';
        }
      } catch (_) {}

      // Check DKIM (common selectors)
      const dkimSelectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail', 'dkim'];
      for (const sel of dkimSelectors) {
        try {
          const dkim = await dns.resolveTxt(sel + '._domainkey.' + domain);
          const dkimRecord = dkim.flat().find(r => r.includes('v=DKIM1') || r.includes('p='));
          if (dkimRecord) {
            results.hasDKIM = true;
            results.dkimSelector = sel;
            break;
          }
        } catch (_) {}
      }

      // Score: 0-3 based on how many auth methods are configured
      results.authCount = [results.hasSPF, results.hasDKIM, results.hasDMARC].filter(Boolean).length;
      results.status = results.authCount >= 2 ? 'strong' : results.authCount === 1 ? 'partial' : 'none';
      return results;
    } catch (e) {
      return { status: 'error', error: e.message, source: 'dns' };
    }
  }

  async checkSafeBrowsing(domain) {
    if (!this.googleApiKey) {
      return { status: 'skipped', isSafe: true, note: 'Requires GOOGLE_API_KEY', source: 'safe_browsing' };
    }
    try {
      const body = JSON.stringify({
        client: { clientId: 'fello-verify', clientVersion: '1.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [
            { url: 'http://' + domain + '/' },
            { url: 'https://' + domain + '/' }
          ]
        }
      });
      const resp = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${this.googleApiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        signal: AbortSignal.timeout(5000)
      });
      const data = await resp.json();
      const threats = data.matches || [];
      return {
        status: threats.length > 0 ? 'unsafe' : 'safe',
        isSafe: threats.length === 0,
        threatCount: threats.length,
        threats: threats.map(t => ({ type: t.threatType, platform: t.platformType })),
        source: 'google_safe_browsing'
      };
    } catch (e) {
      return { status: 'error', isSafe: true, error: e.message, source: 'safe_browsing' };
    }
  }

  async checkCertTransparency(domain) {
    try {
      const resp = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json&deduplicate=Y`, {
        signal: AbortSignal.timeout(8000),
        headers: { 'User-Agent': 'FelloVerify/1.0' }
      });
      if (!resp.ok) return { status: 'error', source: 'crt_sh' };
      const certs = await resp.json();
      if (!Array.isArray(certs) || certs.length === 0) {
        return { status: 'not_found', certCount: 0, source: 'crt_sh' };
      }
      // Find earliest and latest cert
      let earliest = null;
      let latest = null;
      for (const cert of certs) {
        const entered = cert.entry_timestamp || cert.not_before;
        if (entered) {
          const d = new Date(entered);
          if (!earliest || d < earliest) earliest = d;
          if (!latest || d > latest) latest = d;
        }
      }
      const yearsActive = earliest ? ((Date.now() - earliest.getTime()) / (365.25 * 24 * 60 * 60 * 1000)).toFixed(1) : null;
      return {
        status: 'found',
        certCount: certs.length,
        firstSeen: earliest ? earliest.toISOString().split('T')[0] : null,
        lastSeen: latest ? latest.toISOString().split('T')[0] : null,
        yearsActive: yearsActive ? parseFloat(yearsActive) : null,
        source: 'crt_sh'
      };
    } catch (e) {
      return { status: 'error', error: e.message, source: 'crt_sh' };
    }
  }

  async checkReverseIP(domain) {
    try {
      // Resolve domain to IP
      const addresses = await dns.resolve4(domain);
      if (!addresses || addresses.length === 0) {
        return { status: 'error', error: 'Could not resolve IP', source: 'reverse_ip' };
      }
      const ip = addresses[0];
      
      // Check reverse IP via HackerTarget (free, 100/day)
      const resp = await fetch(`https://api.hackertarget.com/reverseiplookup/?q=${ip}`, {
        signal: AbortSignal.timeout(8000),
        headers: { 'User-Agent': 'FelloVerify/1.0' }
      });
      const text = await resp.text();
      
      if (text.includes('error') || text.includes('API count exceeded')) {
        return { status: 'error', ip, error: 'API limit reached', source: 'reverse_ip' };
      }
      
      const domains = text.split('\\n').filter(d => d.trim() && d.includes('.'));
      const sharedCount = domains.length;
      
      return {
        status: 'found',
        ip,
        sharedDomains: sharedCount,
        isSharedHosting: sharedCount > 50,
        isDedicatedHosting: sharedCount <= 5,
        sampleDomains: domains.slice(0, 5),
        riskLevel: sharedCount > 500 ? 'high' : sharedCount > 50 ? 'medium' : 'low',
        source: 'reverse_ip'
      };
    } catch (e) {
      return { status: 'error', error: e.message, source: 'reverse_ip' };
    }
  }

  async _checkUrl(url, platform, bodyCheck = null) {
    try {
      const mod = url.startsWith('https') ? https : http;
      const result = await new Promise((resolve) => {
        const req = mod.get(url, {
          timeout: 6000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Language': 'en-US,en;q=0.9'
          }
        }, (resp) => {
          const isOk = resp.statusCode >= 200 && resp.statusCode < 400;
          if (!isOk) {
            resp.resume();
            return resolve({ exists: false, httpStatus: resp.statusCode });
          }
          if (bodyCheck) {
            let data = '';
            resp.on('data', chunk => {
              if (data.length < 50000) data += chunk;
            });
            resp.on('end', () => {
              resolve({ exists: bodyCheck(data), httpStatus: resp.statusCode });
            });
          } else {
            resp.resume(); // Drain response
            resolve({ exists: true, httpStatus: resp.statusCode });
          }
        });
        req.on('error', () => resolve({ exists: false, httpStatus: null }));
        req.setTimeout(6000, () => { req.destroy(); resolve({ exists: false, httpStatus: null }); });
      });
      return { platform, url, ...result };
    } catch (e) {
      return { platform, url, exists: false, httpStatus: null };
    }
  }

  // ── Layer 8: Web History (Wayback Machine) ─────────────────────────
  // Free, no API key needed. Uses the faster availability API + CDX as fallback.
  async verifyBusinessRegistration(companyName, domain) {
    try {
      // Try the fast availability API first (much faster than CDX)
      const availUrl = `https://archive.org/wayback/available?url=${domain}&timestamp=19900101`;

      let availJson = null;
      for (let attempt = 0; attempt < 2; attempt++) {
        if (attempt > 0) await new Promise(r => setTimeout(r, 2000)); // wait before retry
        try {
          const availResp = await fetch(availUrl, {
            headers: {
              'User-Agent': 'FelloVerify/1.0 (dano@fello.com)',
              'Accept': 'application/json'
            },
            signal: AbortSignal.timeout(10000)
          });
          if (availResp.status === 429) continue; // rate limited, retry
          const text = await availResp.text();
          if (text.startsWith('<')) continue; // HTML error page, retry
          availJson = JSON.parse(text);
          break;
        } catch (_) { continue; }
      }

      if (!availJson) {
        // If availability API fails, try CDX directly
        try {
          const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=${domain}&output=json&limit=1&fl=timestamp&sort=asc`;
          const cdxResp = await fetch(cdxUrl, {
            headers: { 'User-Agent': 'FelloVerify/1.0 (dano@fello.com)' },
            signal: AbortSignal.timeout(10000)
          });
          const cdxText = await cdxResp.text();
          if (cdxText.startsWith('<') || cdxResp.status === 429) {
            return { status: 'error', error: 'Wayback Machine rate limited — try again shortly', source: 'wayback_machine' };
          }
          const cdxJson = JSON.parse(cdxText);
          if (cdxJson && cdxJson.length >= 2) {
            availJson = { archived_snapshots: { closest: { timestamp: cdxJson[1][0] } } };
          }
        } catch (_) {}
      }
      if (!availJson) {
        // Both APIs failed — likely rate limited
        return { status: 'error', error: 'Wayback Machine unavailable — try again shortly', source: 'wayback_machine' };
      }

      const snapshot = availJson?.archived_snapshots?.closest;
      if (!snapshot || !snapshot.timestamp) {
        return { status: 'not_found', domain, note: 'No web archive history found', source: 'wayback_machine' };
      }

      // Now get the actual earliest snapshot via CDX (non-blocking, with fallback)
      let earliestTs = snapshot.timestamp;
      try {
        const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=${domain}&output=json&limit=1&fl=timestamp&sort=asc`;
        const cdxResp = await fetch(cdxUrl, {
          headers: { 'User-Agent': 'FelloVerify/1.0 (dano@fello.com)' },
          signal: AbortSignal.timeout(8000)
        });
        const cdxText = await cdxResp.text();
        const cdxJson = JSON.parse(cdxText);
        if (cdxJson && cdxJson.length >= 2) {
          earliestTs = cdxJson[1][0];
        }
      } catch (_) { /* use availability API timestamp as fallback */ }

      const year = parseInt(earliestTs.substring(0, 4));
      const month = parseInt(earliestTs.substring(4, 6));
      const day = parseInt(earliestTs.substring(6, 8));
      const firstArchived = new Date(year, month - 1, day);
      const archiveAgeYears = ((Date.now() - firstArchived.getTime()) / (365.25 * 24 * 60 * 60 * 1000)).toFixed(1);
      const isEstablished = parseFloat(archiveAgeYears) >= 2;
      const archiveUrl = `https://web.archive.org/web/${earliestTs}/${domain}`;

      return {
        status: isEstablished ? 'found' : 'limited',
        companyStatus: isEstablished ? 'active' : 'new',
        domain,
        firstArchived: `${year}-${String(month).padStart(2,'0')}-${String(day).padStart(2,'0')}`,
        archiveAgeYears: parseFloat(archiveAgeYears),
        archiveUrl,
        isEstablished,
        source: 'wayback_machine'
      };
    } catch (e) {
      console.warn(`[CustomerVerify] Wayback Machine error: ${e.message}`);
      return { status: 'error', error: e.message, source: 'wayback_machine' };
    }
  }

  calculateTrustScore(emailClass, emailVerify, domainVerify, companyEnrich, googlePlaces, phoneValidation, searchPresence, businessRegistration, trancoRank, wikipedia, secEdgar, emailAuth, safeBrowsing, certTransparency, reverseIP) {
    let score = 0;
    
    // Email signals (20 pts max)
    let emailPts = 0;
    if (emailVerify.isDeliverable) emailPts += 10;
    if (emailVerify.smtpValid) emailPts += 5;
    if (emailVerify.mxRecords) emailPts += 5;
    score += emailPts;
    
    // Domain infrastructure (10 pts max)
    let infraPts = 0;
    if (domainVerify.hasValidSSL) infraPts += 5;
    if (domainVerify.hasMxRecords) infraPts += 3;
    if (domainVerify.hasARecord) infraPts += 2;
    score += infraPts;
    
    // Website legitimacy (15 pts max)
    let contentPts = 0;
    const contentCheck = domainVerify.activeDomainCheck || domainVerify;
    if (contentCheck.websiteResponds) contentPts += 5;
    if (contentCheck.hasRealContent) contentPts += 5;
    if (domainVerify.isParkedDomain && !domainVerify.redirectedTo) contentPts -= 25;
    if (contentCheck.pageTitle) contentPts += 5;
    score += contentPts;
    
    // Domain age (10 pts max)
    let agePts = 0;
    if (domainVerify.domainAgeYears !== null) {
      if (domainVerify.domainAgeYears >= 2) agePts += 10;
      else if (domainVerify.domainAgeYears >= 1) agePts += 7;
      else if (domainVerify.domainAgeYears >= 0.25) agePts += 3;
      else agePts -= 5;
    }
    score += agePts;
    
    // Company enrichment (5 pts)
    let enrichPts = 0;
    if (companyEnrich.status === 'found') enrichPts += 5;
    score += enrichPts;

    // Google Places (15 pts max)
    let placesPts = 0;
    if (googlePlaces && googlePlaces.hasListing && googlePlaces.domainMatch) {
      placesPts += 5;
      if (googlePlaces.reviewCount >= 10) placesPts += 5;
      else if (googlePlaces.reviewCount >= 3) placesPts += 2;
      if (googlePlaces.rating >= 3.5) placesPts += 3;
      if (googlePlaces.hasHours) placesPts += 2;
    }
    score += placesPts;

    // Phone validation (5 pts max)
    let phonePts = 0;
    if (phoneValidation && phoneValidation.status !== 'skipped') {
      if (phoneValidation.isValid && !phoneValidation.isVoIP) phonePts += 5;
      else if (phoneValidation.isValid && phoneValidation.isVoIP) phonePts += 1;
      if (phoneValidation.isTollFree) phonePts += 2;
      if (phoneValidation.riskLevel === 'high') phonePts -= 10;
    }
    score += phonePts;

    // Search presence (10 pts max)
    let presencePts = 0;
    if (searchPresence && searchPresence.status === 'found') {
      presencePts += 5;
      if (searchPresence.hasLinkedIn) presencePts += 2;
      if (searchPresence.hasBBB) presencePts += 3;
    } else if (searchPresence && searchPresence.status === 'limited') {
      presencePts += 2;
    }
    score += presencePts;

    // Business Registration / Web History (12 pts max)
    let historyPts = 0;
    if (businessRegistration && businessRegistration.status === 'found') {
      if (businessRegistration.companyStatus === 'active') {
        historyPts += 12;
      } else {
        historyPts += 4;
      }
    } else if (businessRegistration && businessRegistration.status === 'error') {
      historyPts += 6;
    }
    score += historyPts;
    
    // Email Authentication (8 pts max) — add as a new category
    let authPts = 0;
    if (emailAuth && emailAuth.status !== 'error') {
      if (emailAuth.hasSPF) authPts += 3;
      if (emailAuth.hasDKIM) authPts += 3;
      if (emailAuth.hasDMARC) authPts += 2;
    }
    score += authPts;

    // Safe Browsing (-50 pts penalty if unsafe)
    let safePts = 0;
    if (safeBrowsing && safeBrowsing.status === 'unsafe') {
      score -= 50; // Major penalty
      safePts = -50;
    }

    // Certificate Transparency (5 pts max)
    let certPts = 0;
    if (certTransparency && certTransparency.status === 'found') {
      if (certTransparency.yearsActive >= 3) certPts += 5;
      else if (certTransparency.yearsActive >= 1) certPts += 3;
      else certPts += 1;
    }
    score += certPts;

    // Reverse IP (3 pts max, penalty for high-risk)
    let ipPts = 0;
    if (reverseIP && reverseIP.status === 'found') {
      if (reverseIP.isDedicatedHosting) ipPts += 3;
      else if (!reverseIP.isSharedHosting) ipPts += 1;
      if (reverseIP.riskLevel === 'high') { score -= 5; ipPts -= 5; }
    }
    score += ipPts;

    // Enterprise signals (bonus)
    let enterpriseBonus = 0;
    if (trancoRank && trancoRank.status === 'found' && trancoRank.isTopSite) {
      if (trancoRank.rank <= 1000) enterpriseBonus += 8;
      else if (trancoRank.rank <= 10000) enterpriseBonus += 6;
      else if (trancoRank.rank <= 50000) enterpriseBonus += 4;
      else enterpriseBonus += 2;
    }
    if (wikipedia && wikipedia.status === 'found') enterpriseBonus += 5;
    if (secEdgar && secEdgar.status === 'found' && secEdgar.isPublicCompany) enterpriseBonus += 5;
    if (domainVerify.sslOrganization) enterpriseBonus += 3;
    if (companyEnrich && companyEnrich.status === 'found' && companyEnrich.emailCount) {
      if (companyEnrich.emailCount >= 500) enterpriseBonus += 5;
      else if (companyEnrich.emailCount >= 100) enterpriseBonus += 3;
      else if (companyEnrich.emailCount >= 20) enterpriseBonus += 1;
    }

    if (enterpriseBonus >= 8 && emailVerify && !emailVerify.isDeliverable) {
      emailPts += 15;
      score += 15;
    }

    if (domainVerify.isSameDomainRedirect && domainVerify.wordCount > 50) {
      if (!domainVerify.hasRealContent) {
        contentPts += 10;
        score += 10;
      }
    }

    score += enterpriseBonus;

    const finalScore = Math.max(0, Math.min(score, 100));
    return {
      score: finalScore,
      breakdown: {
        emailSignals: { earned: emailPts, max: 20 },
        infrastructure: { earned: infraPts, max: 10 },
        websiteContent: { earned: contentPts, max: 15 },
        domainAge: { earned: agePts, max: 10 },
        companyEnrichment: { earned: enrichPts, max: 5 },
        googlePlaces: { earned: placesPts, max: 15 },
        phoneValidation: { earned: phonePts, max: 5 },
        onlinePresence: { earned: presencePts, max: 10 },
        webHistory: { earned: historyPts, max: 12 },
        emailAuth: { earned: authPts, max: 8 },
        safeBrowsing: { earned: safePts, max: 0, note: 'Penalty only' },
        certHistory: { earned: certPts, max: 5 },
        hostingAnalysis: { earned: ipPts, max: 3 },
        enterpriseBonus: { earned: enterpriseBonus, max: 26, note: 'Bonus only' }
      }
    };
  }

  getDecision(score) {
    if (score >= 80) return 'auto_approved';
    if (score >= 50) return 'needs_review';
    return 'rejected';
  }

  async verify(email, options = {}) {
    email = email.trim().toLowerCase();
    const domain = email.split('@')[1];
    const phone = options.phone || null;
    const companyName = options.companyName || null;
    
    console.log(`[CustomerVerify] Verifying: ${email}${phone ? ' | Phone: ' + phone : ''}${companyName ? ' | Company: ' + companyName : ''}`);
    
    const emailClassification = this.classifyEmail(email);
    
    if (emailClassification.status === 'fail') {
      const result = {
        email,
        domain,
        phone,
        companyName,
        trustScore: 0,
        decision: 'rejected',
        reason: `${emailClassification.type} email provider`,
        verifiedAt: new Date().toISOString(),
        checks: {
          emailClassification,
          emailVerification: { status: 'skipped', reason: 'Failed classification' },
          domainVerification: { status: 'skipped', reason: 'Failed classification' },
          companyEnrichment: { status: 'skipped', reason: 'Failed classification' },
          googlePlaces: { status: 'skipped', reason: 'Failed classification' },
          phoneValidation: { status: 'skipped', reason: 'Failed classification' },
          searchPresence: { status: 'skipped', reason: 'Failed classification' },
          businessRegistration: { status: 'skipped', reason: 'Failed classification' },
          trancoRank: { status: 'skipped', reason: 'Failed classification' },
          wikipedia: { status: 'skipped', reason: 'Failed classification' },
          secEdgar: { status: 'skipped', reason: 'Failed classification' },
          emailAuth: { status: 'skipped', reason: 'Failed classification' },
          safeBrowsing: { status: 'skipped', reason: 'Failed classification' },
          certTransparency: { status: 'skipped', reason: 'Failed classification' },
          reverseIP: { status: 'skipped', reason: 'Failed classification' }
        }
      };
      this._saveResult(result);
      return result;
    }
    
    // Resolve domain redirects (e.g., billfoldpos.com → billfold.tech)
    let activeDomain = domain;
    let redirectedFrom = null;
    try {
      const resolvedDomain = await this._resolveRedirectDomain(domain);
      if (resolvedDomain && resolvedDomain !== domain && resolvedDomain !== `www.${domain}`) {
        console.log(`[CustomerVerify] Domain redirect: ${domain} → ${resolvedDomain}`);
        redirectedFrom = domain;
        activeDomain = resolvedDomain;
      }
    } catch (_) {}

    // Phase 1: Domain verification first (to extract company name)
    const domainVerification = await this.verifyDomain(domain).catch(e => ({ status: 'error', error: e.message }));

    // Extract company name from page title if not provided
    let effectiveCompanyName = companyName;
    if (!effectiveCompanyName && domainVerification.pageTitle) {
      // Clean page title: remove common suffixes like 'Home -', '| Official Site', etc.
      let title = domainVerification.pageTitle;
      title = title.replace(/^(Home|Welcome|Official)\s*[-–|:]/i, '').trim();
      title = title.replace(/\s*[-–|:]\s*(Home|Official Site|Official Website|Welcome)$/i, '').trim();
      title = title.replace(/\s*[-–|]\s*$/, '').trim();
      if (title.length > 2 && title.length < 80) {
        effectiveCompanyName = title;
      }
    }

    // Phase 2: All other checks in parallel (using effectiveCompanyName)
    const [emailVerification, companyEnrichment, googlePlaces, searchPresence, businessRegistration, trancoRank, wikipedia, secEdgar, emailAuth, safeBrowsing, certTransparency, reverseIP] = await Promise.all([
      this.verifyEmail(email).catch(e => ({ status: 'error', error: e.message })),
      this.enrichCompany(activeDomain).catch(e => ({ status: 'error', error: e.message })),
      this.verifyGooglePlaces(effectiveCompanyName, activeDomain, redirectedFrom ? [redirectedFrom] : []).catch(e => ({ status: 'error', error: e.message })),
      this.checkSearchPresence(effectiveCompanyName, activeDomain).catch(e => ({ status: 'error', error: e.message })),
      this.verifyBusinessRegistration(effectiveCompanyName, activeDomain).catch(e => ({ status: 'error', error: e.message })),
      this.checkTrancoRank(activeDomain).catch(e => ({ status: 'error', error: e.message })),
      this.checkWikipedia(effectiveCompanyName, activeDomain).catch(e => ({ status: 'error', error: e.message })),
      this.checkSECEdgar(effectiveCompanyName, activeDomain).catch(e => ({ status: 'error', error: e.message })),
      this.checkEmailAuth(activeDomain).catch(e => ({ status: 'error', error: e.message })),
      this.checkSafeBrowsing(activeDomain).catch(e => ({ status: 'error', error: e.message })),
      this.checkCertTransparency(activeDomain).catch(e => ({ status: 'error', error: e.message })),
      this.checkReverseIP(activeDomain).catch(e => ({ status: 'error', error: e.message }))
    ]);

    // If we followed a redirect, also verify the active domain's website content
    if (redirectedFrom && domainVerification) {
      domainVerification.redirectedTo = activeDomain;
      domainVerification.emailDomain = redirectedFrom;
      // Re-check website content on the active domain for scoring
      try {
        const activeCheck = await this.verifyDomain(activeDomain);
        domainVerification.activeDomainCheck = activeCheck;
        // Use the active domain's content check for scoring
        if (activeCheck.hasRealContent) {
          domainVerification.hasRealContent = true;
          domainVerification.pageTitle = activeCheck.pageTitle;
          domainVerification.metaDescription = activeCheck.metaDescription;
          domainVerification.wordCount = activeCheck.wordCount;
        }
      } catch (_) {}
    }

    // Phone validation is synchronous
    const phoneValidation = this.validatePhone(phone);

    // Use enriched company name for display if we didn't have one
    const resolvedCompanyName = effectiveCompanyName || companyEnrichment?.companyName || null;
    
    const scoreResult = this.calculateTrustScore(emailClassification, emailVerification, domainVerification, companyEnrichment, googlePlaces, phoneValidation, searchPresence, businessRegistration, trancoRank, wikipedia, secEdgar, emailAuth, safeBrowsing, certTransparency, reverseIP);
    const trustScore = scoreResult.score;
    const scoreBreakdown = scoreResult.breakdown;
    const decision = this.getDecision(trustScore);
    
    const result = {
      email,
      domain,
      activeDomain: redirectedFrom ? activeDomain : undefined,
      phone,
      companyName: resolvedCompanyName,
      extractedCompanyName: (!companyName && effectiveCompanyName) ? effectiveCompanyName : undefined,
      trustScore,
      scoreBreakdown,
      decision,
      verifiedAt: new Date().toISOString(),
      checks: {
        emailClassification,
        emailVerification,
        domainVerification,
        companyEnrichment,
        googlePlaces,
        phoneValidation,
        searchPresence,
        businessRegistration,
        trancoRank,
        wikipedia,
        secEdgar,
        emailAuth,
        safeBrowsing,
        certTransparency,
        reverseIP
      }
    };
    
    // Mark check types for UI grouping
    if (result.checks.trancoRank) result.checks.trancoRank.checkType = 'enterprise';
    if (result.checks.wikipedia) result.checks.wikipedia.checkType = 'enterprise';
    if (result.checks.secEdgar) result.checks.secEdgar.checkType = 'enterprise';
    if (result.checks.googlePlaces) result.checks.googlePlaces.checkType = 'core';
    if (result.checks.emailClassification) result.checks.emailClassification.checkType = 'core';
    if (result.checks.emailVerification) result.checks.emailVerification.checkType = 'core';
    if (result.checks.domainVerification) result.checks.domainVerification.checkType = 'core';
    if (result.checks.companyEnrichment) result.checks.companyEnrichment.checkType = 'core';
    if (result.checks.searchPresence) result.checks.searchPresence.checkType = 'core';
    if (result.checks.businessRegistration) result.checks.businessRegistration.checkType = 'core';
    if (result.checks.phoneValidation) result.checks.phoneValidation.checkType = 'core';
    if (result.checks.emailAuth) result.checks.emailAuth.checkType = 'core';
    if (result.checks.safeBrowsing) result.checks.safeBrowsing.checkType = 'core';
    if (result.checks.certTransparency) result.checks.certTransparency.checkType = 'core';
    if (result.checks.reverseIP) result.checks.reverseIP.checkType = 'core';
    
    this._saveResult(result);
    console.log(`[CustomerVerify] ${email} → Score: ${trustScore}, Decision: ${decision}${redirectedFrom ? ` (via ${activeDomain})` : ''}`);
    return result;
  }

  async checkTrancoRank(domain) {
    try {
      const resp = await fetch(`https://tranco-list.eu/api/ranks/domain/${domain}`, {
        signal: AbortSignal.timeout(5000)
      });
      const data = await resp.json();
      if (data.ranks && data.ranks.length > 0) {
        const rank = data.ranks[0].rank;
        return {
          status: 'found',
          rank,
          isTopSite: rank <= 100000,
          source: 'tranco'
        };
      }
      return { status: 'not_found', source: 'tranco' };
    } catch (e) {
      return { status: 'not_found', source: 'tranco' };
    }
  }

  async checkWikipedia(companyName, domain) {
    try {
      const name = companyName || domain.split('.')[0];
      const opts = { signal: AbortSignal.timeout(6000) };

      // Use Wikipedia search API to find the right article (handles disambiguation)
      const searchQueries = [
        `${name} company`,
        `${name} (company)`,
        name
      ];

      let articleTitle = null;
      for (const sq of searchQueries) {
        try {
          const searchResp = await fetch(`https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(sq)}&format=json&srlimit=3`, opts);
          if (searchResp.ok) {
            const searchData = await searchResp.json();
            const results = searchData?.query?.search || [];
            // Find a result that looks like a company article (not disambiguation)
            for (const r of results) {
              const snippet = (r.snippet || '').toLowerCase();
              const title = (r.title || '').toLowerCase();
              const nameLower = name.toLowerCase();
              if (title.includes('disambiguation')) continue;
              // Title base (before parenthetical) must match the company name closely
              const titleBase = title.split(' (')[0].trim();
              if (titleBase !== nameLower && !titleBase.startsWith(nameLower + ' ') && !nameLower.startsWith(titleBase)) continue;
              if (snippet.includes('company') || snippet.includes('corporation') || snippet.includes('founded') ||
                  snippet.includes('headquartered') || snippet.includes('inc.') || snippet.includes('platform') ||
                  snippet.includes('financial') || snippet.includes('technology') || snippet.includes('software')) {
                articleTitle = r.title;
                break;
              }
            }
            if (articleTitle) break;
          }
        } catch (_) {}
      }

      if (!articleTitle) {
        return { status: 'not_found', source: 'wikipedia' };
      }

      // Fetch the summary for the found article
      const resp = await fetch(`https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(articleTitle)}`, opts);
      if (resp && resp.status === 200) {
        const data = await resp.json();
        return {
          status: 'found',
          title: data.title,
          description: data.description,
          extract: (data.extract || '').substring(0, 200),
          url: data.content_urls?.desktop?.page,
          source: 'wikipedia'
        };
      }
      return { status: 'not_found', source: 'wikipedia' };
    } catch (e) {
      return { status: 'not_found', source: 'wikipedia' };
    }
  }

  async checkSECEdgar(companyName, domain) {
    try {
      if (!companyName) {
        companyName = domain.split('.')[0];
      }
      const url = `https://efts.sec.gov/LATEST/search-index?q="${encodeURIComponent(companyName)}"&forms=10-K&dateRange=custom&startdt=2020-01-01&enddt=2026-01-01`;
      const resp = await fetch(url, {
        headers: {
          'User-Agent': 'FelloVerify/1.0 (dano@fello.com)',
          'Accept': 'application/json'
        },
        signal: AbortSignal.timeout(8000)
      });
      const data = await resp.json();
      if (data.hits && data.hits.total && data.hits.total.value > 0) {
        return {
          status: 'found',
          isPublicCompany: true,
          entityName: data.hits.hits[0]._source.entity_name,
          filingCount: data.hits.total.value,
          source: 'sec_edgar'
        };
      }
      return { status: 'not_found', isPublicCompany: false, source: 'sec_edgar' };
    } catch (e) {
      return { status: 'error', source: 'sec_edgar' };
    }
  }

  // Resolve domain redirects — follows HTTP 301/302 to find the actual domain
  async _resolveRedirectDomain(domain) {
    return new Promise((resolve) => {
      const req = https.get(`https://${domain}`, {
        timeout: 6000,
        headers: { 'User-Agent': 'Mozilla/5.0' }
      }, (resp) => {
        resp.resume();
        if (resp.statusCode >= 300 && resp.statusCode < 400 && resp.headers.location) {
          try {
            const url = new URL(resp.headers.location.startsWith('http') ? resp.headers.location : `https://${domain}${resp.headers.location}`);
            const targetDomain = url.hostname.replace(/^www\./, '');
            resolve(targetDomain);
          } catch (_) { resolve(domain); }
        } else {
          resolve(domain);
        }
      });
      req.on('error', () => resolve(domain));
      req.setTimeout(6000, () => { req.destroy(); resolve(domain); });
    });
  }

  _saveResult(result) {
    this.results[result.email] = result;
    try {
      fs.writeFileSync(this.resultsFile, JSON.stringify(this.results, null, 2));
    } catch (e) {
      console.error('[CustomerVerify] Failed to save results:', e.message);
    }
  }

  getResults() {
    return Object.values(this.results).sort((a, b) => new Date(b.verifiedAt) - new Date(a.verifiedAt));
  }

  getResult(email) {
    return this.results[email.toLowerCase()] || null;
  }

  deleteResult(email) {
    const key = email.toLowerCase();
    if (this.results[key]) {
      delete this.results[key];
      try { fs.writeFileSync(this.resultsFile, JSON.stringify(this.results, null, 2)); } catch(e) {}
      return true;
    }
    return false;
  }
}

module.exports = { CustomerVerifyService };
