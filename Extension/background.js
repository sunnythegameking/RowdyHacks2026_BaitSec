// background.js

// ⚠️ REQUIRED: Get a valid Google Cloud API key starting with 'AIzaSy...' from:
// https://console.cloud.google.com/apis/credentials
const SAFE_BROWSING_KEY = 'AIzaSyBZ6hvJoezlEfpUo45iSC-yXsYTBdlCCB0';

// In-memory cache to prevent spamming API requests on repeated visits
const scanCache = new Map();

/**
 * 1. Listen for page navigation events (Automatic trigger)
 */
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;

  const url = details.url;
  if (!isValidUrl(url)) return;

  await evaluateUrl(details.tabId, url);
});

/**
 * 2. Listen for tab updates (Catches SPA transitions)
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && isValidUrl(tab.url)) {
    evaluateUrl(tabId, tab.url);
  }
});

/**
 * 3. Listen for manual scan requests from popup.js
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'CHECK_URL') {
    (async () => {
      try {
        const result = await handleManualScan(request.url);
        sendResponse(result);
      } catch (err) {
        sendResponse({ success: false, error: err.message || 'Scan failed' });
      }
    })();

    return true; // Keeps async response channel open
  }
});

/**
 * Core evaluation pipeline
 */
async function evaluateUrl(tabId, url) {
  if (scanCache.has(url)) {
    const cached = scanCache.get(url);
    if (cached.isThreat) triggerThreatAlert(tabId, url, cached.reason);
    return;
  }

  const heuristic = checkHeuristics(url);
  if (heuristic.flagged) {
    scanCache.set(url, { isThreat: true, reason: heuristic.reason });
    triggerThreatAlert(tabId, url, heuristic.reason);
    return;
  }

  const apiResult = await checkSafeBrowsingApi(url);
  scanCache.set(url, { isThreat: apiResult.isThreat, reason: apiResult.reason });

  if (apiResult.isThreat) {
    triggerThreatAlert(tabId, url, apiResult.reason);
  } else {
    clearThreatAlert(tabId);
  }
}

/**
 * Brand Impersonation & Typosquatting Heuristics
 */
function checkHeuristics(urlStr) {
  try {
    const hostname = new URL(urlStr).hostname.toLowerCase();

    const targetBrands = [
      { name: 'Google', official: 'google.com', patterns: [/g00gle/i, /gooogle/i, /google-login/i, /google-security/i] },
      { name: 'PayPal', official: 'paypal.com', patterns: [/paypaI/i, /pay-pal/i, /paypal-update/i, /paypal-verify/i] },
      { name: 'Apple', official: 'apple.com', patterns: [/appIe/i, /appleid-verify/i, /apple-support-login/i] },
      { name: 'Microsoft', official: 'microsoft.com', patterns: [/mıcrosoft/i, /micros0ft/i, /ms-login/i] },
      { name: 'Amazon', official: 'amazon.com', patterns: [/amaz0n/i, /amazon-verify/i] }
    ];

    for (const brand of targetBrands) {
      if (!hostname.endsWith(brand.official)) {
        for (const pattern of brand.patterns) {
          if (pattern.test(hostname)) {
            return {
              flagged: true,
              reason: `Domain '${hostname}' matches known spoofing pattern for ${brand.name}.`
            };
          }
        }
      }
    }
  } catch (err) {
    console.error('Heuristic parsing error:', err);
  }

  return { flagged: false };
}

/**
 * Safe Browsing API v4 lookup
 */
async function checkSafeBrowsingApi(targetUrl) {
  if (!SAFE_BROWSING_KEY || SAFE_BROWSING_KEY.startsWith('AQ.') || SAFE_BROWSING_KEY === 'YOUR_GOOGLE_CLOUD_API_KEY_HERE') {
    return { isThreat: false, reason: 'Invalid or Missing Google Cloud API Key' };
  }

  // Normalize test suite endpoints to http:// scheme
  let urlToTest = targetUrl;
  if (urlToTest.includes('testsafebrowsing.appspot.com')) {
    urlToTest = urlToTest.replace('https://', 'http://');
  }

  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_KEY}`;
  
  const payload = {
    client: { clientId: "baitsec-extension", clientVersion: "1.0.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url: urlToTest }]
    }
  };

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      console.error(`Safe Browsing API Error: Status ${res.status}`);
      return { isThreat: false, reason: `API Error (Status ${res.status})` };
    }

    const data = await res.json();
    const isFlagged = data.matches && data.matches.length > 0;
    
    return {
      isThreat: isFlagged,
      reason: isFlagged ? `Flagged as ${data.matches[0].threatType} threat.` : null
    };
  } catch (err) {
    console.error('Network Error querying Safe Browsing API:', err);
    return { isThreat: false, reason: 'Network Failure' };
  }
}

/**
 * Manual scan handler called by popup.js
 */
async function handleManualScan(url) {
  if (!isValidUrl(url)) {
    return { success: false, error: 'Cannot scan internal or restricted browser pages.' };
  }

  const heuristic = checkHeuristics(url);
  const apiResult = await checkSafeBrowsingApi(url);

  const isMalicious = heuristic.flagged || apiResult.isThreat;
  const reason = heuristic.reason || apiResult.reason;

  return {
    success: true,
    url: url,
    isMalicious: isMalicious,
    reason: reason
  };
}

/**
 * UI Alerts & Badge Updates
 */
function triggerThreatAlert(tabId, url, reason) {
  const hostname = new URL(url).hostname;

  chrome.action.setBadgeText({ tabId, text: '!' });
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#D9534F' });

  chrome.notifications.create(`baitsec-alert-${Date.now()}`, {
    type: 'basic',
    iconUrl: 'images/logo128.png',
    title: '⚠️ BaitSec Security Alert',
    message: `Suspicious domain detected: ${hostname}\nReason: ${reason}`,
    priority: 2
  });
}

function clearThreatAlert(tabId) {
  chrome.action.setBadgeText({ tabId, text: '' });
}

function isValidUrl(url) {
  return url && (url.startsWith('http://') || url.startsWith('https://'));
}