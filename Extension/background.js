// Replace with your real Google Safe Browsing API key from GCP Console
const SAFE_BROWSING_KEY = 'AIzaSyBZ6hvJoezlEfpUo45iSC-yXsYTBdlCCB0';

const scanCache = new Map();

/**
 * 1. Automatic Navigation Trigger
 */
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (!isValidUrl(details.url)) return;
  await evaluateUrl(details.tabId, details.url);
});

/**
 * 2. SPA Tab Update Listener
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab && tab.url && isValidUrl(tab.url)) {
    evaluateUrl(tabId, tab.url);
  }
});

/**
 * 3. Manual Scan Request Listener
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'CHECK_URL') {
    handleManualScan(request.url)
      .then((res) => sendResponse(res))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // Keep channel open
  }
});

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

async function checkSafeBrowsingApi(targetUrl) {
  if (!SAFE_BROWSING_KEY || SAFE_BROWSING_KEY.includes('YOUR_KEY')) {
    console.warn('BaitSec: Missing API Key');
    return { isThreat: false, reason: 'Missing API Key' };
  }

  // Safe Browsing API test URLs require http:// scheme
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
      console.error(`Safe Browsing API Error: HTTP ${res.status}`);
      return { isThreat: false, reason: `API Error ${res.status}` };
    }

    const data = await res.json();
    const isFlagged = data.matches && data.matches.length > 0;
    
    return {
      isThreat: isFlagged,
      reason: isFlagged ? `Flagged as ${data.matches[0].threatType}` : null,
      threatType: isFlagged ? data.matches[0].threatType : null
    };
  } catch (err) {
    console.error('Network error checking Safe Browsing API:', err);
    return { isThreat: false, reason: 'Network Failure' };
  }
}

async function handleManualScan(url) {
  if (!isValidUrl(url)) {
    return { success: false, error: 'Cannot scan restricted browser pages.' };
  }

  const heuristic = checkHeuristics(url);
  const apiResult = await checkSafeBrowsingApi(url);

  const isMalicious = heuristic.flagged || apiResult.isThreat;

  return {
    success: true,
    url: url,
    isMalicious: isMalicious,
    heuristicWarning: heuristic.flagged ? heuristic.reason : null,
    threats: apiResult.isThreat ? [{ threatType: apiResult.threatType || apiResult.reason }] : []
  };
}

function triggerThreatAlert(tabId, url, reason) {
  try {
    const hostname = new URL(url).hostname;

    if (tabId) {
      chrome.action.setBadgeText({ tabId, text: '!' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#D9534F' });
    }

    chrome.notifications.create(`baitsec-${Date.now()}`, {
      type: 'basic',
      iconUrl: 'images/logo128.png',
      title: '⚠️ BaitSec Alert',
      message: `${hostname}\nReason: ${reason}`,
      priority: 2
    });
  } catch (err) {
    console.error('Alert error:', err);
  }
}

function clearThreatAlert(tabId) {
  if (tabId) {
    chrome.action.setBadgeText({ tabId, text: '' });
  }
}

function isValidUrl(url) {
  return url && (url.startsWith('http://') || url.startsWith('https://'));
}