document.addEventListener('DOMContentLoaded', async () => {
  const urlDisplay = document.getElementById('current-url');
  const scanBtn = document.getElementById('scan-btn');
  const learnBtn = document.getElementById('learn-btn');
  const resultContainer = document.getElementById('result-container');

  // Handle "Learn How Not To Be Scammed" Button Click
  if (learnBtn) {
    learnBtn.addEventListener('click', () => {
      chrome.tabs.create({ url: 'https://baitsec.vercel.app/BaitSec.html' });
    });
  }

  // Get active tab URL
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  if (tab && tab.url) {
    urlDisplay.textContent = tab.url;
  } else {
    urlDisplay.textContent = 'Unable to fetch active tab URL.';
    scanBtn.disabled = true;
    return;
  }

  // Handle "Scan This Page" Button Click
  scanBtn.addEventListener('click', () => {
    resultContainer.innerHTML = 'Scanning...';

    chrome.runtime.sendMessage(
      { action: 'CHECK_URL', url: tab.url },
      (response) => {
        if (!response || !response.success) {
          resultContainer.innerHTML = `<div class="status danger">Error: ${response?.error || 'Scan failed'}</div>`;
          return;
        }

        if (response.isMalicious) {
          let html = `<div class="status danger">⚠️ Warning: Site Flagged!</div>`;
          if (response.heuristicWarning) {
            html += `<div class="warning"><strong>Spoof Warning:</strong> ${response.heuristicWarning}</div>`;
          }
          if (response.threats && response.threats.length > 0) {
            html += `<div class="warning"><strong>Known Threat:</strong> ${response.threats[0].threatType}</div>`;
          }
          resultContainer.innerHTML = html;
        } else {
          resultContainer.innerHTML = `<div class="status safe">✓ No known threats detected.</div>`;
        }
      }
    );
  });
});