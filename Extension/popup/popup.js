document.getElementById('scanBtn').addEventListener('click', () => {
  alert('BaitSec is analyzing this page for social engineering triggers...');
  
  // Example: You can send a message to background.js here to trigger a scan
  chrome.runtime.sendMessage({ action: "scan_page" });
});
