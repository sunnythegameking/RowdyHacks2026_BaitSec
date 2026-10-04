document.getElementById('scanBtn').addEventListener('click', () => {
  alert('BaitSec is analyzing this page for social engineering triggers. We are looking at the HTML page and the webpage overall for anything malicous...');
  
  // Example: You can send a message to background.js here to trigger a scan
  chrome.runtime.sendMessage({ action: "scan_page" });
});
