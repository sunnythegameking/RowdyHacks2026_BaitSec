// if website comes back good, use this search (implement actual if statement later or in another file)
var theText;
$('p,h1,h2,h3,h4,h5').each(function() {
  theText += $(this).text();
});

const pattern = "jajjsjaja/g";  // PLACE HOLDER !!!! !!!! THIS IS A PLACE HOLDER CHANGE IT PELASE. CHANGE ITTTTT

const matches = theText.match(pattern);
console.log(matches); 
