if (window.location.protocol == 'http:') {
    
    console.log("you are accessing us via "
        + "an insecure protocol (HTTP). "
        + "Redirecting you to HTTPS.");
        
    window.location.href =
        window.location.href.replace(
                'http:', 'https:');
}
else
    (window.location.protocol == "https:") {
        console.log("you are accessing us via"
            + " our secure HTTPS protocol.");
    }

    