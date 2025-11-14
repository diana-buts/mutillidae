/***********************************************
 * Bookmark site script- © Dynamic Drive DHTML code library (www.dynamicdrive.com)
 * This notice MUST stay intact for legal use
 * Visit Dynamic Drive at http://www.dynamicdrive.com/ for full source code
 ***********************************************/

/* Modified heavily by Jeremy Druin */
/* XSS-safe version */
function bookmarkSite(){

    try{
        var rawURL = document.location.href;

        // sanitize the URL (prevents javascript:, data:, vbscript:, etc.)
        function sanitizeURL(url) {
            try {
                var u = new URL(url);

                // allow only http(s)
                if (u.protocol !== "http:" && u.protocol !== "https:") {
                    return location.origin; // fallback safe value
                }

                // disallow userinfo
                if (u.username || u.password) {
                    return location.origin;
                }

                // return safe normalized URL
                return u.href;
            } catch (e) {
                return location.origin; // fallback safe URL
            }
        }

        var lURL = sanitizeURL(rawURL);
        var lTitle = "Mutillidae";

        if (window.sidebar){
            // Firefox
            window.sidebar.addPanel(lTitle, lURL, "");
        } else if (window.opera && window.print){
            // Opera
            var elem = document.createElement('a');
            elem.setAttribute('href', lURL);   // SAFE
            elem.setAttribute('title', lTitle);
            elem.setAttribute('rel', 'sidebar');
            elem.click();
        } else if (document.all){
            // IE
            window.external.AddFavorite(lURL, lTitle);
        }
    }catch(e){
        // NEVER reflect raw URL back to the page → prevents DOM XSS
        alert('Could not add bookmark for ' + lTitle + '.\nError: ' + e.message);
    }

} // end function bookmarkSite
