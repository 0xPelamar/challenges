- - -
# 🚩 OverTheWire: Natas Wargame Solutions - Level 20

**Vulnerability: Session Poisoning (CRLF Injection)**
This level uses a custom session handler (`mywrite` and `myread`) that stores session data in a text file using a simple `key value` format, separated by newlines (`\n`).
The code grants access if `$_SESSION["admin"] == 1`. To achieve this, you need to inject a newline followed by `admin 1`.

So enter `pelamar%0aadmin%201` in name field and refresh the page

password for next level = `BPhv63cKE1lkQl04cE5CuFTzXe15NfiH`