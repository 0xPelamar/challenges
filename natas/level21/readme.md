- - -
# 🚩 OverTheWire: Natas Wargame Solutions - Level 21

**Vulnerability: Cross-Site Session Pollution (Colocation)**

**The Flaw**: There are two websites involved here: the main level and an "experimenter" site.

**Mass Assignment:** The `natas21-experimenter` site contains a loop that takes _every_ parameter from your request and dumps it directly into `$_SESSION` without filtering:
```PHP
foreach($_REQUEST as $key => $val) {
    $_SESSION[$key] = $val;
}
```
**Colocation:** The main page states it is "colocated" with the experimenter. This usually implies they are hosted on the same server and, critically, **share the same session storage path** (e.g., `/tmp`).
**The Exploit**: Because the sites share a session storage location, a valid Session ID (PHPSESSID) created on the experimenter site is also valid on the main site. If you dirty the session on the experimenter site with `admin=1`, the main site will read that same variable if you use the same cookie.
So first delete the `PHPSESSID` and add `admin=1` to body of submit request and the copy the returned `PHPSESSID` to main website and see the password.

password for next level: `d8rwGBl0Xslg3b76uh3fEbSlnOUBlozz`
