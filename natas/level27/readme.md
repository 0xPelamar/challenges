# 🚩 OverTheWire: Natas Wargame Solutions - Level 27
---
This level is vulnerable to a specific type of SQL injection known as **SQL Column Truncation**. It occurs when the application allows you to input more data than the database column can hold, combined with a `substr()` function in PHP that attempts to sanitize input but actually aids the exploit.
The vulnerable logic lies in the `createUser` function.
We want to retrieve the password for the user `natas28`. We cannot simply look it up because the `dumpData` function requires us to log in as that user, and `validUser` prevents us from creating a user named "natas28" because it already exists.

**The Attack Plan:** Create a "Shadow User" named `natas28` (with a password we know) by tricking the database into thinking we are creating a different user, but having it truncated to `natas28` upon insertion.

**The Exploit: Null Byte Injection**
While spaces can sometimes work, they are risky because of the `trim()` check and browser behavior. A more robust method is using **Null Bytes (`%00`)**.
**The Payload:** `natas28 + [Many Null Bytes]`
```
username=natas28%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00&password=password
```

Password for next level: `1JNwQM1Oi6J6j1k49Xyw7ZN6pXMQInVj`