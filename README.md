# emailguard

Fast, practical heuristics for validating business email domains during signup.

`emailguard` filters out disposable, masked, or misconfigured email domains using lightweight DNS inspection and a curated blocklist of known temporary email providers.  
It’s designed for B2B SaaS signup flows where you want **real business emails**, not throwaway addresses.

---

## ⚡ Features

- ✅ Checks MX records (fast, 1s timeout)
- ✅ Blocks disposable & temp-mail domains (auto-syncs from GitHub)
- ✅ Detects masking/aliasing services via MX heuristics
- ✅ Caches verdicts and DNS results in memory
- ✅ Safe defaults for consumer providers (Gmail, Outlook, etc.)
- ✅ Zero external services — pure Go + DNS

---

## 🚀 Installation

```bash
go get github.com/yourname/emailguard
````

---

## 🧠 Example

```go
package main

import (
    "fmt"
    "github.com/yourname/emailguard"
)

func main() {
    ok := emailguard.IsLegitEmail("user@company.com")
    if !ok {
        fmt.Println("Reject: unverified or disposable domain")
    } else {
        fmt.Println("Looks good ✅")
    }
}
```

Output:

```
Looks good ✅
```

or, for a disposable domain:

```
Reject: unverified or disposable domain
```

---

## 🧩 How it works

1. Clones [disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains) into `/tmp` (once per process).
2. Checks:

   * Is domain in blocklist?
   * Has valid MX?
   * Does MX contain masking keywords? (`mask`, `relay`, `forward`, `tempmail`, etc.)
   * Are MX registrable domains disposable?
3. Caches DNS + verdicts for 5 minutes.
4. Returns a simple boolean — **fast, deterministic, low overhead**.

---

## ⚙️ Config / Policy

Modify `allowlist`, `mxBadKeywords`, or cache TTLs inside the package if needed.

---

## 📦 Use cases

* Block signups using temp or masked emails
* Improve lead quality in B2B products
* Sanitize marketing imports
* Gate API access behind legit company addresses

---

## 🧑‍💻 License

MIT — free for commercial use.
Attribution appreciated but not required.
