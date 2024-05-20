# roc-utils

Miscellaneous utility functions for the Roc language. I wrote these as an exercise to learn the language. They're not optimized in any way, but as far as I can tell they work correctly.

* `Hex` — convert between bytes and hex strings
* `Base64` — encode and decode base64 strings
* `Sha` — compute SHA 256 hashes
* `Hmac` — HMAC-SHA 256 message authentication

## How to use

Look for the latest release and copy the URL of the `.tar.br` file, then use it in your Roc application like this:

```roc
app [main] {
    utils: "<URL of .tar.br release asset>",
}

import utils.Base64

encoded = Str.toUtf8 |> Base64.encode
```
