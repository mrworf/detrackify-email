# Guard server and link rewriting

Many phishing attempts disguise a malicious link behind seemingly innocent text. `detrackify_email.py` can rewrite such links so that the user is warned before the browser follows them. The guard server verifies the link using a shared secret, serves a warning page and then redirects without storing any state on the server. Logging of the clicked link can be disabled for privacy.
## Enabling guarded links

Set the following options either on the command line or in your `detrackify_email.py` configuration file:

```yaml
guard:
  server: https://guard.example.com
  salt: changeme123
  link: mismatch
  capture_to: false
```

`guard.server` is the public URL to the guard server including the scheme. `guard.salt` must be at least eight characters and should be kept secret. `guard.link` controls which links are rewritten: `mismatch` only rewrites links that do not match the sender domain, `always` rewrites all links and `off` disables the feature.

When a link is rewritten, a JSON payload containing the original URL, its display text and the sender domain is base64 encoded.  A SHA1 hash is then calculated from that encoded payload plus the configured salt and both values are appended to the guard server address.  This allows the server to verify that the payload has not been tampered with when a user clicks the link.  The processed email will also include the headers `X-Detrackify-Guarded-Links` and `X-Detrackify-Guard-Mode` when guardlink is active.
If `guard.capture_to` is enabled, the recipient address is included in the JSON so the server can log which user clicked the link&mdash;or at least which recipient the link was originally meant for (forwards and quoted mail may not reflect the actual clicker).

## Running the guard server

Start the server with at least the salt option:

```bash
python3 detrackify_guard.py --guardsalt changeme123
```

Optional parameters:

* `--listen-ip` IP to bind to (default `0.0.0.0`)
* `--listen-port` Port to listen on (default `9090`)
* `--template-dir` Directory containing templates (default `templates`)
* `--resource-dir` Directory containing additional resources (images only)
* `--timeout` Seconds to wait before the continue button activates (default `5`)
* `--privacy` Disable logging of visited links

### Privacy

Nothing is stored on the server. Normally each redirect is logged along with how long the user waited before continuing. When `--privacy` is enabled these informational messages are suppressed, but warnings and errors are still logged.


The server verifies the provided hash, shows a warning page and then redirects the
user without sending a referrer header. It automatically chooses a warning page
template based on the browser's `Accept-Language` header. Templates for German,
Spanish, French, Chinese and Arabic are included; if no matching template exists
the English version is used. These translations were generated automatically so
minor errors may exist.

## Using a reverse proxy

The guard server can run behind a reverse proxy such as nginx or Apache. Configure the proxy to pass requests for `/guard/` and `/resource/` to the internal server. Example nginx snippet:

```nginx
location /guard/ {
    proxy_pass http://127.0.0.1:9090/guard/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
location /resource/ {
    proxy_pass http://127.0.0.1:9090/resource/;
}
```

When using a proxy, set `guard.server` to the external URL clients will access (e.g. `https://example.com`). No code changes are required.
