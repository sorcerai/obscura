## Runtime

### `OBSCURA_ALLOW_PRIVATE_NETWORK`

Allow fetches to loopback (`127.0.0.0/8`), RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and link-local (`169.254.0.0/16`, including the `169.254.169.254` cloud-metadata endpoint) addresses. The deny-set also covers the unspecified address (`0.0.0.0` / `::`), IPv6 unique-local (`fc00::/7`), and any IPv4-mapped form of the above. Off by default to block SSRF.

The guard validates at DNS-resolution time as well as on literal hosts, so a public hostname that resolves to a forbidden address is rejected at connect time (DNS-rebinding safe), not just hosts written as raw IPs.

Truthy values: `1`, `true`, `yes`, `on`.

```bash
OBSCURA_ALLOW_PRIVATE_NETWORK=1 obscura fetch http://localhost:8080
```

Per-process equivalent: `--allow-private-network` on any subcommand.

### `OBSCURA_NAV_TIMEOUT_MS`

Hard ceiling on a single navigation. Default 30000 (30 seconds). Applies to `Page.navigate` and the CLI `fetch` command.

```bash
OBSCURA_NAV_TIMEOUT_MS=60000 obscura serve
```

### `OBSCURA_NAV_CHAIN_LIMIT`

How many documents a navigation chain may load, the first navigation included. Default 10, which allows the requested document and nine navigations the page itself triggers via `location` assignments or form submissions. Raise the value for an endpoint that chains longer for good reasons, such as an SSO handover across several providers. The low default is what stops a page that resets `location` on every load.

A zero is raised to 1. This loads the requested document. If the page wants to chain further afterwards, the call reports an error, as at any other limit. A value the engine does not read as a number is replaced by the default. This also applies to a negative value and to a value with a trailing space.

The time budget is not tied to this limit. A longer chain usually also needs a higher `OBSCURA_NAV_TIMEOUT_MS`, because its default of 30 seconds applies to the whole chain and not to the individual document.

```bash
OBSCURA_NAV_CHAIN_LIMIT=20 obscura serve
```

### `OBSCURA_SCRIPT_DEADLINE_MS`

Soft deadline for the complete page script-execution phase, including classic scripts and ES modules. Default 30000 (30 seconds). Raise it for a heavy SPA whose initial module is responsible for mounting an otherwise empty document. The engine also uses this value as a hard V8 watchdog budget, with a one-second grace period, so a synchronous script cannot run forever.

```bash
OBSCURA_SCRIPT_DEADLINE_MS=60000 obscura serve
```

### `OBSCURA_MODULE_BUDGET_MS`

Per-module graph-loading and evaluation budget for modules that enhance an already-rendered page. Default 3000 (3 seconds). Raise it when a module such as the Vite HMR client legitimately needs longer to evaluate:

```bash
OBSCURA_MODULE_BUDGET_MS=10000 obscura serve
```

This shorter budget applies when the document body already contains more than 50 descendant nodes, where modules are normally progressive enhancement and should not delay navigation indefinitely. For an unmounted SPA shell, Obscura instead gives each module the full `OBSCURA_SCRIPT_DEADLINE_MS` budget so the app has time to mount. Module network requests remain independently bounded by `OBSCURA_FETCH_TIMEOUT_MS`.

### `OBSCURA_CDP_COMMAND_TIMEOUT_MS`

Per-command deadline for the CDP server. A hung page (a runaway `Runtime.evaluate`, a synchronous DOM op) is terminated after this budget so one bad session cannot hold the shared V8 lock and stall the others. Default 60000 (60 seconds); `0` disables it. Navigation self-bounds via `OBSCURA_NAV_TIMEOUT_MS` well under this.

```bash
OBSCURA_CDP_COMMAND_TIMEOUT_MS=30000 obscura serve
```

### `OBSCURA_CDP_TOKEN`

Bearer token for the CDP discovery and WebSocket endpoints. It is optional on
loopback. A non-loopback bind is refused unless this is set to at least 32
bytes. Pass it as `Authorization: Bearer <token>` in the CDP client's headers.

```bash
OBSCURA_CDP_TOKEN="$(openssl rand -hex 32)" obscura serve --host 0.0.0.0
```

### `OBSCURA_FETCH_TIMEOUT_MS`

Request timeout for scripted `fetch()`, `XMLHttpRequest`, and ES-module loads. Without it a request to a server that accepts the connection but never responds (including a CORS preflight) hangs forever and the XHR is stuck with no completion event. Default 30000 (30 seconds).

```bash
OBSCURA_FETCH_TIMEOUT_MS=15000 obscura serve
```

### `OBSCURA_PROXY`

Default proxy URL used by `obscura-worker` for the parallel `scrape` command when no `--proxy` flag is set.

```bash
OBSCURA_PROXY=http://proxy.example.com:8080 obscura scrape - < urls.txt
```

## Stealth and identity

These tune the browser identity the engine presents so it stays internally consistent. See [Configure stealth and proxies](Configure-stealth-and-proxies.md) for the full picture.

### `OBSCURA_BLOCK_TRACKERS`

Controls the tracker blocklist used by the stealth HTTP transport. It is on by
default so `--stealth` retains its current privacy-first behavior. Set it to
`0`, `false`, `no`, or `off` to keep the stealth TLS/browser fingerprint while
allowing tracker requests.

The setting is read when a stealth client is created. Values are case-insensitive
and surrounding whitespace is ignored; unset, empty, and unrecognized values keep
blocking enabled. Non-stealth transport settings and SSRF protection are unchanged.

```bash
OBSCURA_BLOCK_TRACKERS=0 obscura --stealth fetch https://example.com
```

### `OBSCURA_TIMEZONE`

Pins the process timezone before V8/ICU reads it, so `Date` (`getTimezoneOffset`, `toString`) and `Intl.DateTimeFormat` report one consistent zone. Default `Europe/Berlin`. Set it to match the exit IP's region.

```bash
OBSCURA_TIMEZONE=America/New_York obscura serve
```

### `OBSCURA_GEOLOCATION`

Override the coordinates the `navigator.geolocation` shim reports, as `lat,lon`. Without it the shim reports a fixed default. Keep it consistent with `OBSCURA_TIMEZONE` and the proxy region.

```bash
OBSCURA_GEOLOCATION="40.7128,-74.0060" obscura serve
```

### `OBSCURA_PROFILE`

Pin a specific browser profile from the built-in pool by index (`0`-based). Each profile keeps `navigator.platform`, `userAgentData`, the UA string, and the GPU renderer internally consistent. Without it a single stable profile is used.

```bash
OBSCURA_PROFILE=2 obscura serve
```

### `OBSCURA_PROFILE_FILE`

Path to a JSON file describing one device. It replaces the fixed Windows Chrome 145 identity of `--stealth`. A profile needs `--stealth` in a build with the `stealth` feature, because only that transport emulates Chrome's TLS; without it the process exits.

The file names the operating system and the Chrome major. The UA string, `navigator.platform`, `userAgentData`, `Sec-CH-UA`, `Sec-CH-UA-Platform` and the TLS/HTTP2 emulation are derived from those two. The other fields are checked when the process starts, and any problem stops it before it serves a request.

The checks:
- `chrome` must be one the transport can emulate (143-148).
- `full_version` must be a `<chrome>.0.x.y` version.
- `architecture` is `x86` or `arm`, and `arm` is refused with `linux`, whose user agent says x86_64.
- `platform_version` must fit the OS.
- `device_memory` must be a value Chrome reports.
- `timezone` must be `UTC` or look like an IANA zone name. Whether the zone exists is not checked.
- `locale` must be a tag such as `en-US`, `es-419` or `sr-Latn`.

What then stays fixed:
- The screen, `hardwareConcurrency`, `deviceMemory` and the noise seed stay the same on every page and in its iframes, instead of being re-drawn per document.
- `timezone` sets `TZ`.
- `locale` sets `navigator.languages`, the `Intl` default locale and the `Accept-Language` header.
- `full_version` and `architecture` appear in `getHighEntropyValues`.

Anything that would split the identity is refused:
- An `OBSCURA_TIMEZONE` or a `--user-agent` that disagrees stops the process.
- A different `Network.setUserAgentOverride`, `Emulation.setUserAgentOverride`, `Emulation.setLocaleOverride` or `acceptLanguage` returns a CDP error.
- A `User-Agent` or `Sec-CH-UA*` header from `Network.setExtraHTTPHeaders` or request interception is dropped.

`/json/version` and `Browser.getVersion` report the profile's user agent, so a client that copies it passes the check.

```json
{
  "os": "macos", "chrome": 146, "full_version": "146.0.7680.164",
  "architecture": "arm", "platform_version": "15.6.1",
  "screen": [1512, 982], "hardware_concurrency": 10, "device_memory": 8,
  "timezone": "America/Chicago", "locale": "en-US", "seed": 424242
}
```

```bash
OBSCURA_PROFILE_FILE=~/.config/obscura/device.json obscura serve --stealth
```

`tools/profile-capture/index.html` writes this file from a real Chrome.

### `OBSCURA_ROTATE_PROFILE`

Opt into picking a random profile per browser context instead of the stable default. Leave it off when you pin a TLS fingerprint, proxy region, or timezone, since a rotated profile would no longer match those.

```bash
OBSCURA_ROTATE_PROFILE=1 obscura serve
```

## MCP

### `OBSCURA_MCP_ALLOWED_ORIGINS`

Comma-separated `Origin` allowlist for the HTTP MCP transport (`obscura mcp --http`). Browser requests are refused by default; when set, only listed origins are accepted. Native, non-browser MCP clients (which send no `Origin`) are always allowed.

```bash
OBSCURA_MCP_ALLOWED_ORIGINS="https://app.example.com" obscura mcp --http --host 0.0.0.0
```

### `OBSCURA_MCP_TOKEN`

Bearer token for MCP HTTP requests. It is optional on loopback. A non-loopback
bind is refused unless this is set to at least 32 bytes.

```bash
OBSCURA_MCP_TOKEN="$(openssl rand -hex 32)" obscura mcp --http --host 0.0.0.0
```

## Logging

### `RUST_LOG`

Standard `tracing` filter. Common settings:

```bash
RUST_LOG=obscura=info obscura serve
RUST_LOG=obscura=debug obscura serve
RUST_LOG=obscura_cdp=trace,obscura_browser=debug obscura serve
```

`--verbose` on the CLI is equivalent to `RUST_LOG=obscura=info`.

## Build

### `OPENSSL_NO_VENDOR`

Forces `cargo build` to use the system OpenSSL instead of compiling the vendored copy. Set to `1` on hosts where the vendored OpenSSL fails (older VPS with AVX-512 issues).

```bash
OPENSSL_NO_VENDOR=1 cargo build --release --features render
```

## V8

V8 flags are passed via `--v8-flags`, not environment variables:

```bash
obscura --v8-flags "--max-old-space-size=2048 --expose-gc" serve
```

Defaults are `--max-old-space-size=4096 --max-semi-space-size=4 --optimize-for-size` on 64-bit systems. In the current V8, `--optimize-for-size` overrides the requested semi-space cap to **1 MiB**, not 4 MiB. The old-generation ceiling remains 4 GB.

User flags are appended after the defaults, but V8 applies flag implications afterwards. To change the young-generation cap, also disable size optimization, for example `obscura --v8-flags "--no-optimize-for-size --max-semi-space-size=8" serve`. This can reduce GC CPU at the cost of more memory; measure the complete workload before adopting it. Use `--v8-flags "--print-flag-values"` to inspect the effective settings after V8 initialization.

## HTTP proxy environment

Obscura does not honor `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`. Use `--proxy` or `OBSCURA_PROXY`.
