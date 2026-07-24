## CWE-89
AI models frequently miss second-order SQL injection where user input is stored then later concatenated into a query. Check for indirect taint paths through persistence layers.

## CWE-79
AI models miss stored XSS where input is persisted and rendered in a different request context. Check for cross-request taint.

## CWE-22
AI models miss path traversal when normalization appears to happen but uses a non-canonical form (e.g. URL decode after path check). Verify canonicalization order.

The OPPOSITE mistake is just as real: flagging a sink as vulnerable because no EXPLICIT sanitizer call is visible, when the sink function itself is safe by construction regardless of upstream validation. In Go specifically, `http.Dir(dir).Open(path)` (and anything that routes through it, e.g. a custom `http.FileSystem` wrapper) prefixes the requested path with "/" before calling `path.Clean` — this anchors any ".." sequence at the root and makes it structurally impossible to escape the base directory, no matter how naive or absent any upstream sanitizer is. Found live: multiple real findings flagged `guessSourceMapLocation`/`staticHandler`-style functions as exploitable path traversal purely because "no canonicalizePath call is visible in the caller chain," when the actual sink was `http.Dir.Open` and therefore safe regardless. Before concluding exploitable for a Go CWE-22 surface, check what function actually performs the file read — a raw `os.Open`/`ioutil.ReadFile`/`fs.Exists` on an unsanitized joined path is genuinely at risk; a read routed through `http.Dir.Open` is not, and no amount of "no explicit guard found" upstream changes that.

## CWE-918
AI models miss SSRF when the URL is constructed from multiple user-controlled fragments. Check for partial taint (host vs path vs query).

## CWE-862
AI models miss broken auth when authorization check is present but applied to the wrong principal or resource type. Authorization is frequently enforced upstream (a controller-level annotation, a filter chain, a middleware) rather than inline in this function — if no auth call is visible here, check whether the caller (use the get_callers tool) already gates access before reaching this surface, rather than assuming its absence here means it's missing everywhere.

## CWE-327
AI models miss weak crypto when a strong algorithm is configured by default but overridden by a user-supplied parameter.

## CWE-502
AI models miss unsafe deserialization when the deserializer appears safe (e.g. Jackson) but is configured with a polymorphic type resolver.

## CWE-94
AI models miss code injection through template engines or scripting APIs that appear to be data-only interfaces.

## CWE-78
AI models miss OS command injection through indirect execution (e.g. ProcessBuilder with array args where one element is user-controlled).
