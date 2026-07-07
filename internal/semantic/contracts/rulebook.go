// Copyright 2026 Minh Hoang Ton
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package contracts

// Invariant describes what the DCC checks for a given CWE.
// All fields are required; a zero value means the rulebook entry is incomplete.
type Invariant struct {
	CWE         string   // e.g. "CWE-89"
	Name        string
	SinkAnchors []string // CPG node type or method signatures that anchor this CWE's sink
	SafeNodes   []string // node types whose presence on the taint path marks it safe
	// Reference cites the primary source for this invariant definition.
	// Format: "SOURCE: <author/standard>, <year>, <title or section>"
	Reference string
}

// Rulebook is the static CWE→invariant table.
// Index by CWE string for O(1) lookup.
var Rulebook = map[string]Invariant{
	"CWE-89": {
		CWE:         "CWE-89",
		Name:        "SQL Injection",
		SinkAnchors: []string{"sql.query", "sql.exec", "sql.prepare", "executeQuery", "executeUpdate", "db.Query", "db.Exec", "rawQuery"},
		SafeNodes:   []string{"paramQuery", "prepareStmt", "boundParam", "parameterizedQuery"},
		Reference:   "OWASP Top 10 2021: A03 Injection; CWE-89 specification",
	},
	"CWE-78": {
		CWE:         "CWE-78",
		Name:        "OS Command Injection",
		SinkAnchors: []string{"os.exec", "exec.Command", "Runtime.exec", "subprocess.Popen", "ProcessBuilder.start", "exec", "system"},
		SafeNodes:   []string{"shellEscape", "commandAllowlist", "argSanitize"},
		Reference:   "OWASP Top 10 2021: A03 Injection; CWE-78 specification",
	},
	"CWE-22": {
		CWE:         "CWE-22",
		Name:        "Path Traversal",
		SinkAnchors: []string{"file.open", "os.OpenFile", "FileWriter", "fopen", "path.Join", "filepath.Join", "readFile", "writeFile"},
		SafeNodes:   []string{"pathClean", "canonicalizePath", "pathValidate", "baseNameOnly"},
		Reference:   "OWASP Top 10 2021: A01 Broken Access Control; CWE-22 specification",
	},
	"CWE-79": {
		CWE:         "CWE-79",
		Name:        "XSS",
		SinkAnchors: []string{"response.write", "response.Send", "innerHTML", "document.write", "echo", "print", "template.HTML", "Render"},
		SafeNodes:   []string{"htmlEscape", "outputEncode", "contextEncode", "autoEscape"},
		Reference:   "OWASP Top 10 2021: A03 Injection; CWE-79 specification",
	},
	"CWE-94": {
		CWE:         "CWE-94",
		Name:        "Code Injection",
		SinkAnchors: []string{"eval", "reflect", "execScript", "Function", "code.eval", "compile", "runtime.exec"},
		SafeNodes:   nil, // no safe path for code injection — always a violation when sink is reached
		Reference:   "OWASP Top 10 2021: A03 Injection; CWE-94 specification",
	},
	"CWE-918": {
		CWE:         "CWE-918",
		Name:        "SSRF",
		SinkAnchors: []string{"http.Get", "http.Post", "http.Request", "fetch", "net.curl", "url.open", "HTTPClient.send"},
		SafeNodes:   []string{"urlAllowlist", "domainCheck", "urlValidate", "hostnameVerify"},
		Reference:   "OWASP Top 10 2021: A10 Server-Side Request Forgery; CWE-918 specification",
	},
	"CWE-862": {
		CWE:         "CWE-862",
		Name:        "Missing Authorization",
		SinkAnchors: []string{"api.handler", "route.Handle", "endpoint", "http.HandlerFunc", "resourceAccess"},
		SafeNodes:   []string{"authCheck", "authMiddleware", "authorize", "requireAuth", "permissionCheck"},
		Reference:   "OWASP Top 10 2021: A01 Broken Access Control; CWE-862 specification",
	},
	"CWE-327": {
		CWE:         "CWE-327",
		Name:        "Broken Crypto",
		SinkAnchors: []string{"crypto.MD5", "crypto.SHA1", "crypto.DES", "crypto.RC4", "cipher.ECB", "MessageDigest.getInstance", "md5", "sha1", "des", "rc4"},
		SafeNodes:   []string{"crypto.SHA256", "crypto.SHA512", "cipher.AESGCM", "crypto.AES", "sha256", "sha512", "aesGcm"},
		Reference:   "OWASP Top 10 2021: A02 Cryptographic Failures; CWE-327 specification",
	},
	"CWE-502": {
		CWE:         "CWE-502",
		Name:        "Unsafe Deserialization",
		SinkAnchors: []string{"ObjectInputStream.readObject", "pickle.load", "yaml.load", "unmarshal", "deserialize", "json.Unmarshal", "readObject"},
		SafeNodes:   []string{"typeFilter", "objectFilter", "deserializeSecure", "validateDeserialize"},
		Reference:   "OWASP Top 10 2021: A08 Software and Data Integrity Failures; CWE-502 specification",
	},
}
