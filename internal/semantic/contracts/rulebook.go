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

import "log/slog"

// Invariant describes what the DCC checks for a given CWE.
// All fields are required unless NoSinkModel is set; a zero value on a
// required field means the rulebook entry is incomplete.
type Invariant struct {
	CWE         string   // e.g. "CWE-89"
	Name        string
	SinkAnchors []string // CPG node type or method signatures that anchor this CWE's sink
	SafeNodes   []string // node types whose presence on the taint path marks it safe
	// NoSinkModel is true for CWE classes that have no fixed dangerous-API
	// signature to anchor on — the "sink" is whatever sensitive operation the
	// surface happens to perform, which Targeting's structural classification
	// (idor_candidate/auth_boundary, via real call-graph reachability) already
	// captures. CWE-862 is the canonical case: MITRE and the access-control
	// detection literature agree missing-authorization bugs need business
	// context static analysis can't derive from a keyword/method-name list —
	// see docs/architecture.md for the false-positive case that motivated this.
	// When true, Check skips SinkAnchors/SafeNodes matching entirely and
	// returns VerdictInconclusive so B4/B5 (real code + LLM reasoning) decide,
	// instead of a keyword match rubber-stamping a verdict it can't justify.
	NoSinkModel bool
	// Reference cites the primary source for this invariant definition.
	// Format: "SOURCE: <author/standard>, <year>, <title or section>"
	Reference string
}

// Rulebook is the static CWE→invariant table.
// Index by CWE string for O(1) lookup.
//
// Anchor discipline (learned from the CWE-862 incident — see NoSinkModel
// doc): every SinkAnchors/SafeNodes entry below is a qualified, specific
// API name (a package-qualified call like "subprocess.Popen" or a distinct
// stdlib/framework method), never a bare common-English word. A bare word
// like "execute" or "getAttribute" collides with unrelated identifiers in
// real code and produces exactly the false-positive pattern that motivated
// NoSinkModel in the first place. Anchors are grouped by language in
// comments for maintainability — Go's substring matching (contracts/check.go)
// doesn't care about language, so this is documentation, not a code split.
var Rulebook = map[string]Invariant{
	"CWE-89": {
		CWE:  "CWE-89",
		Name: "SQL Injection",
		SinkAnchors: []string{
			// Java (JDBC / Spring / Hibernate)
			"executeQuery", "executeUpdate", "createNativeQuery", "createSQLQuery", "Statement.execute",
			"JdbcTemplate.query", "JdbcTemplate.update", "JdbcTemplate.queryForObject", "JdbcTemplate.batchUpdate",
			// Python (DB-API / SQLAlchemy / Django)
			"cursor.execute", "cursor.executemany", "cursor.executescript", "connection.execute",
			"sqlalchemy.text", "RawSQL",
			// Go (database/sql / sqlx / GORM)
			"db.Query", "db.Exec", "db.QueryRow", "sqlx.Query", "sqlx.Exec", "gorm.Raw", "gorm.Exec",
			// JavaScript/TypeScript (node-postgres / mysql2 / Sequelize / Knex / TypeORM)
			"pool.query", "connection.query", "sequelize.query", "knex.raw", "createQueryBuilder", "manager.query",
		},
		SafeNodes: []string{
			"PreparedStatement", "prepareStatement", "bindParams", "sqlalchemy.bindparams",
			"paramQuery", "parameterizedQuery", "boundParam", "knex.where", "sequelize.findOne",
		},
		Reference: "OWASP Top 10 2021: A03 Injection; CWE-89 specification",
	},
	"CWE-78": {
		CWE:  "CWE-78",
		Name: "OS Command Injection",
		SinkAnchors: []string{
			// Java
			"Runtime.exec", "ProcessBuilder.start",
			// Python
			"subprocess.Popen", "subprocess.call", "subprocess.run", "subprocess.check_output",
			"subprocess.check_call", "os.system", "os.popen", "os.spawnl", "os.spawnv",
			// Go
			"exec.Command", "exec.CommandContext",
			// JavaScript/TypeScript (Node child_process)
			"child_process.exec", "child_process.execSync", "child_process.spawn", "child_process.spawnSync",
			"child_process.execFile", "child_process.execFileSync",
		},
		SafeNodes: []string{
			"shellEscape", "shlex.quote", "shlex.split", "execFile", "commandAllowlist", "argSanitize",
		},
		Reference: "OWASP Top 10 2021: A03 Injection; CWE-78 specification",
	},
	"CWE-22": {
		CWE:  "CWE-22",
		Name: "Path Traversal",
		SinkAnchors: []string{
			// Java
			"FileWriter", "FileOutputStream", "FileInputStream", "FileReader", "new File", "Paths.get",
			"Files.copy", "Files.write", "Files.readAllBytes", "Files.newInputStream", "ZipEntry", "ZipInputStream",
			"getCanonicalPath", "getAbsolutePath", "transferTo", "file.transferTo", "OutputStream.write",
			"Files.newOutputStream", "Files.newBufferedWriter", "Files.createFile", "Files.createTempFile", "Files.move",
			// Python
			"os.path.join", "pathlib.Path", "shutil.copy", "shutil.move", "shutil.copyfile",
			"zipfile.extract", "zipfile.extractall", "tarfile.extract", "tarfile.extractall",
			"send_file", "send_from_directory",
			// Go
			"os.Open", "os.OpenFile", "os.Create", "os.ReadFile", "os.WriteFile", "ioutil.ReadFile",
			"ioutil.WriteFile", "filepath.Join", "http.ServeFile", "zip.OpenReader",
			// JavaScript/TypeScript
			"fs.readFile", "fs.readFileSync", "fs.writeFile", "fs.writeFileSync", "fs.createReadStream",
			"fs.createWriteStream", "path.join", "path.resolve", "res.sendFile", "unzipper.Extract",
		},
		SafeNodes: []string{
			"pathClean", "canonicalizePath", "pathValidate", "baseNameOnly", "normalize", "toAbsolutePath", "startsWith",
			"filepath.Clean", "os.path.abspath", "secure_filename", "sanitizeFilename",
		},
		Reference: "OWASP Top 10 2021: A01 Broken Access Control; CWE-22 specification",
	},
	"CWE-79": {
		CWE:  "CWE-79",
		Name: "XSS",
		SinkAnchors: []string{
			// Java
			"PrintWriter.print", "HttpServletResponse.print", "out.println", "response.getWriter",
			// Python
			"render_template_string", "Markup", "mark_safe", "format_html",
			// Go
			"template.HTML", "template.JS", "Fprintf(w",
			// JavaScript/TypeScript
			"innerHTML", "outerHTML", "document.write", "dangerouslySetInnerHTML", "v-html",
			"insertAdjacentHTML", "response.write", "response.Send",
		},
		SafeNodes: []string{
			"htmlEscape", "outputEncode", "contextEncode", "autoEscape", "html.EscapeString",
			"template.HTMLEscapeString", "bleach.clean", "DOMPurify.sanitize", "textContent",
		},
		Reference: "OWASP Top 10 2021: A03 Injection; CWE-79 specification",
	},
	"CWE-94": {
		CWE:  "CWE-94",
		Name: "Code Injection",
		SinkAnchors: []string{
			// Java
			"ScriptEngine.eval", "Nashorn.eval", "JavaCompiler.compile", "Compiler.compile",
			"GroovyShell.evaluate", "Method.invoke", "Constructor.newInstance",
			// Python — bare "exec" deliberately excluded: it's a substring of
			// every CWE-78 command-exec anchor (exec.Command, child_process.exec,
			// Runtime.exec, ...), and since this CWE has no SafeNodes (any match
			// is an instant Violation) it would silently override a correct
			// CWE-78 Safe verdict on any command-injection surface. Python's
			// exec() is left to B4/B5's code-text reasoning instead.
			"eval", "compile", "__import__",
			// Go (dynamic code loading is rare — plugin misuse is the closest analogue)
			"plugin.Open",
			// JavaScript/TypeScript
			"new Function", "vm.runInContext", "vm.runInNewContext", "vm.runInThisContext", "execScript",
		},
		SafeNodes: nil, // no safe path for code injection — always a violation when sink is reached
		Reference: "OWASP Top 10 2021: A03 Injection; CWE-94 specification",
	},
	"CWE-918": {
		CWE:  "CWE-918",
		Name: "SSRF",
		SinkAnchors: []string{
			// Java
			"HTTPClient.send", "RestTemplate.getForObject", "RestTemplate.postForObject",
			"WebClient.get", "URLConnection.openConnection", "HttpURLConnection",
			// Python
			"requests.get", "requests.post", "requests.request", "urllib.request.urlopen",
			"httpx.get", "httpx.post", "aiohttp.ClientSession",
			// Go
			"http.Get", "http.Post", "http.Client", "http.NewRequest",
			// JavaScript/TypeScript
			"axios.get", "axios.post", "http.request", "https.request", "node-fetch", "fetch",
		},
		SafeNodes: []string{
			"urlAllowlist", "domainCheck", "urlValidate", "hostnameVerify", "isPrivateIP", "ssrfReqFilter",
		},
		Reference: "OWASP Top 10 2021: A10 Server-Side Request Forgery; CWE-918 specification",
	},
	"CWE-862": {
		CWE:  "CWE-862",
		Name: "Missing Authorization",
		// No SinkAnchors/SafeNodes: unlike injection-class CWEs, missing
		// authorization has no fixed dangerous-API signature to keyword-match
		// — the sink is whatever operation the surface performs, and that's
		// already been established structurally by Targeting (idor_candidate/
		// auth_boundary, via real call-graph reachability to auth). A prior
		// version of this entry populated SinkAnchors with auth-check function
		// names (hasRole, isAuthenticated, getSession, getAttribute, ...) —
		// intended as "reaching one of these means the vuln", but (a) that's
		// backwards (reaching an auth check is evidence of authorization, not
		// its absence), and (b) generic getter names like getAttribute are a
		// substring of extremely common unrelated code (getAttributes()),
		// producing false positives on ordinary CRUD code. See NoSinkModel.
		NoSinkModel: true,
		Reference:   "OWASP Top 10 2021: A01 Broken Access Control; CWE-862 specification; MITRE CWE-862 (missing-authorization detection requires business-context knowledge not derivable from static keyword/method-name matching)",
	},
	"CWE-327": {
		CWE:  "CWE-327",
		Name: "Broken Crypto",
		SinkAnchors: []string{
			// Java (bare algorithm-name literals catch MessageDigest.getInstance("MD5")-style
			// calls via the code-text fallback, since Joern's sink node for a generic
			// factory call like getInstance won't itself encode the string argument)
			"MessageDigest.getInstance", "Cipher.getInstance", "md5", "sha1", "des", "rc4",
			// Python
			"hashlib.md5", "hashlib.sha1", "Crypto.Cipher.DES", "Crypto.Cipher.ARC4",
			// Go
			"crypto/md5", "crypto/sha1", "crypto/des", "crypto/rc4", "des.NewCipher",
			// JavaScript/TypeScript
			"createHash", "createCipheriv",
		},
		SafeNodes: []string{
			"crypto.SHA256", "crypto.SHA512", "cipher.AESGCM", "crypto.AES", "sha256", "sha512", "aesGcm",
			"hashlib.sha256", "bcrypt", "argon2", "scrypt",
		},
		Reference: "OWASP Top 10 2021: A02 Cryptographic Failures; CWE-327 specification",
	},
	"CWE-502": {
		CWE:  "CWE-502",
		Name: "Unsafe Deserialization",
		SinkAnchors: []string{
			// Java
			"ObjectInputStream.readObject", "ObjectInputStream.deserialize", "XMLDecoder",
			"XStream.fromXML", "Deserializer.deserialize", "Unmarshaller.unmarshal", "XmlUnmarshaller.unmarshal",
			// Python
			"pickle.load", "pickle.loads", "yaml.load", "marshal.loads", "shelve.open",
			// Go — gob is Go's actual unsafe-deserialization-relevant primitive;
			// encoding/json.Unmarshal into a typed struct is not itself dangerous
			// and is deliberately excluded to avoid false-positiving on ordinary
			// JSON parsing (the same substring-collision risk that CWE-862 hit).
			"gob.Decode", "gob.NewDecoder",
			// JavaScript/TypeScript
			"node-serialize.unserialize", "js-yaml.load",
		},
		SafeNodes: []string{
			"typeFilter", "objectFilter", "deserializeSecure", "validateDeserialize",
			"yaml.safe_load", "yaml.SafeLoader", "js-yaml.safeLoad",
		},
		Reference: "OWASP Top 10 2021: A08 Software and Data Integrity Failures; CWE-502 specification",
	},
}

func init() {
	slog.Debug("rulebook loaded", "entries", len(Rulebook))
}
