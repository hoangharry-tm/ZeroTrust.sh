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

package cpg_engine

import (
	"path/filepath"
	"strings"
)

// Language identifies a supported programming language for taint analysis.
type Language string

const (
	LanguageJava   Language = "java"
	LanguagePython Language = "python"
	LanguageJS     Language = "js"
	LanguageGo     Language = "go"
)

// SourceDef describes an untrusted-data entry-point pattern.
type SourceDef struct {
	Name string // method / call name pattern
	Kind string // "http_param" | "env_var" | "file_read" | "stdin" | "http_body" | "http_header"
}

// SinkDef describes a dangerous data-consumption point.
type SinkDef struct {
	Name string   // method / call name pattern
	Kind SinkKind // sql / command / deserialization / file_write / template / redirect / eval
	CWE  string   // canonical CWE identifier
}

// JoernName returns the bare call name for Joern sinkSet matching.
// Joern's c.name is always the unqualified method name, so "XStream.fromXML"
// must be queried as "fromXML".
func (s SinkDef) JoernName() string {
	if i := strings.LastIndex(s.Name, "."); i >= 0 {
		return s.Name[i+1:]
	}
	return s.Name
}

// SanitizerDef describes a validation / encoding function pattern.
type SanitizerDef struct {
	Name string
}

// TaintConfig holds the complete taint configuration for one language.
type TaintConfig struct {
	Language         Language
	Sources          []SourceDef
	Sinks            []SinkDef
	ConstructorSinks []SinkDef // constructor-based sinks (<init> + typeFullName match)
	Sanitizers       []SanitizerDef
}

// DetectLanguage returns the Language for a file path based on its extension.
// The second return value is false for unsupported extensions.
func DetectLanguage(filePath string) (Language, bool) {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".java":
		return LanguageJava, true
	case ".py":
		return LanguagePython, true
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
		return LanguageJS, true
	case ".go":
		return LanguageGo, true
	default:
		return "", false
	}
}

// TaintConfigs maps each supported language to its taint configuration.
var TaintConfigs = map[Language]TaintConfig{
	LanguageJava:   {Language: LanguageJava, Sources: javaSources, Sinks: javaSinks, ConstructorSinks: javaConstructorSinks, Sanitizers: javaSanitizers},
	LanguagePython: {Language: LanguagePython, Sources: pythonSources, Sinks: pythonSinks, Sanitizers: pythonSanitizers},
	LanguageJS:     {Language: LanguageJS, Sources: jsSources, Sinks: jsSinks, Sanitizers: jsSanitizers},
	LanguageGo:     {Language: LanguageGo, Sources: goSources, Sinks: goSinks, Sanitizers: goSanitizers},
}

// ── Java ──────────────────────────────────────────────────────────────────────

var javaSources = []SourceDef{
	{Name: "getParameter", Kind: "http_param"},
	{Name: "getParameterValues", Kind: "http_param"},
	{Name: "getQueryString", Kind: "http_param"},
	{Name: "getHeader", Kind: "http_header"},
	{Name: "getHeaders", Kind: "http_header"},
	{Name: "getCookies", Kind: "http_param"},
	{Name: "getReader", Kind: "http_body"},
	{Name: "getInputStream", Kind: "http_body"},
	{Name: "getParts", Kind: "http_body"},
	{Name: "getParameterMap", Kind: "http_param"},
	{Name: "getAttribute", Kind: "http_param"},
	{Name: "getPathVariable", Kind: "http_param"},
	{Name: "getRequestBody", Kind: "http_body"},
	{Name: "readLine", Kind: "stdin"},
	{Name: "nextLine", Kind: "stdin"},
	{Name: "getPathInfo", Kind: "http_param"},
	{Name: "getServletPath", Kind: "http_param"},
	{Name: "Part.getInputStream", Kind: "http_body"},
	{Name: "Part.getSubmittedFileName", Kind: "http_param"},
	{Name: "System.getenv", Kind: "env_var"},
	{Name: "System.getProperty", Kind: "env_var"},
	{Name: "System.getProperties", Kind: "env_var"},
}

var javaSinks = []SinkDef{
	{Name: "executeQuery", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "executeUpdate", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "execute", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "createNativeQuery", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "createQuery", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "createSQLQuery", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "nativeQuery", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "queryForObject", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "queryForList", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "exec", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "Runtime.exec", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "ProcessBuilder.start", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "ProcessBuilder.command", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "readObject", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "ObjectInputStream", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "XStream.fromXML", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "Yaml.load", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "JSON.parseObject", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "readValue", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "XMLDecoder.readObject", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "SerializationUtils.deserialize", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "Hessian2Input.readObject", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "sendRedirect", Kind: SinkRedirect, CWE: "CWE-601"},
	{Name: "forward", Kind: SinkRedirect, CWE: "CWE-601"},
	{Name: "eval", Kind: SinkEval, CWE: "CWE-94"},
	{Name: "ScriptEngine.eval", Kind: SinkEval, CWE: "CWE-94"},
	{Name: "response.getWriter", Kind: SinkTemplate, CWE: "CWE-79"},
	{Name: "out.print", Kind: SinkTemplate, CWE: "CWE-79"},
	{Name: "out.println", Kind: SinkTemplate, CWE: "CWE-79"},
	{Name: "out.write", Kind: SinkTemplate, CWE: "CWE-79"},
	{Name: "ModelAndView", Kind: SinkTemplate, CWE: "CWE-79"},
	{Name: "Velocity.evaluate", Kind: SinkTemplate, CWE: "CWE-79"},
	{Name: "FileWriter", Kind: SinkFileWrite, CWE: "CWE-22"},
	{Name: "FileOutputStream", Kind: SinkFileWrite, CWE: "CWE-22"},
}

var javaConstructorSinks = []SinkDef{
	{Name: "FileWriter", Kind: SinkFileWrite, CWE: "CWE-22"},
	{Name: "FileOutputStream", Kind: SinkFileWrite, CWE: "CWE-22"},
	{Name: "FileInputStream", Kind: SinkFileWrite, CWE: "CWE-22"},
	{Name: "FileReader", Kind: SinkFileWrite, CWE: "CWE-22"},
	{Name: "ZipOutputStream", Kind: SinkFileWrite, CWE: "CWE-22"},
	{Name: "ObjectInputStream", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "XMLDecoder", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "ProcessBuilder", Kind: SinkCommand, CWE: "CWE-78"},
}

var javaSanitizers = []SanitizerDef{
	{Name: "Encode.forHtml"},
	{Name: "Encode.forJavaScript"},
	{Name: "Encode.forSql"},
	{Name: "ESAPI.encoder"},
	{Name: "StringEscapeUtils.escapeHtml"},
	{Name: "StringEscapeUtils.escapeSql"},
	{Name: "HtmlUtils.htmlEscape"},
	{Name: "URLEncoder.encode"},
	{Name: "URLDecoder.decode"},
	{Name: "Validator.validate"},
	{Name: "validate"},
	{Name: "isValid"},
	{Name: "sanitize"},
	{Name: "PreparedStatement"},
	{Name: "setString"},
	{Name: "setInt"},
	{Name: "setParameter"},
}

// ── Python ────────────────────────────────────────────────────────────────────

var pythonSources = []SourceDef{
	{Name: "request.args", Kind: "http_param"},
	{Name: "request.form", Kind: "http_body"},
	{Name: "request.json", Kind: "http_body"},
	{Name: "request.data", Kind: "http_body"},
	{Name: "request.headers", Kind: "http_header"},
	{Name: "request.cookies", Kind: "http_param"},
	{Name: "request.files", Kind: "http_body"},
	{Name: "request.query_string", Kind: "http_param"},
	{Name: "request.values", Kind: "http_param"},
	{Name: "request.get_json", Kind: "http_body"},
	{Name: "request.get_data", Kind: "http_body"},
	{Name: "request.form.get", Kind: "http_body"},
	{Name: "request.args.get", Kind: "http_param"},
	{Name: "request.headers.get", Kind: "http_header"},
	{Name: "Query", Kind: "http_param"},
	{Name: "Body", Kind: "http_body"},
	{Name: "Header", Kind: "http_header"},
	{Name: "Cookie", Kind: "http_param"},
	{Name: "Path", Kind: "http_param"},
	{Name: "File", Kind: "http_body"},
	{Name: "request.GET", Kind: "http_param"},
	{Name: "request.POST", Kind: "http_body"},
	{Name: "request.body", Kind: "http_body"},
	{Name: "request.META", Kind: "http_header"},
	{Name: "request.FILES", Kind: "http_body"},
	{Name: "os.environ", Kind: "env_var"},
	{Name: "os.getenv", Kind: "env_var"},
	{Name: "environ.get", Kind: "env_var"},
	{Name: "sys.stdin", Kind: "stdin"},
	{Name: "sys.argv", Kind: "http_param"},
	{Name: "input", Kind: "stdin"},
}

var pythonSinks = []SinkDef{
	{Name: "execute", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "executemany", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "rawsql", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "os.system", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "subprocess.Popen", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "subprocess.run", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "subprocess.call", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "subprocess.check_output", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "os.popen", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "os.popen2", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "os.popen3", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "os.popen4", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "pickle.load", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "pickle.loads", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "yaml.load", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "marshal.load", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "shelve.open", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "eval", Kind: SinkEval, CWE: "CWE-94"},
	{Name: "exec", Kind: SinkEval, CWE: "CWE-94"},
	{Name: "compile", Kind: SinkEval, CWE: "CWE-94"},
	{Name: "render", Kind: SinkTemplate, CWE: "CWE-1336"},
	{Name: "render_template", Kind: SinkTemplate, CWE: "CWE-1336"},
	{Name: "render_template_string", Kind: SinkTemplate, CWE: "CWE-1336"},
	{Name: "Template", Kind: SinkTemplate, CWE: "CWE-1336"},
	{Name: "open", Kind: SinkFileWrite, CWE: "CWE-22"},
	{Name: "shutil.copy", Kind: SinkFileWrite, CWE: "CWE-22"},
	{Name: "shutil.move", Kind: SinkFileWrite, CWE: "CWE-22"},
}

var pythonSanitizers = []SanitizerDef{
	{Name: "escape"},
	{Name: "html.escape"},
	{Name: "markupsafe.escape"},
	{Name: "cgi.escape"},
	{Name: "validate"},
	{Name: "is_valid"},
	{Name: "clean"},
	{Name: "sanitize"},
	{Name: "sanitize_filename"},
	{Name: "shlex.quote"},
	{Name: "pipes.quote"},
	{Name: "bleach.clean"},
	{Name: "bleach.linkify"},
	{Name: "defusedxml"},
	{Name: "defusedxml.ElementTree"},
}

// ── JavaScript / TypeScript ───────────────────────────────────────────────────

var jsSources = []SourceDef{
	{Name: "req.query", Kind: "http_param"},
	{Name: "req.body", Kind: "http_body"},
	{Name: "req.params", Kind: "http_param"},
	{Name: "req.headers", Kind: "http_header"},
	{Name: "req.cookies", Kind: "http_param"},
	{Name: "req.signedCookies", Kind: "http_param"},
	{Name: "req.get", Kind: "http_header"},
	{Name: "req.param", Kind: "http_param"},
	{Name: "ctx.query", Kind: "http_param"},
	{Name: "ctx.request.body", Kind: "http_body"},
	{Name: "ctx.params", Kind: "http_param"},
	{Name: "ctx.headers", Kind: "http_header"},
	{Name: "ctx.cookies", Kind: "http_param"},
	{Name: "process.env", Kind: "env_var"},
	{Name: "process.argv", Kind: "http_param"},
	{Name: "Deno.env", Kind: "env_var"},
	{Name: "Bun.env", Kind: "env_var"},
}

var jsSinks = []SinkDef{
	{Name: "query", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "execute", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "find", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "findOne", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "findAll", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "findOneAndUpdate", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "exec", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "execSync", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "spawn", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "spawnSync", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "fork", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "execFile", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "execFileSync", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "unserialize", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "deserialize", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "writeFile", Kind: SinkFileWrite, CWE: "CWE-22"},
	{Name: "writeFileSync", Kind: SinkFileWrite, CWE: "CWE-22"},
	{Name: "appendFile", Kind: SinkFileWrite, CWE: "CWE-22"},
	{Name: "render", Kind: SinkTemplate, CWE: "CWE-1336"},
	{Name: "renderFile", Kind: SinkTemplate, CWE: "CWE-1336"},
	{Name: "renderString", Kind: SinkTemplate, CWE: "CWE-1336"},
	{Name: "eval", Kind: SinkEval, CWE: "CWE-94"},
	{Name: "Function", Kind: SinkEval, CWE: "CWE-94"},
	{Name: "redirect", Kind: SinkRedirect, CWE: "CWE-601"},
	{Name: "res.redirect", Kind: SinkRedirect, CWE: "CWE-601"},
	{Name: "ctx.redirect", Kind: SinkRedirect, CWE: "CWE-601"},
}

var jsSanitizers = []SanitizerDef{
	{Name: "escape"},
	{Name: "escapeHtml"},
	{Name: "xss"},
	{Name: "sanitize"},
	{Name: "sanitizeHtml"},
	{Name: "validator.escape"},
	{Name: "validator.trim"},
	{Name: "DOMPurify"},
	{Name: "shellQuote"},
	{Name: "shell-quote"},
	{Name: "validate"},
	{Name: "isValid"},
}

// ── Go ────────────────────────────────────────────────────────────────────────

var goSources = []SourceDef{
	{Name: "r.URL.Query", Kind: "http_param"},
	{Name: "r.URL.Query().Get", Kind: "http_param"},
	{Name: "r.FormValue", Kind: "http_param"},
	{Name: "r.PostFormValue", Kind: "http_body"},
	{Name: "r.Form", Kind: "http_param"},
	{Name: "r.PostForm", Kind: "http_body"},
	{Name: "r.MultipartForm", Kind: "http_body"},
	{Name: "r.Header", Kind: "http_header"},
	{Name: "r.Header.Get", Kind: "http_header"},
	{Name: "r.Header.Values", Kind: "http_header"},
	{Name: "r.Cookie", Kind: "http_param"},
	{Name: "r.Referer", Kind: "http_header"},
	{Name: "r.UserAgent", Kind: "http_header"},
	{Name: "r.RemoteAddr", Kind: "http_header"},
	{Name: "r.RequestURI", Kind: "http_param"},
	{Name: "os.Getenv", Kind: "env_var"},
	{Name: "os.Environ", Kind: "env_var"},
	{Name: "os.LookupEnv", Kind: "env_var"},
	{Name: "ctx.Value", Kind: "http_param"},
}

var goSinks = []SinkDef{
	{Name: "Query", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "QueryRow", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "Exec", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "Prepare", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "Raw", Kind: SinkSQL, CWE: "CWE-89"},
	{Name: "exec.Command", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "exec.CommandContext", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "os.StartProcess", Kind: SinkCommand, CWE: "CWE-78"},
	{Name: "json.Unmarshal", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "gob.Decode", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "xml.Unmarshal", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "yaml.Unmarshal", Kind: SinkDeserialization, CWE: "CWE-502"},
	{Name: "os.WriteFile", Kind: SinkFileWrite, CWE: "CWE-22"},
	{Name: "os.Create", Kind: SinkFileWrite, CWE: "CWE-22"},
	{Name: "ioutil.WriteFile", Kind: SinkFileWrite, CWE: "CWE-22"},
	{Name: "http.Redirect", Kind: SinkRedirect, CWE: "CWE-601"},
}

var goSanitizers = []SanitizerDef{
	{Name: "html.EscapeString"},
	{Name: "html.UnescapeString"},
	{Name: "template.HTMLEscapeString"},
	{Name: "template.JSEscapeString"},
	{Name: "template.URLQueryEscaper"},
	{Name: "url.QueryEscape"},
	{Name: "url.PathEscape"},
	{Name: "validate"},
	{Name: "isValid"},
	{Name: "sanitize"},
	// db.Query*, db.Exec, stmt.Query, stmt.Exec are SQL sinks — not sanitizers.
	// They were incorrectly listed here and would suppress all Go SQL injection findings.
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// DetectLanguageFromFiles returns the majority Language among the given file set.
// Unsupported extensions are ignored. Returns ("", false) when no supported files
// are present.
func DetectLanguageFromFiles(files []string) (Language, bool) {
	counts := make(map[Language]int)
	for _, f := range files {
		if lang, ok := DetectLanguage(f); ok {
			counts[lang]++
		}
	}
	if len(counts) == 0 {
		return "", false
	}
	best := Language("")
	maxN := 0
	for lang, n := range counts {
		if n > maxN {
			best = lang
			maxN = n
		}
	}
	return best, true
}

// ConstructorSinkTypeNames returns the type names for constructor-based sinks
// for the given language. These match against c.call.typeFullName when c.name == "<init>".
func ConstructorSinkTypeNames(lang Language) []string {
	cfg, ok := TaintConfigs[lang]
	if !ok {
		return nil
	}
	names := make([]string, len(cfg.ConstructorSinks))
	for i, s := range cfg.ConstructorSinks {
		names[i] = s.Name
	}
	return names
}

// SinkDefForCall matches a CALL node name against the language's sink definitions.
// Returns the matched SinkDef and true, or SinkDef{} and false if no match.
func SinkDefForCall(lang Language, callName string) (SinkDef, bool) {
	cfg, ok := TaintConfigs[lang]
	if !ok {
		return SinkDef{}, false
	}
	for _, s := range cfg.Sinks {
		// ponytail: substring match risks false positives (e.g. "exec" matches "execute").
		// Upgrade path: structural PDG edge classification when PDG ingestion is added.
		bareName := s.Name
		if i := strings.LastIndex(s.Name, "."); i >= 0 {
			bareName = s.Name[i+1:]
		}
		if strings.Contains(callName, bareName) {
			return s, true
		}
	}
	return SinkDef{}, false
}

// SourceDefForCall matches a CALL node name against the language's source definitions.
// Returns the matched SourceDef and true, or SourceDef{} and false if no match.
func SourceDefForCall(lang Language, callName string) (SourceDef, bool) {
	cfg, ok := TaintConfigs[lang]
	if !ok {
		return SourceDef{}, false
	}
	for _, s := range cfg.Sources {
		// ponytail: substring match risks false positives (e.g. "exec" matches "execute").
		// Upgrade path: structural PDG edge classification when PDG ingestion is added.
		if strings.Contains(callName, s.Name) {
			return s, true
		}
	}
	return SourceDef{}, false
}

// DetectSanitizer reports whether a function name is a known sanitizer for the given language.
func DetectSanitizer(lang Language, name string) bool {
	cfg, ok := TaintConfigs[lang]
	if !ok {
		return false
	}
	for _, s := range cfg.Sanitizers {
		if strings.Contains(name, s.Name) {
			return true
		}
	}
	return false
}
