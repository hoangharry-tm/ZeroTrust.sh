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

// This file defines the single-pass union JSON schema used by XGrammar-2
// TagDispatch. One UnionSchema object covers all three vulnerability classes
// (taint_flow, auth_guard, logic_flaw) in a single LLM inference call, without
// recompilation of the XGrammar-2 grammar between classes.
//
// The Python worker deserialises LLM output against this schema; the Go side
// uses it to type-check decoded results and to build the structured payload sent
// to the summarize handler.

package assembler

// CheckLocation classifies where (or whether) an authorization check occurs.
// Shared by AuthGuardSchema and LogicFlawSchema. Distinguishes real auth gaps
// from framework-controlled access (LLMxCPG USENIX 2025, VULSOLVER arXiv 2025).
type CheckLocation string

const (
	// CheckFrameworkAnnotation means access control is enforced by a framework
	// annotation or decorator (e.g. @PreAuthorize, @login_required, middleware chain).
	CheckFrameworkAnnotation CheckLocation = "framework_annotation"
	// CheckExplicitCode means an explicit conditional (if/guard) performs the check.
	CheckExplicitCode CheckLocation = "explicit_code"
	// CheckMiddleware means the check is in middleware/interceptor before this function.
	CheckMiddleware CheckLocation = "middleware"
	// CheckUnknown means no check was detected.
	CheckUnknown CheckLocation = "unknown"
)

// TaintFlowSchema captures untrusted data propagation through a function.
type TaintFlowSchema struct {
	// UntrustedSources lists parameter names or call sites that introduce untrusted data.
	UntrustedSources []string `json:"untrusted_sources"`
	// SanitizerNodes lists call sites that sanitize or validate the tainted data.
	SanitizerNodes []string `json:"sanitizer_nodes"`
	// SinkType is the kind of dangerous sink the tainted data flows into
	// (e.g. "sql", "command", "template"); empty if no sink is reached.
	SinkType string `json:"sink_type"`
	// TaintPropagates is true when tainted data reaches a sink without sanitization.
	TaintPropagates bool `json:"taint_propagates"`
}

// AuthGuardSchema captures the authorization check status for a function.
// CheckLocation distinguishes real auth gaps from framework-level controls,
// reducing false positives on annotated endpoints.
type AuthGuardSchema struct {
	// CheckPresent is true when an authorization check was detected.
	CheckPresent bool `json:"check_present"`
	// CheckLocation describes where the check is performed.
	CheckLocation CheckLocation `json:"check_location"`
}

// LogicFlawSchema captures resource ID and authorization data for IDOR detection.
// Populated for surfaces flagged as IDOR candidates.
type LogicFlawSchema struct {
	// ResourceIDSource is the parameter or variable name carrying the external resource ID.
	ResourceIDSource string `json:"resource_id_source"`
	// DBSink is the database or storage call the resource ID flows into.
	DBSink string `json:"db_sink"`
	// CheckLocation describes where (if anywhere) an ownership check occurs.
	CheckLocation CheckLocation `json:"check_location"`
}

// UnionSchema is the XGrammar-2 TagDispatch union covering all three vulnerability
// classes. A single LLM inference call populates all three sub-schemas simultaneously;
// the TagDispatch discriminator tells the grammar engine which class is primary.
// Neither the Go engine nor the Python worker need to recompile the grammar to
// switch between vulnerability classes.
type UnionSchema struct {
	// Tag is the TagDispatch discriminator set by the LLM ("taint_flow", "auth_guard",
	// or "logic_flaw"). The primary finding class has Tag set to its name; the others
	// are still populated but treated as supplementary evidence.
	Tag string `json:"tag"`
	// TaintFlow describes untrusted data propagation.
	TaintFlow TaintFlowSchema `json:"taint_flow"`
	// AuthGuard describes authorization check presence and location.
	AuthGuard AuthGuardSchema `json:"auth_guard"`
	// LogicFlaw describes resource ID flow and ownership check status.
	LogicFlaw LogicFlawSchema `json:"logic_flaw"`
}
