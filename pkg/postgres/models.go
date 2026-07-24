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

package postgres

// projectModel backs the projects table. GORM's default pluralized snake_case
// table name ("project_models") is overridden via TableName below to match
// the schema every consumer already expects.
type projectModel struct {
	ProjectID       string `gorm:"column:project_id;primaryKey"`
	RootPath        string `gorm:"column:root_path;not null;unique"`
	PrimaryLanguage string `gorm:"column:primary_language"`
	FirstSeenAt     int64  `gorm:"column:first_seen_at;not null"`
	LastScannedAt   int64  `gorm:"column:last_scanned_at;not null"`
}

func (projectModel) TableName() string { return "projects" }

type scanRunModel struct {
	RunID         string `gorm:"column:run_id;primaryKey"`
	ProjectID     string `gorm:"column:project_id;not null;index:idx_scan_runs_project"`
	StartedAt     int64  `gorm:"column:started_at;not null;index:idx_scan_runs_project"`
	FinishedAt    int64  `gorm:"column:finished_at"`
	ScanMode      string `gorm:"column:scan_mode;not null;default:default"`
	FilesScanned  int    `gorm:"column:files_scanned;not null;default:0"`
	FindingsTotal int    `gorm:"column:findings_total;not null;default:0"`
	Status        string `gorm:"column:status;not null;default:running"`
}

func (scanRunModel) TableName() string { return "scan_runs" }

type findingModel struct {
	FindingID      string  `gorm:"column:finding_id;primaryKey"`
	ProjectID      string  `gorm:"column:project_id;not null;index:idx_findings_project_sev;index:idx_findings_first_seen"`
	RunID          string  `gorm:"column:run_id;not null"`
	FilePath       string  `gorm:"column:file_path;not null"`
	LineStart      int     `gorm:"column:line_start;not null"`
	LineEnd        int     `gorm:"column:line_end;not null"`
	CWE            string  `gorm:"column:cwe"`
	Severity       string  `gorm:"column:severity;not null;index:idx_findings_project_sev"`
	Confidence     float64 `gorm:"column:confidence;not null"`
	SourcePath     string  `gorm:"column:source_path;not null"`
	RuleID         string  `gorm:"column:rule_id"`
	MatchedCode    string  `gorm:"column:matched_code"`
	Justification  string  `gorm:"column:justification"`
	SuppressReason string  `gorm:"column:suppress_reason"`
	Patch          string  `gorm:"column:patch"`
	PatchStatus    string  `gorm:"column:patch_status"`
	FirstSeenAt    int64   `gorm:"column:first_seen_at;not null;index:idx_findings_first_seen"`
	LastSeenAt     int64   `gorm:"column:last_seen_at;not null"`
}

func (findingModel) TableName() string { return "findings" }

// ssvcScoreModel backs ssvc_scores — written via UpsertSSVCScore (findings.go).
type ssvcScoreModel struct {
	FindingID       string `gorm:"column:finding_id;primaryKey"`
	Exploitation    string `gorm:"column:exploitation"`
	Automatable     string `gorm:"column:automatable"`
	TechnicalImpact string `gorm:"column:technical_impact"`
}

func (ssvcScoreModel) TableName() string { return "ssvc_scores" }

// poeResultModel backs poe_results — written via UpsertPoEResult (findings.go).
// Only the columns the original schema defined are persisted; finding.PoEResult's
// more verbose ExploitInput/DevTrace fields stay in-memory/logs only.
type poeResultModel struct {
	FindingID          string  `gorm:"column:finding_id;primaryKey"`
	Status             string  `gorm:"column:status"`
	Confidence         float64 `gorm:"column:confidence"`
	BusinessImpactTier string  `gorm:"column:business_impact_tier"`
	ExecSummary        string  `gorm:"column:exec_summary"`
}

func (poeResultModel) TableName() string { return "poe_results" }

type cpgCacheModel struct {
	ProjectID        string `gorm:"column:project_id;primaryKey"`
	CPGPath          string `gorm:"column:cpg_path;not null"`
	ScopeMode        string `gorm:"column:scope_mode;not null"`
	BuiltAt          int64  `gorm:"column:built_at;not null"`
	ChangedFunctions int    `gorm:"column:changed_functions;not null;default:0"`
}

func (cpgCacheModel) TableName() string { return "cpg_cache" }

type scanStateModel struct {
	ProjectID     string `gorm:"column:project_id;primaryKey;index:idx_scan_state_hash"`
	FilePath      string `gorm:"column:file_path;primaryKey"`
	ContentHash   string `gorm:"column:content_hash;not null;index:idx_scan_state_hash"`
	LastScannedAt int64  `gorm:"column:last_scanned_at;not null"`
}

func (scanStateModel) TableName() string { return "scan_state" }

type suppressionModel struct {
	ProjectID    string `gorm:"column:project_id;primaryKey"`
	FindingID    string `gorm:"column:finding_id;primaryKey"`
	Reason       string `gorm:"column:reason;not null"`
	SuppressedAt int64  `gorm:"column:suppressed_at;not null"`
}

func (suppressionModel) TableName() string { return "suppressions" }

type workItemModel struct {
	ScanID    string `gorm:"column:scan_id;primaryKey;index:idx_work_pending"`
	Component string `gorm:"column:component;primaryKey;index:idx_work_pending"`
	SurfaceID string `gorm:"column:surface_id;primaryKey"`
	Status    string `gorm:"column:status;not null;default:pending;index:idx_work_pending"`
	Payload   string `gorm:"column:payload"`
	CreatedAt int64  `gorm:"column:created_at;not null"`
	UpdatedAt int64  `gorm:"column:updated_at;not null"`
}

func (workItemModel) TableName() string { return "work_items" }

type pendingFindingModel struct {
	ScanID    string `gorm:"column:scan_id;primaryKey"`
	FindingID string `gorm:"column:finding_id;primaryKey"`
	Data      string `gorm:"column:data;not null"`
	CreatedAt int64  `gorm:"column:created_at;not null"`
}

func (pendingFindingModel) TableName() string { return "pending_findings" }

// cpgNodeModel and cpgEdgeModel back the CPG graph store. AutoMigrate creates
// these tables too, but the hot read/write path (IngestNodeBatch/EdgeBatch,
// graph queries) goes through the raw pgx pool in cpg.go, not GORM.
type cpgNodeModel struct {
	ProjectID  string `gorm:"column:project_id;primaryKey;index:idx_cpn_type;index:idx_cpn_file"`
	CPGVersion string `gorm:"column:cpg_version;primaryKey;index:idx_cpn_type;index:idx_cpn_file"`
	NodeID     string `gorm:"column:node_id;primaryKey"`
	NodeType   string `gorm:"column:node_type;not null;index:idx_cpn_type"`
	Name       string `gorm:"column:name;not null;default:''"`
	File       string `gorm:"column:file;not null;default:'';index:idx_cpn_file"`
	Line       int    `gorm:"column:line;not null;default:0"`
	Code       string `gorm:"column:code;not null;default:''"`
}

func (cpgNodeModel) TableName() string { return "cpg_nodes" }

type cpgEdgeModel struct {
	ProjectID  string `gorm:"column:project_id;primaryKey;index:idx_cpe_from;index:idx_cpe_to"`
	CPGVersion string `gorm:"column:cpg_version;primaryKey;index:idx_cpe_from;index:idx_cpe_to"`
	FromID     string `gorm:"column:from_id;primaryKey;index:idx_cpe_from"`
	ToID       string `gorm:"column:to_id;primaryKey;index:idx_cpe_to"`
	EdgeType   string `gorm:"column:edge_type;primaryKey;not null;default:CALL"`
}

func (cpgEdgeModel) TableName() string { return "cpg_edges" }

type cpgBuildModel struct {
	ProjectID   string `gorm:"column:project_id;primaryKey"`
	CPGVersion  string `gorm:"column:cpg_version;not null"`
	ChangedHash string `gorm:"column:changed_hash;not null"`
	NodeCount   int    `gorm:"column:node_count;not null;default:0"`
	EdgeCount   int    `gorm:"column:edge_count;not null;default:0"`
	BuiltAt     int64  `gorm:"column:built_at;not null"`
}

func (cpgBuildModel) TableName() string { return "cpg_builds" }

// allModels lists every table for AutoMigrate, in FK-safe creation order
// (referenced tables before their referencing tables).
var allModels = []any{
	&projectModel{},
	&scanRunModel{},
	&findingModel{},
	&ssvcScoreModel{},
	&poeResultModel{},
	&cpgCacheModel{},
	&scanStateModel{},
	&suppressionModel{},
	&workItemModel{},
	&pendingFindingModel{},
	&cpgNodeModel{},
	&cpgEdgeModel{},
	&cpgBuildModel{},
}
