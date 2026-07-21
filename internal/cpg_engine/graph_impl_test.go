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

import "testing"

func TestIsPhantomTaintPath(t *testing.T) {
	tests := []struct {
		name         string
		sinkName     string
		intermediate []string
		wantPhantom  bool
	}{
		{
			name:         "results_getMetaData_getColumnCount_phantom",
			sinkName:     "results",
			intermediate: []string{"results", "results", "results", "results", "getMetaData"},
			wantPhantom:  true,
		},
		{
			name:         "is_in_read_phantom",
			sinkName:     "is",
			intermediate: []string{"is", "is", "in", "in", "read"},
			wantPhantom:  true,
		},
		{
			name:         "inputStream_FileCopyUtils_phantom",
			sinkName:     "inputStream",
			intermediate: []string{"inputStream", "FileCopyUtils", "copyToByteArray", "getEncoder", "encode"},
			wantPhantom:  true,
		},
		{
			name:         "real_sqli_path",
			sinkName:     "query",
			intermediate: []string{"query", "executeQuery", "stmt"},
			wantPhantom:  false,
		},
		{
			name:         "real_path_traversal",
			sinkName:     "filename",
			intermediate: []string{"filename", "path", "new File"},
			wantPhantom:  false,
		},
		{
			name:         "results_phantom_after_scala_fix",
			sinkName:     "results",
			intermediate: []string{"results", "results", "results", "results", "getMetaData"},
			wantPhantom:  true,
		},
		{
			name:         "empty_sink_internal_chain",
			sinkName:     "",
			intermediate: []string{"results", "results", "results", "results", "getMetaData"},
			wantPhantom:  true,
		},
		{
			name:         "kid_jdbc_metadata_phantom",
			sinkName:     "kid",
			intermediate: []string{"results", "results", "results", "results", "getMetaData", "resultsMetaData", "resultsMetaData", "getColumnCount"},
			wantPhantom:  true,
		},
		{
			name:         "action_getColumnName_phantom",
			sinkName:     "action",
			intermediate: []string{"results", "results", "getMetaData", "getColumnCount", "cols", "col", "i", "getColumnName"},
			wantPhantom:  true,
		},
		{
			name:         "username_FileCopyUtils_phantom",
			sinkName:     "username",
			intermediate: []string{"inputStream", "FileCopyUtils", "copyToByteArray", "getEncoder", "encode", "encodeToString", "toByteArray"},
			wantPhantom:  true,
		},
		{
			name:         "real_short_query_path",
			sinkName:     "query",
			intermediate: []string{"query", "executeQuery", "stmt"},
			wantPhantom:  false,
		},
		{
			name:         "real_path_traversal_file",
			sinkName:     "file",
			intermediate: []string{"file", "path", "filename", "new File", "canWrite"},
			wantPhantom:  false,
		},
		{
			name:         "real_sqli_short_kid",
			sinkName:     "kid",
			intermediate: []string{"kid", "query", "executeQuery"},
			wantPhantom:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := joernFlow{
				Sink: joernNode{Name: tt.sinkName},
			}
			for _, n := range tt.intermediate {
				f.Intermediate = append(f.Intermediate, joernNode{Name: n})
			}
			got := isPhantomTaintPath(f)
			if got != tt.wantPhantom {
				t.Errorf("isPhantomTaintPath(sink=%q, intermediates=%v) = %v, want %v",
					tt.sinkName, tt.intermediate, got, tt.wantPhantom)
			}
		})
	}
}
