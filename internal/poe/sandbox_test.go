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

package poe

import (
	"os"
	"testing"
)

func TestStageSeccompProfile_WritesEmbeddedContent(t *testing.T) {
	path, err := stageSeccompProfile()
	if err != nil {
		t.Fatalf("stageSeccompProfile: %v", err)
	}
	defer os.Remove(path)

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	if string(got) != string(seccompProfile) {
		t.Errorf("staged content does not match embedded seccompProfile")
	}
}

func TestStageSeccompProfile_EachCallGetsItsOwnFile(t *testing.T) {
	p1, err := stageSeccompProfile()
	if err != nil {
		t.Fatalf("stageSeccompProfile: %v", err)
	}
	defer os.Remove(p1)

	p2, err := stageSeccompProfile()
	if err != nil {
		t.Fatalf("stageSeccompProfile: %v", err)
	}
	defer os.Remove(p2)

	if p1 == p2 {
		t.Errorf("expected distinct staged paths for concurrent scans, got the same path twice: %q", p1)
	}
}
