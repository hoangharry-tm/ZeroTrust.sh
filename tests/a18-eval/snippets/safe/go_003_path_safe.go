// Copyright 2026 hoangharry-tm
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

package files
import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)
const base = "/var/static"
func ServeFile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	full := filepath.Join(base, filepath.Clean("/"+name))
	if !strings.HasPrefix(full, base) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	data, err := os.ReadFile(full)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Write(data)
}
var _ = errors.New // suppress import error in stub
