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

package proxy
import (
	"io"
	"net/http"
	"net/url"
)
var allowed = map[string]struct{}{"api.internal.corp": {}}
func Fetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	u, err := url.Parse(target)
	if err != nil {
		http.Error(w, "bad url", http.StatusBadRequest)
		return
	}
	if _, ok := allowed[u.Hostname()]; !ok {
		http.Error(w, "blocked", http.StatusForbidden)
		return
	}
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
