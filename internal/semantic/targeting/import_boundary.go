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

// Package targeting: import boundary analysis.
//
// Classifies source files by the package categories they import, without
// inspecting method names. Works for any HTTP framework because even custom
// frameworks must eventually import a canonical networking/IO package.
//
// Classification is purely structural: a file is a source boundary if it
// imports an HTTP/IO package; a sink boundary if it imports a DB/exec/fs
// package; an auth boundary if it imports an auth/session package.

package targeting

import (
	"bufio"
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// BoundaryKind is a bitmask classifying the role of a source file's imports.
// Multiple bits may be set (e.g. a controller that also talks to a DB).
type BoundaryKind uint8

const (
	BoundaryNone   BoundaryKind = 0
	BoundarySource BoundaryKind = 1 << iota // imports HTTP / external-input packages
	BoundarySink                            // imports DB / exec / filesystem packages
	BoundaryAuth                            // imports auth / session / JWT packages
	BoundaryStorage                         // imports DB/cache/file-write packages (persistence)
)

// FileClass holds the boundary classification for one source file.
type FileClass struct {
	Path  string
	Bound BoundaryKind
}

// sourcePkgPrefixes lists import substrings whose presence marks a file as
// receiving external input. Keyed by file extension.
//
// Custom frameworks built on top of these packages will import them
// (directly or transitively), so their application-layer files inherit
// BoundarySource through the import graph even when the custom wrapper
// is an external dependency.
var sourcePkgPrefixes = map[string][]string{
	".java": {
		"javax.servlet", "jakarta.servlet",
		"org.springframework.web",
		"javax.ws.rs", "jakarta.ws.rs",
		"io.javalin", "io.vertx.web",
		"io.micronaut.http", "io.quarkus.vertx.http",
		"ratpack.handling",
	},
	".py": {
		"flask", "django.http", "django.views", "django.shortcuts",
		"fastapi", "aiohttp.web", "tornado.web",
		"starlette", "bottle", "falcon", "quart", "sanic",
		"litestar",
	},
	".go": {
		`"net/http"`,
		`"github.com/gin-gonic/gin"`,
		`"github.com/labstack/echo"`,
		`"github.com/gofiber/fiber"`,
		`"github.com/gorilla/mux"`,
		`"github.com/julienschmidt/httprouter"`,
		`"github.com/go-chi/chi"`,
		`"github.com/valyala/fasthttp"`,
	},
}

// sinkPkgPrefixes lists import substrings whose presence marks a file as
// performing a privileged operation (DB read/write, OS exec, filesystem write).
var sinkPkgPrefixes = map[string][]string{
	".java": {
		"java.sql", "javax.sql", "jakarta.persistence",
		"org.springframework.data", "org.springframework.jdbc",
		"org.hibernate", "com.mongodb",
		"java.io.File", "java.nio.file",
		"java.lang.Runtime", "java.lang.ProcessBuilder",
		"org.springframework.ldap",
	},
	".py": {
		"sqlite3", "psycopg2", "pymysql", "sqlalchemy",
		"django.db", "pymongo", "redis", "motor", "aiomysql",
		"subprocess", "paramiko", "fabric",
		// "os" is intentionally omitted — nearly every file imports os.
		// We catch exec sinks via subprocess.
	},
	".go": {
		`"database/sql"`,
		`"gorm.io/gorm"`,
		`"go.mongodb.org/mongo-driver"`,
		`"github.com/jmoiron/sqlx"`,
		`"os/exec"`,
		`"github.com/go-redis/redis"`,
		`"github.com/redis/go-redis"`,
	},
}

// authPkgPrefixes lists import substrings whose presence marks a file as
// containing auth / session / identity-check logic.
var authPkgPrefixes = map[string][]string{
	".java": {
		"org.springframework.security",
		"javax.servlet.http.HttpSession",
		"jakarta.servlet.http.HttpSession",
		"io.jsonwebtoken",
		"org.keycloak",
		"com.auth0",
		"io.micronaut.security",
	},
	".py": {
		"flask_login", "flask_jwt", "flask_jwt_extended",
		"django.contrib.auth",
		"fastapi_users", "fastapi.security",
		"jose", "jwt", "authlib",
		"itsdangerous",
	},
	".go": {
		`"github.com/golang-jwt/jwt"`,
		`"github.com/dgrijalva/jwt-go"`,
		`"github.com/lestrrat-go/jwx"`,
		`"golang.org/x/oauth2"`,
		`"github.com/casbin/casbin"`,
	},
}

// storagePkgPrefixes lists import substrings whose presence marks a file as
// performing persistence writes (DB, cache, file writes).
var storagePkgPrefixes = map[string][]string{
	".java": {
		"org.springframework.data",
		"org.hibernate",
		"javax.persistence",
		"jakarta.persistence",
		"redis.clients",
		"com.google.cloud.storage",
		"software.amazon.awssdk.services.s3",
	},
	".py": {
		"sqlalchemy", "django.db",
		"pymongo", "motor",
		"redis", "aioredis",
		"boto3", "botocore",
	},
	".go": {
		`"database/sql"`,
		`"go.mongodb.org/mongo-driver"`,
		`"github.com/go-redis/redis"`,
		`"gorm.io/gorm"`,
		`"github.com/jackc/pgx"`,
		`"github.com/lib/pq"`,
	},
}

// skipDirs are directory name substrings that are always excluded from the walk.
var skipDirs = []string{
	"vendor", "node_modules", ".git",
	"target", "build", "dist", "__pycache__",
	".gradle", ".mvn",
	"test", "tests", "it", // skip test source trees (src/test/java, src/it/java)
}

// classifyFile reads up to maxImportLines lines of path and returns the OR of
// all boundary kinds whose package prefixes appear in the import block.
// Returns BoundaryNone on unsupported extensions or unreadable files.
func classifyFile(path string) BoundaryKind {
	ext := filepath.Ext(path)
	srcs := sourcePkgPrefixes[ext]
	sinks := sinkPkgPrefixes[ext]
	auths := authPkgPrefixes[ext]
	storage := storagePkgPrefixes[ext]
	if len(srcs)+len(sinks)+len(auths)+len(storage) == 0 {
		return BoundaryNone
	}

	f, err := os.Open(path)
	if err != nil {
		return BoundaryNone
	}
	defer f.Close()

	const maxImportLines = 250 // imports are always near the top
	var bound BoundaryKind
	all := BoundarySource | BoundarySink | BoundaryAuth | BoundaryStorage

	scanner := bufio.NewScanner(f)
	n := 0
	for scanner.Scan() && n < maxImportLines {
		n++
		line := scanner.Text()
		for _, p := range srcs {
			if strings.Contains(line, p) {
				bound |= BoundarySource
			}
		}
		for _, p := range sinks {
			if strings.Contains(line, p) {
				bound |= BoundarySink
			}
		}
		for _, p := range auths {
			if strings.Contains(line, p) {
				bound |= BoundaryAuth
			}
		}
		for _, p := range storage {
			if strings.Contains(line, p) {
				bound |= BoundaryStorage
			}
		}
		if bound == all {
			break // found everything, stop early
		}
	}
	return bound
}

// AnalyzeImports walks root and returns the boundary classification for every
// source file that imports at least one recognised package.
// Files in vendor/build/test directories are skipped.
// Returns a map keyed by absolute file path.
func AnalyzeImports(ctx context.Context, root string) (map[string]FileClass, error) {
	result := make(map[string]FileClass)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // soft — skip unreadable entries
		}
		if d.IsDir() {
			name := d.Name()
			for _, skip := range skipDirs {
				if strings.EqualFold(name, skip) {
					return filepath.SkipDir
				}
			}
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		ext := filepath.Ext(path)
		if ext != ".java" && ext != ".py" && ext != ".go" {
			return nil
		}

		bound := classifyFile(path)
		if bound != BoundaryNone {
			result[path] = FileClass{Path: path, Bound: bound}
		}
		return nil
	})
	if err != nil {
		return result, err
	}

	slog.Debug("import_boundary: analysis complete",
		slog.String("root", root),
		slog.Int("boundary_files", len(result)))
	return result, nil
}
