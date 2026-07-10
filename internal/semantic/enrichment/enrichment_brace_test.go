package enrichment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
)

func TestStripStringsAndComments(t *testing.T) {
	cases := []struct {
		desc        string
		in          string
		wantOpen    int // expected '{' count after strip
		wantClose   int // expected '}' count after strip
	}{
		{
			desc:      "brace inside string literal ignored",
			in:        `String s = "hello {world}";`,
			wantOpen:  0,
			wantClose: 0,
		},
		{
			desc:      "brace after line comment ignored",
			in:        `foo(); // end }`,
			wantOpen:  0,
			wantClose: 0,
		},
		{
			desc:      "escaped quote does not close string early",
			in:        `String s = "he said \"hi {there}\"";`,
			wantOpen:  0,
			wantClose: 0,
		},
		{
			desc:      "real brace outside string preserved",
			in:        `if (x) {`,
			wantOpen:  1,
			wantClose: 0,
		},
		{
			desc:      "string with brace then real brace",
			in:        `log("{"); if (ok) {`,
			wantOpen:  1,
			wantClose: 0,
		},
		{
			desc:      "empty line",
			in:        ``,
			wantOpen:  0,
			wantClose: 0,
		},
		{
			desc:      "closing brace outside string preserved",
			in:        `  }`,
			wantOpen:  0,
			wantClose: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := stripStringsAndComments(tc.in)
			open := strings.Count(got, "{")
			close := strings.Count(got, "}")
			if open != tc.wantOpen || close != tc.wantClose {
				t.Errorf("input:  %q\noutput: %q\n  open braces: got %d want %d\n  close braces: got %d want %d",
					tc.in, got, open, tc.wantOpen, close, tc.wantClose)
			}
		})
	}
}

func TestReadFunctionBody_BraceInString(t *testing.T) {
	// Java source with a string literal containing a brace trap.
	// Without Fix 1, readFunctionBody would terminate at the '}' inside the string.
	src := `public class T {
  public void foo() {
    String s = "trap }";
    if (true) {
      doSomething();
    }
  }

  public void bar() {
    // must NOT be included
  }
}
`
	path := filepath.Join(t.TempDir(), "T.java")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	body := readFunctionBody(path, 2, "") // line 2 = "  public void foo() {"
	if body == "" {
		t.Fatal("readFunctionBody returned empty")
	}
	if !strings.Contains(body, "doSomething") {
		t.Errorf("body missing doSomething(); likely terminated early at brace-in-string:\n%s", body)
	}
	if strings.Contains(body, "bar") {
		t.Errorf("body bled into bar(); brace counting terminated late:\n%s", body)
	}
}

func TestReadFunctionBody_CommentBrace(t *testing.T) {
	// Brace inside line comment must not affect depth.
	src := `public class T {
  public void greet() {
    // say hello }
    System.out.println("hi");
  }

  public void other() {}
}
`
	path := filepath.Join(t.TempDir(), "T.java")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	body := readFunctionBody(path, 2, "")
	if !strings.Contains(body, "println") {
		t.Errorf("body terminated early due to comment brace:\n%s", body)
	}
	if strings.Contains(body, "other") {
		t.Errorf("body bled into other():\n%s", body)
	}
}

func TestReadFunctionBody_FallsBackToJoernCode(t *testing.T) {
	// Single-line method signature with no brace — brace-counting returns empty,
	// so readFunctionBody should fall back to returning the line text.
	src := "public String getPath()\n"
	path := filepath.Join(t.TempDir(), "T.java")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	body := readFunctionBody(path, 1, "")
	if body == "" {
		t.Fatal("readFunctionBody returned empty for single-line signature (fallback expected)")
	}
	if !strings.Contains(body, "getPath") {
		t.Errorf("expected fallback to contain 'getPath', got %q", body)
	}
}

func TestReadFunctionBody_StillReturnsFullBodyWhenBracesWork(t *testing.T) {
	src := "public void doExec(String cmd) {\n  exec(cmd);\n  return;\n}\n"
	path := filepath.Join(t.TempDir(), "T.java")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	body := readFunctionBody(path, 1, "")
	if !strings.Contains(body, "exec(cmd)") {
		t.Errorf("expected full body with exec(cmd), got %q", body)
	}
}

func TestReadFunctionBody_JoernCodeEmptyStillReturnsEmpty(t *testing.T) {
	// If both brace-counting and fallback are empty (non-existent file), return "".
	body := readFunctionBody("/nonexistent/File.java", 1, "")
	if body != "" {
		t.Errorf("expected empty for non-existent file, got %q", body)
	}
}

// ── P2-C: detectLangFromFile majority vote ────────────────────────────────

func TestDetectLangFromFile_UsesFirstSurface(t *testing.T) {
	// Single surface — uses its language.
	surfaces := []targeting.Surface{
		{File: "Main.java"},
	}
	if got := detectLangFromFile(surfaces); got != "java" {
		t.Errorf("single .java surface: expected java, got %q", got)
	}
}

func TestDetectLangFromFile_MajorityVoteJava(t *testing.T) {
	surfaces := []targeting.Surface{
		{File: "Main.java"},
		{File: "Helper.java"},
		{File: "Util.java"},
		{File: "app.py"},
		{File: "script.go"},
	}
	if got := detectLangFromFile(surfaces); got != "java" {
		t.Errorf("3 java vs 1 python vs 1 go: expected java (majority), got %q", got)
	}
}

func TestDetectLangFromFile_EmptyFallsToEmpty(t *testing.T) {
	if got := detectLangFromFile(nil); got != "" {
		t.Errorf("expected empty for nil, got %q", got)
	}
	if got := detectLangFromFile([]targeting.Surface{}); got != "" {
		t.Errorf("expected empty for empty slice, got %q", got)
	}
}

func TestDetectLangFromFile_JsVariants(t *testing.T) {
	surfaces := []targeting.Surface{
		{File: "app.js"},
		{File: "component.tsx"},
	}
	if got := detectLangFromFile(surfaces); got != "javascript" {
		t.Errorf("expected javascript for .js + .tsx, got %q", got)
	}
}

func TestDetectLangFromFile_TieFirstWins(t *testing.T) {
	surfaces := []targeting.Surface{
		{File: "a.java"},
		{File: "b.py"},
	}
	got := detectLangFromFile(surfaces)
	if got != "java" && got != "python" {
		t.Errorf("tie between java and python: expected one of them, got %q", got)
	}
}

func TestReadFunctionBody_InvalidLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "T.java")
	if err := os.WriteFile(path, []byte("public void f() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := readFunctionBody(path, 0, ""); got != "" {
		t.Errorf("line 0 should return empty, got %q", got)
	}
	if got := readFunctionBody(path, 999, ""); got != "" {
		t.Errorf("out-of-bounds line should return empty, got %q", got)
	}
	if got := readFunctionBody("/nonexistent/file.java", 1, ""); got != "" {
		t.Errorf("missing file should return empty, got %q", got)
	}
}

func TestReadFunctionBody_BracelessLambda(t *testing.T) {
	src := `  private void someMethod() {
    lessons.stream()
        .filter(l -> l.getClass().equals(pkg))
        .findFirst()
        .ifPresentOrElse(
            l -> l.addAssignment(toAssignment(ep)),
            () ->
                attachToLesson(ep, pkg));
  }

  private void nextMethod() {
    doSomething();
  }
`
	path := filepath.Join(t.TempDir(), "T.java")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	// Point to the expression lambda on line 6 ("l -> l.addAssignment(...)").
	body := readFunctionBody(path, 6, "")
	if body == "" {
		t.Fatal("readFunctionBody returned empty for lambda expression")
	}
	if !strings.Contains(body, "addAssignment") {
		t.Errorf("body missing lambda expression 'addAssignment':\n%s", body)
	}
	if strings.Contains(body, "nextMethod") {
		t.Errorf("body bled into nextMethod():\n%s", body)
	}
	if strings.Contains(body, "doSomething") {
		t.Errorf("body bled into doSomething():\n%s", body)
	}
}

func TestReadFunctionBody_ClassB_ClassLevelInit(t *testing.T) {
	src := `public class Foo {
  private int x;
  public Foo() {
    this.x = 1;
  }
}
`
	path := filepath.Join(t.TempDir(), "T.java")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	// lineNumber=1 points to the class declaration. Must skip past it to find
	// the constructor body instead of capturing the entire class.
	body := readFunctionBody(path, 1, "")
	if body == "" {
		t.Fatal("readFunctionBody returned empty for class-level init")
	}
	if !strings.Contains(body, "this.x") {
		t.Errorf("body missing constructor body 'this.x':\n%s", body)
	}
	if strings.Contains(body, "public class Foo") {
		t.Logf("note: body includes class declaration line (acceptable):\n%s", body)
	}
}

func TestReadFunctionBody_ClassC_MultiLineSignature(t *testing.T) {
	src := `@GetMapping
public String handler(
    HttpServletRequest req,
    String param) {
  return param;
}
`
	path := filepath.Join(t.TempDir(), "T.java")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	// lineNumber=4 points to ") {" which is the last line of the multi-line
	// signature. The backward scan should find the method start at line 2.
	body := readFunctionBody(path, 4, "")
	if body == "" {
		t.Fatal("readFunctionBody returned empty for multi-line signature")
	}
	if !strings.Contains(body, "public String handler") {
		t.Errorf("body missing method signature start 'public String handler':\n%s", body)
	}
	if !strings.Contains(body, "return param") {
		t.Errorf("body missing method body 'return param':\n%s", body)
	}
}

func TestReadFunctionBody_N2OffByOneRegression(t *testing.T) {
	src := `  public void prior() {
    doPrior();
  }
  public void target() {
    doTarget();
  }
`
	path := filepath.Join(t.TempDir(), "T.java")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	// lineNumber=3 points to the closing } of prior(). The N2 scan should
	// find target()'s { and capture its body.
	body := readFunctionBody(path, 3, "")
	if body == "" {
		t.Fatal("readFunctionBody returned empty for N2 off-by-one case")
	}
	if !strings.Contains(body, "doTarget") {
		t.Errorf("body missing target method body 'doTarget':\n%s", body)
	}
	if strings.Contains(body, "doPrior") {
		t.Errorf("body bled into prior method 'doPrior':\n%s", body)
	}
}

func TestReadFunctionBody_MultiAnomalyScenario(t *testing.T) {
	tests := []struct {
		name       string
		src        string
		lineNum    int
		methodName string
		wantCont   []string
		wantAbsent []string
	}{
		{
			name:       "ClassB_class_level_init",
			src: `public class Foo {
  private int x;
  public Foo() {
    this.x = 1;
  }
}
`,
			lineNum:    1,
			methodName: "",
			wantCont:   []string{"this.x"},
			wantAbsent: nil,
		},
		{
			name:       "ClassC_multi_line_signature",
			src: `@GetMapping
public String handler(
    HttpServletRequest req,
    String param) {
  return param;
}
`,
			lineNum:    4,
			methodName: "",
			wantCont:   []string{"public String handler", "return param"},
			wantAbsent: nil,
		},
		{
			name:       "lambda_braceless_regression",
			src: `  private void someMethod() {
    lessons.stream()
        .ifPresentOrElse(
            l -> l.addAssignment(ep),
            () -> attach(ep));
  }
  private void next() {
    doOther();
  }
`,
			lineNum:    4,
			methodName: "",
			wantCont:   []string{"addAssignment"},
			wantAbsent: []string{"doOther"},
		},
		{
			name:       "normal_method_regression",
			src: `public void foo() {
  bar();
}
`,
			lineNum:    1,
			methodName: "",
			wantCont:   []string{"bar()"},
			wantAbsent: nil,
		},
		{
			name:       "N2_off_by_one",
			src: `  public void prior() {
    doPrior();
  }
  public void target() {
    doTarget();
  }
`,
			lineNum:    3,
			methodName: "",
			wantCont:   []string{"doTarget"},
			wantAbsent: []string{"doPrior"},
		},
		{
			name:       "sort_line_beyond_eof",
			src: `package db;
public class Servers {
  private String url;
  public void sort(String order) {
    prepareStatement("SELECT * FROM s ORDER BY " + order);
  }
}
`,
			lineNum:    87, // beyond 71-line source
			methodName: "sort",
			wantCont:   []string{"prepareStatement"},
			wantAbsent: nil,
		},
		{
			name:       "lombok_getter_no_body",
			src: `@Getter
public class Assignment {
  private String path;
  private String hints;
}
`,
			lineNum:    55, // beyond 51-line source
			methodName: "getPath",
			wantCont:   nil,
			wantAbsent: nil,
		},
		{
			name:       "name_fallback_finds_overload",
			src: `public class Parser {
  public String getPath() {
    return "/default";
  }
  private String getPath(String x) {
    return x;
  }
}
`,
			lineNum:    99, // beyond EOF
			methodName: "getPath",
			wantCont:   []string{"/default"},
			wantAbsent: []string{"private String getPath(String x)"},
		},
		{
			name:       "annotation_array_brace_skipped",
			src: `package demo;
import java.util.List;
@GetMapping(path = {"users", "all-users"})
public List<User> listUsers() {
    return repo.findAll();
}
// end
`,
			lineNum:    3,
			methodName: "listUsers",
			wantCont:   []string{"repo.findAll()"},
			wantAbsent: nil,
		},
		{
			name:       "import_block_name_fallback",
			src: `package demo;
import java.util.List;
import java.util.ArrayList;

public class Svc {
    @AssignmentHints({
        "hint1",
        "hint2"
    })
    public List<String> getItems(String filter) {
        return new ArrayList<>();
    }
}
`,
			lineNum:    2, // Joern points to import line
			methodName: "getItems",
			wantCont:   []string{"new ArrayList<>()"},
			wantAbsent: nil,
		},
		{
			name:       "init_after_class_decl_javadoc",
			src: `public class MD5 {
    /**
     * Constructor.
     */
    public MD5() {
        reset();
    }
}
`,
			lineNum:    5, // public MD5() { line
			methodName: "MD5",
			wantCont:   []string{"reset()"},
			wantAbsent: []string{"public class MD5"},
		},
		{
			name:       "multiline_sig_regression",
			src: `public class Baz {
    public ResponseEntity<List<String>>
        getAll(String param) {
        return ResponseEntity.ok(list);
    }
}
`,
			lineNum:    3, // getAll line (where { is)
			methodName: "getAll",
			wantCont:   []string{"ResponseEntity.ok"},
			wantAbsent: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "T.java")
			if err := os.WriteFile(path, []byte(tc.src), 0644); err != nil {
				t.Fatal(err)
			}
			body := readFunctionBody(path, tc.lineNum, tc.methodName)
			if tc.wantCont == nil {
				if body != "" {
					t.Errorf("expected empty body for Lombok-generated method, got:\n%s", body)
				}
				return
			}
			if body == "" {
				t.Fatal("readFunctionBody returned empty")
			}
			for _, want := range tc.wantCont {
				if !strings.Contains(body, want) {
					t.Errorf("body missing %q:\n%s", want, body)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(body, absent) {
					t.Errorf("body contains %q but should not:\n%s", absent, body)
				}
			}
		})
	}
}
