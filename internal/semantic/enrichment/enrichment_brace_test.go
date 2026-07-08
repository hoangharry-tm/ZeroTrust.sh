package enrichment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

	body := readFunctionBody(path, 2) // line 2 = "  public void foo() {"
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

	body := readFunctionBody(path, 2)
	if !strings.Contains(body, "println") {
		t.Errorf("body terminated early due to comment brace:\n%s", body)
	}
	if strings.Contains(body, "other") {
		t.Errorf("body bled into other():\n%s", body)
	}
}

func TestReadFunctionBody_InvalidLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "T.java")
	if err := os.WriteFile(path, []byte("public void f() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := readFunctionBody(path, 0); got != "" {
		t.Errorf("line 0 should return empty, got %q", got)
	}
	if got := readFunctionBody(path, 999); got != "" {
		t.Errorf("out-of-bounds line should return empty, got %q", got)
	}
	if got := readFunctionBody("/nonexistent/file.java", 1); got != "" {
		t.Errorf("missing file should return empty, got %q", got)
	}
}
