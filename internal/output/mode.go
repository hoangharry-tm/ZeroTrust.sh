package output

import (
	"os"

	"github.com/mattn/go-isatty"
)

// IsTTY reports whether os.Stdout is an interactive terminal.
func IsTTY() bool {
	return isatty.IsTerminal(os.Stdout.Fd())
}
