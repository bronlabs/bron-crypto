package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"text/template"
)

const tmpl = `//nolint:depguard,wrapcheck,gci,gofmt // we want to use pkg/errors only here, but nowhere else
package errs

import (
	"fmt"
	"github.com/pkg/errors"
)

{{ range . }}
func New{{ . }}(format string, args ...any) error {
    return errors.Errorf("%s %s", {{ . }}, fmt.Sprintf(format, args...))
}

func Wrap{{ . }}(err error, format string, args ...any) error {
    return errors.Wrapf(err, "%s %s", {{ . }}, fmt.Sprintf(format, args...))
}

func Is{{ . }}(err error) bool {
    return Is(err, {{ . }})
}

func Has{{ . }}(err error) bool {
    return Has(err, {{ . }})
}
{{ end }}`

func main() {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "errors.go", nil, parser.ParseComments)
	if err != nil {
		panic(err)
	}

	var errorTypes []string
	ast.Inspect(f, func(n ast.Node) bool {
		v, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for _, name := range v.Names {
			if name.Name != "TotalAbort" && name.Name != "IdentifiableAbort" {
				errorTypes = append(errorTypes, name.Name)
			}
		}
		return true
	})

	file, err := os.Create("error_functions.gen.go")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	t := template.Must(template.New("tmpl").Parse(tmpl))
	t.Execute(file, errorTypes)
}
