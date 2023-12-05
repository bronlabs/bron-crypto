package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"text/template"
)

const tmpl = `//nolint:nolintlint,gci,gofmt // we want to use pkg/errors only here, but nowhere else
package errs

var knownErrors = []ErrorType{
    {{- range . }}
    {{ . }},
    {{- end }}
}
`

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
			errorTypes = append(errorTypes, name.Name)
		}
		return true
	})

	file, err := os.Create("known_errors.gen.go")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	t := template.Must(template.New("tmpl").Parse(tmpl))
	t.Execute(file, errorTypes)
}
