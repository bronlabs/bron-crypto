package main

import (
	_ "embed"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/bits"
	"os"
	"path/filepath"
	"strconv"
	"text/template"
)

const GenGoExt = ".gen.go"

//go:embed secparams.go.tmpl
var templateString string

type data struct {
	ComputationalBits      uint
	ComputationalLog2Ceil  int
	ComputationalBytesCeil uint

	StatisticalBits      uint
	StatisticalLog2Ceil  int
	StatisticalBytesCeil uint

	CollisionBytesCeil uint
}

func main() {
	// Get the package directory from working directory
	wd, err := os.Getwd()
	if err != nil {
		fail("get working directory: %v", err)
	}

	// Read constants from constants.go
	constantsFile := filepath.Join(wd, "constants.go")
	constants, err := readConstants(constantsFile)
	if err != nil {
		fail("read constants: %v", err)
	}

	// Extract values
	compBits, ok := constants["ComputationalSecurityBits"]
	if !ok {
		fail("ComputationalSecurityBits not found in constants.go")
	}

	statBits, ok := constants["StatisticalSecurityBits"]
	if !ok {
		fail("StatisticalSecurityBits not found in constants.go")
	}

	// Validate values
	if compBits%8 != 0 {
		fail("ComputationalSecurityBits must be multiple of 8")
	}
	if statBits%8 != 0 {
		fail("StatisticalSecurityBits must be multiple of 8")
	}
	if compBits < 128 {
		fail("ComputationalSecurityBits must be at least 128")
	}
	if statBits < 80 {
		fail("StatisticalSecurityBits must be at least 80")
	}

	d := data{
		ComputationalBits:      compBits,
		ComputationalLog2Ceil:  log2Ceil(compBits),
		ComputationalBytesCeil: bytesCeil(compBits),
		StatisticalBits:        statBits,
		StatisticalLog2Ceil:    log2Ceil(statBits),
		StatisticalBytesCeil:   bytesCeil(statBits),
		CollisionBytesCeil:     bytesCeil(2 * compBits),
	}

	out := filepath.Join(wd, "constants.gen.go")

	tpl, err := template.New("constants").Parse(templateString)
	if err != nil {
		fail("parse template: %v", err)
	}

	f, err := os.Create(out)
	if err != nil {
		fail("create output: %v", err)
	}
	defer f.Close()

	if err := tpl.Execute(f, d); err != nil {
		fail("execute template: %v", err)
	}

	// Generate Miller-Rabin iterations using sage
	fmt.Println("Computing Miller-Rabin iterations from FIPS 186-5...")
	sageScriptPath := filepath.Join(wd, "nt", "fips1865c.sage")
	iterations, err := computeMillerRabinIterations(sageScriptPath, statBits)
	if err != nil {
		fail("compute Miller-Rabin iterations: %v", err)
	}

	if err := generateMillerRabinCode(wd, iterations); err != nil {
		fail("generate Miller-Rabin code: %v", err)
	}
	fmt.Println("Generated nt/millerrabin.gen.go")
}

// readConstants parses constants.go and extracts const values
func readConstants(filename string) (map[string]uint, error) {
	src, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, err
	}

	constants := make(map[string]uint)

	// Walk through all declarations
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			continue
		}

		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}

			for i, name := range valueSpec.Names {
				if i < len(valueSpec.Values) {
					if val := extractIntValue(valueSpec.Values[i], constants); val != nil {
						constants[name.Name] = *val
					}
				}
			}
		}
	}

	return constants, nil
}

// extractIntValue extracts integer value from an expression
func extractIntValue(expr ast.Expr, constants map[string]uint) *uint {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.INT {
			val, err := strconv.ParseUint(e.Value, 0, 64)
			if err == nil {
				v := uint(val)
				return &v
			}
		}
	case *ast.BinaryExpr:
		// Handle expressions like 2 * ComputationalSecurityBits
		left := extractIntValue(e.X, constants)
		right := extractIntValue(e.Y, constants)
		if left != nil && right != nil {
			switch e.Op {
			case token.MUL:
				v := *left * *right
				return &v
			case token.ADD:
				v := *left + *right
				return &v
			}
		}
	case *ast.Ident:
		// Reference to another constant
		if val, ok := constants[e.Name]; ok {
			return &val
		}
	}
	return nil
}

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(2)
}

func log2Floor(n uint) int {
	return bits.Len(n) - 1
}

func log2Ceil(n uint) int {
	lc := log2Floor(n)
	if n != 1<<uint(lc) {
		lc++
	}
	return lc
}

func bytesCeil(n uint) uint {
	return (n + 7) / 8
}
