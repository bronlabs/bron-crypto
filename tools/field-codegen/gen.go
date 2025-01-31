package main

import (
	_ "embed"
	"encoding/hex"
	"fmt"
	addChainAst "github.com/mmcloughlin/addchain/acc/ast"
	"math/big"
	"os"
	"reflect"
	"slices"
	"strconv"
	"text/template"
)

//go:embed field.go.tmpl
var fieldTemplateString string

func GenerateFieldType(goPackage, fileName, goType, sqrtCall string, e, limbs, bitLen uint64, rootOfUnity, progenitorExp, modulus *big.Int) {
	type fieldModel struct {
		Pkg                string
		TypeName           string
		FiatPkg            string
		SqrtCall           string
		FiatPrefix         string
		Modulus            string
		E                  string
		Limbs              string
		BitLen             string
		ProgenitorExponent string
		RootOfUnity        string
		InvChain           *addChainAst.Chain
	}

	tmpl := template.Must(template.New(goType).
		Funcs(map[string]any{
			"exprType": func(expr addChainAst.Expr) string {
				return reflect.TypeOf(expr).Name()
			},
			"args": func(values ...any) (map[string]any, error) {
				if len(values)%2 != 0 {
					panic("args must be even")
				}
				dict := make(map[string]interface{}, len(values)/2)
				for i := 0; i < len(values); i += 2 {
					key, ok := values[i].(string)
					if !ok {
						panic("dict keys must be strings")
					}
					dict[key] = values[i+1]
				}
				return dict, nil
			},
		}).
		Parse(fieldTemplateString),
	)

	outFile := Must(os.Create(fileName))
	defer outFile.Close()

	rouBytes := make([]byte, 8*(((bitLen-1)/64)+1))
	rootOfUnity.FillBytes(rouBytes)

	Must0(tmpl.Execute(outFile, fieldModel{
		Pkg:                goPackage,
		TypeName:           goType,
		SqrtCall:           sqrtCall,
		FiatPrefix:         FiatPrefix + goType,
		Modulus:            biToArray(modulus),
		E:                  strconv.Itoa(int(e)),
		Limbs:              strconv.Itoa(int(limbs)),
		BitLen:             strconv.Itoa(int(bitLen)),
		ProgenitorExponent: biToArray(progenitorExp),
		RootOfUnity:        hex.EncodeToString(rouBytes),
	}))
}

func biToArray(bi *big.Int) string {
	biBytes := bi.Bytes()
	slices.Reverse(biBytes)

	result := ""
	for i, b := range biBytes {
		result += fmt.Sprintf("0x%02x", b)
		if i != len(biBytes)-1 {
			result += ", "
		}
	}
	return result
}
