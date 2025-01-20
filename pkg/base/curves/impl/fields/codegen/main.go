package main

import (
	_ "embed"
	"fmt"
	"go/types"
	"golang.org/x/tools/go/packages"
	"math/big"
	"os"
	"reflect"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"text/template"
)

//go:embed field.go.tmpl
var fieldTemplate string

type Data struct {
	Type string
}

func main() {
	pkg := mustLoadPackage()
	montgomeryModels := mustLookupMontgomeryFields(pkg)

	tmpl, err := template.New("field").Parse(fieldTemplate)
	if err != nil {
		panic(err)
	}

	for _, montgomeryModel := range montgomeryModels {
		montgomeryModel.Pkg = pkg.Name
		outputFile, err := os.Create(strings.ToLower(montgomeryModel.TypeName) + ".gen.go")
		if err != nil {
			panic(err)
		}
		err = tmpl.Execute(outputFile, montgomeryModel)
		if err != nil {
			panic(err)
		}
		_ = outputFile.Close()
	}
}

func mustLoadPackage() *packages.Package {
	path := os.Args[1]
	if len(path) == 0 {
		panic("code generate must specify a path argument")
	}

	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		panic("could not read build info")
	}

	modulePath := buildInfo.Main.Path
	cfg := &packages.Config{
		Mode: packages.LoadTypes | packages.NeedTypesInfo | packages.NeedTypesSizes,
	}

	pkg, err := packages.Load(cfg, modulePath+"/"+path)
	if err != nil {
		panic(err)
	}
	if len(pkg) != 1 {
		panic("expected exactly one package")
	}

	return pkg[0]
}

func mustLookupMontgomeryFields(pkg *packages.Package) []*montgomeryField {
	var result []*montgomeryField
	for _, v := range pkg.TypesInfo.Defs {
		if v != nil {
			if typeName, ok := v.(*types.TypeName); ok {
				if ty, ok := typeName.Type().Underlying().(*types.Struct); ok {
					fiatField, fiatParams := findTag(ty, "word_by_word_montgomery")
					sqrtTraitField, _ := findTag(ty, "sqrt_trait")
					if fiatField != nil && sqrtTraitField != nil {
						result = append(result, mustComputeMontgomeryFieldParams(typeName, fiatField, fiatParams, sqrtTraitField))
						continue
					}
				}
			}
		}
	}
	return result
}

func findTag(ty *types.Struct, t string) (field *types.Var, params map[string]string) {
	for i := 0; i < ty.NumFields(); i++ {
		f := ty.Field(i)
		rawTag := reflect.StructTag(ty.Tag(i)).Get("fiat")
		tags := strings.Split(rawTag, ",")
		if idx := slices.Index(tags, t); idx >= 0 {
			tags = slices.Delete(tags, idx, idx+1)
			params = make(map[string]string)
			for _, tag := range tags {
				kv := strings.Split(tag, "=")
				params[kv[0]] = kv[1]
			}
			return f, params
		}
	}

	return nil, nil
}

func mustComputeMontgomeryFieldParams(typeName *types.TypeName, fiatField *types.Var, fiatParams map[string]string, sqrtField *types.Var) *montgomeryField {
	fiatTypeName, ok := fiatField.Type().(*types.Named)
	if !ok {
		panic("unsupported fiat type")
	}
	fiatPrefix, ok := strings.CutSuffix(fiatTypeName.Obj().Name(), "MontgomeryDomainFieldElement")
	if !ok {
		panic("unsupported fiat type")
	}
	fiatType, ok := fiatTypeName.Underlying().(*types.Array)
	if !ok {
		panic("unsupported fiat type")
	}
	fiatWordType, ok := fiatType.Elem().(*types.Basic)
	if !ok {
		panic("invalid fiat word type")
	}
	if fiatWordType.Kind() != types.Uint64 {
		panic("unsupported fiat word size")
	}
	orderBig, ok := new(big.Int).SetString(fiatParams["order"], 0)
	if !ok {
		panic("invalid order")
	}
	primitiveElementBig, ok := new(big.Int).SetString(fiatParams["primitive_element"], 0)
	if !ok {
		panic("invalid primitive_element")
	}
	sqrtFieldType, ok := sqrtField.Type().(*types.Named)
	if !ok {
		panic("unsupported sqrt_trait type")
	}

	limbs := fiatType.Len()
	orderM1Big := new(big.Int).Sub(orderBig, big.NewInt(1))
	bitLen := orderM1Big.BitLen()
	e := orderM1Big.TrailingZeroBits()
	rootOfUnityBig := new(big.Int).Exp(primitiveElementBig, new(big.Int).Rsh(orderM1Big, e), orderBig)
	progenitorExponentBig := new(big.Int).Rsh(orderBig, e+1)

	rootOfUnityBytes := make([]byte, 8*(((bitLen-1)/64)+1))
	rootOfUnityBig.FillBytes(rootOfUnityBytes)
	progenitorExponentBytes := progenitorExponentBig.Bytes()
	slices.Reverse(progenitorExponentBytes)

	return &montgomeryField{
		TypeName:           typeName.Name(),
		FiatPkg:            fiatTypeName.Obj().Pkg().Path(),
		FiatPrefix:         fiatPrefix,
		FieldsPkg:          sqrtFieldType.Obj().Pkg().Path(),
		RootOfUnity:        bytesAsHexString(rootOfUnityBytes),
		ProgenitorExponent: bytesAsArray(progenitorExponentBytes),
		E:                  strconv.Itoa(int(e)),
		BitLen:             strconv.Itoa(bitLen),
		Limbs:              strconv.Itoa(int(limbs)),
	}
}

func bytesAsArray(s []byte) string {
	orderString := ""
	for i, b := range s {
		orderString += fmt.Sprintf("0x%02x", b)
		if i < len(s)-1 {
			orderString += ", "
		}
	}
	return orderString
}

func bytesAsHexString(s []byte) string {
	orderString := ""
	for _, b := range s {
		orderString += fmt.Sprintf("%02x", b)
	}
	return orderString
}

type montgomeryField struct {
	Pkg                string
	TypeName           string
	FiatPkg            string
	FieldsPkg          string
	FiatPrefix         string
	E                  string
	Limbs              string
	BitLen             string
	ProgenitorExponent string
	RootOfUnity        string
}
