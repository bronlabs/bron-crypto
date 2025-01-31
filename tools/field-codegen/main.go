package main

import (
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"math/big"
)

const (
	MontgomeryElementSuffix = "MontgomeryDomainFieldElement"
	GenGoExt                = ".gen.go"
	FiatFilePrefix          = "fiat_"
	FiatPrefix              = "fiat"
)

type Mode string

const (
	MontgomeryMode Mode = "word-by-word-montgomery"
	SolinasMode    Mode = "unsaturated-solinas"
)

func main() {
	mode, goPackage, _, goType, modulus, sqrtFunc := ReadInput()
	if mode != MontgomeryMode {
		panic("only montgomery mode is supported (yet)")
	}

	fiatFileName := GenerateFiat(goPackage, goType, modulus)
	fiatElementType := FiatPrefix + goType + MontgomeryElementSuffix
	fieldLimbs := FindLimbCount(goPackage, fiatFileName, fiatElementType)

	fieldRootOfUnity, fieldModulus := ComputeRootOfUnity(modulus)
	fieldBits := new(big.Int).Sub(fieldModulus, big.NewInt(1)).BitLen()
	fieldE := uint64(new(big.Int).Sub(fieldModulus, big.NewInt(1)).TrailingZeroBits())
	fieldProgenitorExp := new(big.Int).Rsh(fieldModulus, uint(fieldE+1))

	fieldFileName := cases.Lower(language.English).String(goType) + GenGoExt
	GenerateFieldType(goPackage, fieldFileName, goType, sqrtFunc, fieldE, fieldLimbs, uint64(fieldBits), fieldRootOfUnity, fieldProgenitorExp, fieldModulus)
}
