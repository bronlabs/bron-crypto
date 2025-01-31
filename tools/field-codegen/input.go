package main

import (
	"flag"
	"os"
)

func ReadInput() (mode Mode, goPackage, goFile, goType, modulus, sqrtFunc string) {
	modeFlag := flag.String("mode", "", "word-by-word-montgomery or unsaturated-solinas")
	modulusFlag := flag.String("modulus", "", "the order of the field (must be prime)")
	sqrtFuncFlag := flag.String("sqrt", "", "square root function")
	goTypeFlag := flag.String("type", "", "the name of type to be generated")
	flag.Parse()

	mode = Mode(*modeFlag)
	if mode != MontgomeryMode && mode != SolinasMode {
		panic("invalid mode")
	}

	goPackage = os.Getenv("GOPACKAGE")
	if goPackage == "" {
		panic("GOPACKAGE environment variable not set")
	}

	goFile = os.Getenv("GOFILE")
	if goFile == "" {
		panic("GOFILE environment variable not set")
	}

	return mode, goPackage, goFile, *goTypeFlag, *modulusFlag, *sqrtFuncFlag
}
