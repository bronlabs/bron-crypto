package main

import (
	_ "embed"
	"flag"
	"fmt"
	"math/bits"
	"os"
	"text/template"
)

const GenGoExt = ".gen.go"

//go:embed secparams.go.tmpl
var templateString string

type data struct {
	Bits          uint
	StatBits      uint
	Log2Floor     int
	Log2Ceil      int
	BytesCeil     uint
	StatBytesCeil uint
	CRBytesCeil   uint
	H2CTag        string
}

func main() {
	var (
		bitsVal  uint
		statBits uint
		h2cTag   string
	)

	flag.UintVar(&bitsVal, "bits", 128, "computational security in bits (>= 2)")
	flag.UintVar(&statBits, "stat", 80, "statistical security in bits (>= 0)")
	flag.StringVar(&h2cTag, "h2c", "bron_crypto_hash2curve-", "hash-to-curve application tag")
	flag.Parse()

	if bitsVal%2 != 0 {
		fail("-bits must be even")
	}
	if statBits%2 != 0 {
		fail("-stat must be even")
	}
	if bitsVal < 128 {
		fail("-bits must be at least 128")
	}
	if statBits < 80 {
		fail("-stat must be at least 80")
	}

	d := data{
		Bits:          bitsVal,
		StatBits:      statBits,
		Log2Floor:     log2Floor(bitsVal),
		Log2Ceil:      log2Ceil(bitsVal),
		BytesCeil:     bytesCeil(bitsVal),
		CRBytesCeil:   bytesCeil(2 * bitsVal),
		StatBytesCeil: bytesCeil(statBits),
		H2CTag:        h2cTag,
	}

	out := "constants" + GenGoExt

	tpl, err := template.New("secparams").Parse(templateString)
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
