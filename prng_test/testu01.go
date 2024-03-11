package main


// #cgo CFLAGS: -std=c99 -O3 -Wall -I${SRCDIR}/testu01/dist/include
// #cgo LDFLAGS: -L${SRCDIR}/testu01/dist/lib -ltestu01 -lprobdist -lmylib -lm -lc
// #include <stdlib.h>
// #include "TestU01.h"
// typedef unsigned int (*RandomGeneratorType)(void);
// extern uint32_t GoCryptoRand(void);
// extern uint32_t GoCryptoRandReverse(void);
import "C"
import (
	"encoding/binary"
	"io"
	"math/bits"
	"unsafe"
)

var prng io.Reader

//export GoCryptoRand
func GoCryptoRand() uint32 {
	var out uint32
	if prng == nil {
		panic("prng is nil")
	}
	err := binary.Read(prng, binary.LittleEndian, &out)
	if err != nil {
		panic(err)
	}
	return out
}

//export GoCryptoRandReverse
func GoCryptoRandReverse() uint32 {
	var out uint32
	if prng == nil {
		panic("prng is nil")
	}
	err := binary.Read(prng, binary.LittleEndian, &out)
	if err != nil {
		panic(err)
	}
	return bits.Reverse32(out)
}

type PrngTest interface {
	GetPrng() (io.Reader, error)
}

func RunPrngTest(prngTest PrngTest) {
	p, err := prngTest.GetPrng()
	if err != nil {
		panic(err)
	}
	prng = p // we can't directly pass prng to C, so we store it in a global variable
	goCryptoRandNameLittleEndian := C.CString("GoCryptoRand")
	defer C.free(unsafe.Pointer(goCryptoRandNameLittleEndian))
	goCryptoRandGenLittleEndian := C.unif01_CreateExternGenBits(goCryptoRandNameLittleEndian, C.RandomGeneratorType(C.GoCryptoRand))
	C.bbattery_SmallCrush(goCryptoRandGenLittleEndian)
	C.unif01_DeleteExternGenBits(goCryptoRandGenLittleEndian)

	goCryptoRandNameBigEndian := C.CString("GoCryptoRandReverse")
	defer C.free(unsafe.Pointer(goCryptoRandNameBigEndian))
	goCryptoRandGenBigEndian := C.unif01_CreateExternGenBits(goCryptoRandNameBigEndian, C.RandomGeneratorType(C.GoCryptoRandReverse))
	C.bbattery_SmallCrush(goCryptoRandGenBigEndian)
	C.unif01_DeleteExternGenBits(goCryptoRandGenBigEndian)
}
