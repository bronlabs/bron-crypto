package main

// #cgo darwin,arm64 CFLAGS: -std=c99 -O3 -Wall -I${SRCDIR}/testu01/darwin/arm64/include
// #cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/testu01/darwin/arm64/lib -ltestu01 -lprobdist -lmylib -lm -lc
// #cgo linux,amd64 CFLAGS: -std=c99 -O3 -Wall -I${SRCDIR}/testu01/linux/amd64/include
// #cgo linux,amd64 LDFLAGS: -L${SRCDIR}/testu01/linux/amd64/lib -ltestu01 -lprobdist -lmylib -lm -lc
// #include <stdlib.h>
// #include "TestU01.h"
// typedef unsigned int (*RandomGeneratorType)(void);
// extern uint32_t GoCryptoRand(void);
// extern uint32_t GoCryptoRandReverse(void);
import "C"
import (
	crand "crypto/rand"
	"encoding/binary"
	"math/bits"
	"unsafe"
)

//export GoCryptoRand
func GoCryptoRand() uint32 {
	var out uint32
	err := binary.Read(crand.Reader, binary.LittleEndian, &out)
	if err != nil {
		panic(err)
	}
	return out
}

//export GoCryptoRandReverse
func GoCryptoRandReverse() uint32 {
	var out uint32
	err := binary.Read(crand.Reader, binary.LittleEndian, &out)
	if err != nil {
		panic(err)
	}
	return bits.Reverse32(out)
}

func main() {
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
