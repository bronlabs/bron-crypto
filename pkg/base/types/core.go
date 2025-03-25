package types

import "io"

type Type string

type PRNG interface {
	io.Reader
	Type() Type
}

type ReseedablePRNG interface {
	PRNG
	Reseed(seed, salt []byte) error
}
