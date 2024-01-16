package types

type IdentityHash [32]byte

type Incomparable [0]func()

type Hashable interface {
	Hash() [32]byte
}

func Equals(a, b Hashable) bool {
	return a.Hash() == b.Hash()
}
