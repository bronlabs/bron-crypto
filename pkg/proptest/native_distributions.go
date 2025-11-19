package proptest

import (
	"io"
	"math/rand/v2"
	"slices"
)

type Alphabet []rune

var (
	Alphabetical Alphabet = []rune{
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	}
	Numerical    Alphabet = []rune{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}
	AlphaNumeric Alphabet = slices.Concat(Alphabetical, Numerical)
)

func NewRuneDistribution(alphabet Alphabet) Distribution[rune] {
	return &runes{
		alphabet,
	}
}

type runes struct {
	alphabet Alphabet
}

func (r *runes) Draw() rune {
	idx := rand.N(len(r.alphabet))
	return r.alphabet[idx]
}

func NewStringsDistribution(alphabet Alphabet, length int) Distribution[string] {
	return &strings{
		alphabet,
		length,
	}
}

type strings struct {
	alphabet Alphabet
	length   int
}

func (s *strings) Draw() string {
	d := &repeated[rune]{
		NewRuneDistribution(s.alphabet),
		s.length,
	}
	return string(d.Draw())
}

func NewBytesDistribution(length int, rng io.Reader) Distribution[[]byte] {
	return &bytes{
		length,
		rng,
	}
}

type bytes struct {
	length int
	rng    io.Reader
}

func (b *bytes) Draw() []byte {
	result := make([]byte, b.length)
	_, err := io.ReadFull(b.rng, result)
	if err != nil {
		panic("unable to read random bytes: " + err.Error())
	}
	return result
}
