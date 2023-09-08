package hashing_test

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton/pkg/hashing"
)

func TestFiatShamirDeterministic(t *testing.T) {
	a := big.NewInt(1)
	hash, err := hashing.FiatShamirHKDF(sha256.New, a.Bytes())
	require.Nil(t, err)
	require.Equal(t, hash, []byte{0x98, 0x9b, 0x9f, 0xa3, 0x49, 0x73, 0xbe, 0x9f, 0xce, 0x97, 0x62, 0xf, 0x6d, 0xc9, 0xe, 0x22, 0x77, 0x47, 0x7c, 0xdb, 0x81, 0x29, 0x62, 0x6f, 0xf1, 0xbd, 0xf5, 0x84, 0x9e, 0xa4, 0xb8, 0x55})

	a = big.NewInt(0xaaa)
	hash, err = hashing.FiatShamirHKDF(sha256.New, a.Bytes())
	require.Nil(t, err)
	require.Equal(t, hash, []byte{0x33, 0x40, 0xfe, 0x30, 0x95, 0x6f, 0x5f, 0xa6, 0xc4, 0x19, 0x78, 0x9c, 0x28, 0x1e, 0x41, 0x41, 0x8c, 0x7d, 0xed, 0x8f, 0xff, 0x9f, 0x93, 0x19, 0x37, 0x40, 0x1, 0xf8, 0xc3, 0x7a, 0x1, 0x56})
}

func TestFiatShamirEqual(t *testing.T) {
	a := big.NewInt(1)
	pi, err := hashing.FiatShamirHKDF(sha256.New, a.Bytes())
	require.Nil(t, err)
	pi_, err := hashing.FiatShamirHKDF(sha256.New, a.Bytes())
	require.Nil(t, err)
	require.Equal(t, pi, pi_)
}

func TestFiatShamirNotEqual(t *testing.T) {
	a := big.NewInt(1)
	pi, err := hashing.FiatShamirHKDF(sha256.New, a.Bytes())
	require.Nil(t, err)
	b := big.NewInt(2)
	pi_, err := hashing.FiatShamirHKDF(sha256.New, b.Bytes())
	require.Nil(t, err)
	require.NotEqual(t, pi, pi_)
}

func TestFiatShamirOrderDependent(t *testing.T) {
	a := big.NewInt(1)
	b := big.NewInt(100)

	pi, err := hashing.FiatShamirHKDF(sha256.New, a.Bytes(), b.Bytes())
	require.Nil(t, err)
	pi_, err := hashing.FiatShamirHKDF(sha256.New, a.Bytes(), b.Bytes())
	require.Nil(t, err)
	require.Equal(t, pi, pi_)

	q, _ := hashing.FiatShamirHKDF(sha256.New, b.Bytes(), a.Bytes())
	require.NotEqual(t, pi, q)
}

func TestFiatShamirExtensionAttackResistance(t *testing.T) {
	a := big.NewInt(0x00FF)
	b := big.NewInt(0xFF00)

	c := big.NewInt(0x00)
	d := big.NewInt(0xFFFF00)

	pi, err := hashing.FiatShamirHKDF(sha256.New, a.Bytes(), b.Bytes())
	require.Nil(t, err)
	pi_, err := hashing.FiatShamirHKDF(sha256.New, c.Bytes(), d.Bytes())
	require.Nil(t, err)
	require.NotEqual(t, pi, pi_)

	a = big.NewInt(0x0000)
	b = big.NewInt(0xFFFF)

	c = big.NewInt(0x0000F)
	d = big.NewInt(0xFFF)

	q, err := hashing.FiatShamirHKDF(sha256.New, a.Bytes(), b.Bytes())
	require.Nil(t, err)
	q_, err := hashing.FiatShamirHKDF(sha256.New, c.Bytes(), d.Bytes())
	require.Nil(t, err)
	require.NotEqual(t, q, q_)
}
