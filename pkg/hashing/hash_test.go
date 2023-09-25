package hashing_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

func TestFiatShamirDeterministic(t *testing.T) {
	a := big.NewInt(1)
	hash, err := hashing.FiatShamirHKDF(sha256.New, a.Bytes())
	fmt.Println("Hex of hash: ", hex.EncodeToString(hash))
	require.NoError(t, err)
	expected, err := hex.DecodeString("327158ed2a14a164dfea5f00233ba81a13e50566e0f6a41552d83c67707c2654")
	require.NoError(t, err)
	require.Equal(t, hash, expected)

	a = big.NewInt(0xaaa)
	hash, err = hashing.FiatShamirHKDF(sha256.New, a.Bytes())
	fmt.Println("Hex of hash: ", hex.EncodeToString(hash))
	require.NoError(t, err)
	expected2, err := hex.DecodeString("a3465a3419c0602ba71852b5a91d59c7a1345b9917db97e4127fb32238549522")
	require.NoError(t, err)
	require.Equal(t, hash, expected2)
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
