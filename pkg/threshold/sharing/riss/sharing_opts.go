package riss

import (
	"math/big"
)

var (
	_ SharingOpts = (*sharingOpts)(nil)
)

type SharingOpts interface {
	GetBitLen() uint
	GetModulus() *big.Int
	IsSpecialForm() bool
	GetRange() (low, high *big.Int)
}

type sharingOpts struct {
	bitLen      uint
	modulus     *big.Int
	specialForm bool
	rangeLow    *big.Int
	rangeHigh   *big.Int
}

func NewSharingOpts(opts ...SharingOpt) SharingOpts {
	var so sharingOpts
	for _, opt := range opts {
		opt(&so)
	}

	return &so
}

func NewPseudoRandomSharingOpts(opts ...SharingOpt) SharingOpts {
	var so sharingOpts
	for _, opt := range opts {
		opt(&so)
	}

	return &so
}

func (o *sharingOpts) GetBitLen() uint {
	return o.bitLen
}

func (o *sharingOpts) GetModulus() *big.Int {
	return o.modulus
}

func (o *sharingOpts) IsSpecialForm() bool {
	return o.specialForm
}

func (o *sharingOpts) GetRange() (low, high *big.Int) {
	return o.rangeLow, o.rangeHigh
}

type SharingOpt func(opts *sharingOpts)

func WithBitLen(bitLen uint) SharingOpt {
	return func(opts *sharingOpts) {
		opts.bitLen = bitLen
	}
}

func WithModulus(modulus *big.Int) SharingOpt {
	return func(opts *sharingOpts) {
		opts.modulus = new(big.Int).Set(modulus)
	}
}

func WithSpecialForm(specialForm bool) SharingOpt {
	return func(opts *sharingOpts) {
		opts.specialForm = specialForm
	}
}

func WithRange(rangeLow, rangeHigh *big.Int) SharingOpt {
	return func(opts *sharingOpts) {
		opts.rangeLow = new(big.Int).Set(rangeLow)
		opts.rangeHigh = new(big.Int).Set(rangeHigh)
	}
}
