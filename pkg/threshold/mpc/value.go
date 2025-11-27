package mpc

import (
	"math/bits"

	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/binrep3"
)

// Value64 represents a 64-bit value that can be public (uint64) or secret (64 shares of GF(2)),
// ideally, something like Either[uint64, *Share] would be used, but that's not possible in Go.
type Value64 struct {
	public *uint64
	secret *binrep3.Share
}

func NewValue64Public(v uint64) *Value64 {
	return &Value64{public: &v, secret: nil}
}

func NewValue64Secret(v *binrep3.Share) *Value64 {
	return &Value64{public: nil, secret: v}
}

func (v *Value64) Clone() *Value64 {
	clone := new(Value64)
	if v.public != nil {
		pClone := *v.public
		clone.public = &pClone
	}
	if v.secret != nil {
		sClone := v.secret.Clone()
		clone.secret = sClone
	}
	return clone
}

func (v *Value64) IsPublic() bool {
	return v.public != nil
}

func (v *Value64) IsSecret() bool {
	return v.secret != nil
}

func (v *Value64) Public() uint64 {
	if v.secret != nil || v.public == nil {
		panic("value is not public")
	}
	return *v.public
}

func (v *Value64) Secret() *binrep3.Share {
	if v.public != nil || v.secret == nil {
		panic("value is not secret")
	}
	return v.secret
}

func (v *Value64) Shl(k int) *Value64 {
	result := new(Value64)
	if v.public != nil {
		p := *v.public << k
		result.public = &p
	}
	if v.secret != nil {
		result.secret = v.secret.ShiftLeft(k)
	}
	return result
}

func (v *Value64) Shr(k int) *Value64 {
	result := new(Value64)
	if v.public != nil {
		p := *v.public >> k
		result.public = &p
	}
	if v.secret != nil {
		result.secret = v.secret.ShiftRight(k)
	}
	return result
}

func (v *Value64) Ror(k int) *Value64 {
	result := new(Value64)
	if v.public != nil {
		p := bits.RotateLeft64(*v.public, -k)
		result.public = &p
	}
	if v.secret != nil {
		result.secret = v.secret.RotateRight(k)
	}
	return result
}

func (v *Value64) ReverseBytes() *Value64 {
	result := new(Value64)
	if v.public != nil {
		p := bits.ReverseBytes64(*v.public)
		result.public = &p
	}
	if v.secret != nil {
		result.secret = v.secret.ReverseBytes()
	}
	return result
}

func (v *Value64) BitMaskOf(bit int) *Value64 {
	result := new(Value64)
	if v.public != nil {
		p := -((*v.public >> bit) & 0b1)
		result.public = &p
	}
	if v.secret != nil {
		result.secret = v.secret.BitMaskOf(bit)
	}
	return result
}
