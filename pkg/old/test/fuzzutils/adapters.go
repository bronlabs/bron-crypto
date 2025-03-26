package curves_testutils

import (
	"encoding/binary"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	fu "github.com/bronlabs/bron-crypto/pkg/base/fuzzutils"
)

var _ fu.ObjectAdapter[curves.Point] = (*PointAdapter)(nil)

type PointAdapter struct {
	Curve curves.Curve
}

func (pa *PointAdapter) Wrap(x fu.Underlyer) curves.Point {
	buffer := make([]byte, pa.Curve.ElementSize()+1)
	binary.LittleEndian.PutUint64(buffer[:8], x)
	p, err := pa.Curve.Point().FromAffineCompressed(buffer)
	if err != nil { // Default to hash if point creation fails
		p, err = pa.Curve.Hash(buffer)
		if err != nil {
			panic(err)
		}
	}
	return p
}

func (*PointAdapter) Unwrap(p curves.Point) fu.Underlyer {
	return binary.LittleEndian.Uint64(p.ToAffineCompressed()[:8])
}

func (pa *PointAdapter) ZeroValue() curves.Point {
	return pa.Curve.AdditiveIdentity()
}

var _ fu.ObjectAdapter[curves.Scalar] = (*ScalarAdapter)(nil)

type ScalarAdapter struct {
	Curve curves.Curve
}

func (sa *ScalarAdapter) Wrap(x fu.Underlyer) curves.Scalar {
	buffer := make([]byte, sa.Curve.ElementSize())
	binary.LittleEndian.PutUint64(buffer[:8], x)
	s, err := sa.Curve.ScalarField().Scalar().SetBytes(buffer)
	if err != nil {
		s, err = sa.Curve.ScalarField().Hash(buffer)
		if err != nil {
			panic(err)
		}
	}
	return s
}

func (*ScalarAdapter) Unwrap(s curves.Scalar) fu.Underlyer {
	return binary.LittleEndian.Uint64(s.Bytes()[:8])
}

func (sa *ScalarAdapter) ZeroValue() curves.Scalar {
	return sa.Curve.ScalarField().Zero()
}

var _ fu.ObjectAdapter[curves.BaseFieldElement] = (*BaseFieldElementAdapter)(nil)

type BaseFieldElementAdapter struct {
	Curve curves.Curve
}

func (ba *BaseFieldElementAdapter) Wrap(x fu.Underlyer) curves.BaseFieldElement {
	buffer := make([]byte, ba.Curve.ElementSize())
	binary.LittleEndian.PutUint64(buffer[:8], x)
	f, err := ba.Curve.BaseField().Element().SetBytes(buffer)
	if err != nil {
		f, err = ba.Curve.BaseField().Hash(buffer)
		if err != nil {
			panic(err)
		}
	}
	return f
}

func (*BaseFieldElementAdapter) Unwrap(f curves.BaseFieldElement) fu.Underlyer {
	return binary.LittleEndian.Uint64(f.Bytes()[:8])
}

func (ba *BaseFieldElementAdapter) ZeroValue() curves.BaseFieldElement {
	return ba.Curve.BaseField().Zero()
}
