//go:build purego || nobignum

package modular

import (
	"github.com/cronokirby/saferith"
	"golang.org/x/sync/errgroup"
)

func FastExp(b, e *saferith.Nat, m *saferith.Modulus) (*saferith.Nat, error) {
	return new(saferith.Nat).Exp(b, e, m), nil
}

func FastMultiBaseExp(bs []*saferith.Nat, e *saferith.Nat, m *saferith.Modulus) ([]*saferith.Nat, error) {
	rs := make([]*saferith.Nat, len(bs))
	var eg errgroup.Group
	for i, b := range bs {
		eg.Go(func() error {
			rs[i] = new(saferith.Nat).Exp(b, e, m)
			return nil
		})
	}
	_ = eg.Wait()
	return rs, nil
}
