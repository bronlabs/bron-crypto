package pedersen

// LinearDealerFunc wraps two underlying dealer functions: one for the secret
// shares and one for the blinding shares. This is returned by
// DealAndRevealDealerFunc to allow the caller to access the dealing components.
type LinearDealerFunc[ULDF any] struct {
	shares   ULDF
	blinding ULDF
}

func (f *LinearDealerFunc[ULDF]) Shares() ULDF {
	return f.shares
}

func (f *LinearDealerFunc[ULDF]) Blinding() ULDF {
	return f.blinding
}
