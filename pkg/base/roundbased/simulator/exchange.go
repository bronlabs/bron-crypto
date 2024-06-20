package simulator

// Exchange P should be []byte when serialisation implemented.
type exchange[P any] struct {
	from    string
	payload P
}
