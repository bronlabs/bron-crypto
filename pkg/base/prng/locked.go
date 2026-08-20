package prng

import (
	"io"
	"sync"
)

// NewThreadSafeReader wraps r so that concurrent Reads are serialised by a
// mutex, making a single-threaded reader — such as *pcg.Pcg — safe to share
// across concurrent consumers (e.g. one PRNG feeding several concurrent
// key-generation calls). Readers that are already safe for concurrent use,
// like crypto/rand.Reader, do not need it. For seedable CSPRNGs prefer
// csprng.NewThreadSafePrng, which also serialises the seeding methods.
func NewThreadSafeReader(r io.Reader) io.Reader {
	return &threadSafeReader{r: r}
}

type threadSafeReader struct {
	mu sync.Mutex
	r  io.Reader
}

// Read serialises reads on the wrapped reader. The underlying error is
// returned as-is: the io.Reader contract relies on error identity (io.EOF),
// which wrapping would break.
func (l *threadSafeReader) Read(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r.Read(p) //nolint:wrapcheck // io.Reader contract requires the underlying error identity
}
