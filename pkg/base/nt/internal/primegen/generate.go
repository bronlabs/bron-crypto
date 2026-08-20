// generate.go runs the prime search as a pipeline: the calling goroutine
// samples all candidate entropy from the PRNG sequentially and slices it into
// numbered jobs, a pool of workers turns jobs into candidates and tests them
// (they never touch the PRNG), and the calling goroutine folds the results
// back in canonical job order.
package primegen

import (
	"context"
	"encoding/binary"
	"io"
	"math/big"
	"runtime"

	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/errs-go/errs"
)

// Rounds carries the Miller-Rabin iteration counts (FIPS 186-5 Appendix C)
// applied after the BPSW filter: Q rounds for the prime itself and — for
// Safe only — Half rounds for (q−1)/2.
type Rounds struct {
	Q    int
	Half int
}

// jobBatch is how many candidates one job carries. Larger batches amortise
// channel traffic; smaller batches shrink the tail latency of in-order
// resolution (a success can only be finalised once every earlier job is
// fully resolved, i.e. at most ~workers·jobBatch candidate tests away).
// 4 keeps the resolution window small enough not to show up in short pair
// searches while channel traffic stays ≪ 1% of generation time.
const jobBatch = 4

// Generate samples a uniformly random prime of the given class with exactly
// `bits` bits, restricted to [lo, 2^bits) when lo is non-nil (lo must then
// have exactly `bits` bits itself). The output is exactly uniform over all
// class-conformant primes in the range.
//
// prng is read sequentially by the calling goroutine only, so a single
// generation call needs no concurrent-safe reader; a PRNG shared across
// concurrent generation calls must still be safe for concurrent use (e.g.
// crypto/rand.Reader, or a wrapper such as csprng.NewThreadSafePrng).
func Generate(class Class, bits uint, lo *big.Int, rounds Rounds, prng io.Reader) (*big.Int, error) {
	primes, err := run(class, bits, lo, rounds, prng, 1, nil)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate prime")
	}
	return primes[0], nil
}

// GeneratePair samples two independent primes of the given class, each of
// exactly `bits` bits and at least lo (when non-nil), additionally
// satisfying the FIPS 186-5 A.1.1 pair conditions checkable at this level —
// p ≠ q and |p − q| > 2^(bits−100) (vacuous and skipped for bits ≤ 100) —
// plus gcd(N, φ(N)) = 1 for N = pq (provably automatic for equal-length
// primes; enforced as defence-in-depth, see the collector filter). Both
// primes are drawn from one shared worker pool, so all cores work on
// whichever of the two is still missing. prng consumption is sequential —
// see Generate.
func GeneratePair(class Class, bits uint, lo *big.Int, rounds Rounds, prng io.Reader) (p, q *big.Int, err error) {
	accept := func(have []*big.Int, cand *big.Int) bool {
		for _, prev := range have {
			if prev.Cmp(cand) == 0 {
				return false
			}
			// FIPS 186-5 A.1.1 2(d): |p−q| > 2^(bits−100), i.e. the
			// difference must have more than bits−100 bits. Rejecting only
			// the candidate (never the prime already collected) is sound:
			// the retained prime stays uniform and the replacement is a
			// fresh uniform draw conditioned on the distance.
			if bits > 100 {
				diff := new(big.Int).Sub(prev, cand)
				if uint(diff.BitLen()) <= bits-100 {
					return false
				}
			}
			// gcd(N, φ(N)) = 1, i.e. p ∤ (q−1) and q ∤ (p−1) — required
			// downstream by Paillier decryption and by CGGMP21's Π^mod
			// statement. For two primes of equal bit length the condition
			// is provably vacuous: p−1 < 2^bits ≤ 2q, so q | (p−1) would
			// force p = q+1, impossible for two odd primes. It is enforced
			// anyway (two cheap reductions per accepted candidate) because
			// the proof would silently stop holding if the equal-length
			// invariant ever changed.
			one := big.NewInt(1)
			if new(big.Int).Mod(new(big.Int).Sub(cand, one), prev).Sign() == 0 ||
				new(big.Int).Mod(new(big.Int).Sub(prev, one), cand).Sign() == 0 {

				return false
			}
		}
		return true
	}
	primes, err := run(class, bits, lo, rounds, prng, 2, accept)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to generate prime pair")
	}
	return primes[0], primes[1], nil
}

// job is one batch of candidate entropy: jobBatch fixed-size chunks cut from
// the sequential PRNG stream, numbered by seq in the order they were cut.
type job struct {
	seq int64
	buf []byte
}

// result reports one fully processed job: the primes found among its
// candidates, in in-job candidate order (usually none).
type result struct {
	seq   int64
	found []*big.Int
}

// run drives the search. The calling goroutine cuts candidate entropy into
// numbered jobs and collects results; `workers` goroutines process jobs in
// parallel.
//
// Successes are folded back in CANONICAL job order — the order their entropy
// was cut from the PRNG stream — never in completion order. This is
// load-bearing for exact uniformity: completion time depends on the
// candidate's value (BPSW's Lucas parameter search runs faster or slower
// with Jacobi(D/q) for D = 5, −7, 9, …), so taking the temporally-first
// success measurably skews outputs toward fast-verifying residue classes
// (see TestGenerate_SafeUniformityChiSquared, which caught exactly that).
// In job order, the output is the first success of an iid candidate stream,
// which is exactly uniform regardless of scheduling and per-value timing.
func run(class Class, bits uint, lo *big.Int, rounds Rounds, prng io.Reader, want int, accept func(have []*big.Int, cand *big.Int) bool) ([]*big.Int, error) {
	ps, err := paramsFor(class, bits)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to derive sieve parameters")
	}
	if prng == nil {
		return nil, ErrIsNil.WithMessage("nil prng")
	}
	if rounds.Q < 1 || (class == Safe && rounds.Half < 1) {
		return nil, ErrInvalidArgument.WithMessage("Miller-Rabin round counts must be positive")
	}
	if lo != nil && lo.BitLen() != int(bits) {
		return nil, ErrInvalidArgument.WithMessage("lower bound must have exactly the requested bit length")
	}

	workers := ps.workerCount(want)
	jobBytes := jobBatch * ps.candBytes()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, gctx := errgroup.WithContext(ctx)
	jobs := make(chan job, workers)
	results := make(chan result, workers)
	for range workers {
		g.Go(func() error {
			return ps.worker(gctx, lo, rounds, jobs, results)
		})
	}

	out := make([]*big.Int, 0, want)
	// resolved holds out-of-order results until the contiguous prefix
	// catches up; its size is bounded by the number of in-flight jobs
	// (channel buffers plus workers).
	resolved := make(map[int64][]*big.Int)
	nextJob, nextResolve := int64(0), int64(0)
	var pending *job
collect:
	for {
		if pending == nil {
			buf := make([]byte, jobBytes)
			if _, err := io.ReadFull(prng, buf); err != nil {
				return nil, errs.Wrap(err).WithMessage("failed to read random bytes")
			}
			pending = &job{seq: nextJob, buf: buf}
		}
		select {
		case jobs <- *pending:
			nextJob++
			pending = nil
		case res := <-results:
			resolved[res.seq] = res.found
			for {
				found, ok := resolved[nextResolve]
				if !ok {
					break
				}
				delete(resolved, nextResolve)
				nextResolve++
				for _, q := range found {
					if accept == nil || accept(out, q) {
						out = append(out, q)
						if len(out) == want {
							break collect
						}
					}
				}
			}
		case <-gctx.Done():
			// Workers currently have no failure modes of their own (they
			// never touch the PRNG), so this fires only if a future change
			// lets one fail; without this branch such a failure would
			// deadlock the collector.
			return nil, errs.Wrap(g.Wait()).WithMessage("prime search failed")
		}
	}
	cancel()
	// Workers exit via the cooperative cancel; wait for them so no goroutine
	// outlives the call.
	if err := g.Wait(); err != nil && !errs.Is(err, context.Canceled) {
		return nil, errs.Wrap(err).WithMessage("prime search failed")
	}
	return out, nil
}

// workerCount balances the parallel speedup of the search against its fixed
// spawn/teardown overhead: sub-millisecond searches (small plain and Blum
// primes) run faster on one or two cores than on all of them. The count
// scales with the bit length and with how many primes the search wants.
// Safe-prime searches square the expected primality-test count, so they
// always use every core.
func (ps *params) workerCount(want int) int {
	cores := runtime.GOMAXPROCS(0)
	if ps.class == Safe {
		return cores
	}
	return min(cores, max(1, want*int(ps.bits)/128))
}

// candBytes is the fixed entropy budget of one candidate: a 4-byte draw per
// sieve-prime residue plus an 8-byte window-index draw.
func (ps *params) candBytes() int {
	return 4*ps.nPi + 8
}

// scratch is a worker's reusable big.Int working set.
type scratch struct {
	x, term, r, q, qHalf, tdRem *big.Int
}

func newScratch() *scratch {
	return &scratch{
		x: new(big.Int), term: new(big.Int), r: new(big.Int),
		q: new(big.Int), qHalf: new(big.Int), tdRem: new(big.Int),
	}
}

// worker processes jobs until ctx is cancelled, reporting one result per
// job. It performs no PRNG reads — all entropy arrives inside the job.
func (ps *params) worker(ctx context.Context, lo *big.Int, rounds Rounds, jobs <-chan job, results chan<- result) error {
	s := newScratch()
	candBytes := ps.candBytes()
	for {
		select {
		case <-ctx.Done():
			return errs.Wrap(ctx.Err()).WithMessage("worker cancelled")
		case jb := <-jobs:
			var found []*big.Int
			for k := range jobBatch {
				// Cooperative cancel between candidates: a batch can hold
				// several primality tests' worth of work.
				select {
				case <-ctx.Done():
					return errs.Wrap(ctx.Err()).WithMessage("worker cancelled")
				default:
				}
				if q, ok := ps.tryCandidate(jb.buf[k*candBytes:(k+1)*candBytes], lo, rounds, s); ok {
					found = append(found, q)
				}
			}
			select {
			case results <- result{seq: jb.seq, found: found}:
			case <-ctx.Done():
				return errs.Wrap(ctx.Err()).WithMessage("worker cancelled")
			}
		}
	}
}

// tryCandidate turns one fixed-size entropy chunk into a candidate and tests
// it. Per candidate it (1) rejection-samples the residue vector and
// assembles x by CRT, (2) places it as q = x + b·m with the chunk's window
// index b, (3) rejects unless q ∈ [lo, 2^bits) — steps (1)–(3) make realised
// candidates exactly uniform over the admissible set in range — then (4)
// trial-divides by the table primes beyond Π and (5) runs the
// BPSW-then-Miller-Rabin tests.
//
// A rejection-sampling miss in (1) or (2) abandons the slot entirely (no
// candidate) rather than redrawing: the chunk is fixed-size, and abandoning
// is sound because the miss is decided before any residue value is realised,
// so accepted draws remain exactly uniform. Misses cost < nPi·2⁻¹⁷ of slots.
func (ps *params) tryCandidate(chunk []byte, lo *big.Int, rounds Rounds, s *scratch) (*big.Int, bool) {
	// Step 1: residue vector r_i ←$ {floor, …, p_i−1} and CRT recombination
	// x ≡ r_i (mod p_i), with the power-of-two residue (odd, or ≡ 3 mod 4)
	// contributed by offset.
	s.x.Set(ps.offset)
	for i := range ps.nPi {
		v := binary.BigEndian.Uint32(chunk[4*i:])
		if t := ps.thresholds[i]; t != 0 && v >= t {
			return nil, false
		}
		s.r.SetInt64(ps.floor + int64(v%ps.spans[i]))
		s.term.Mul(ps.basis[i], s.r)
		s.x.Add(s.x, s.term)
	}
	// x < m·(floor + Σ r_i) < m·2^23, so a single reduction suffices.
	s.x.Mod(s.x, ps.m)

	// Step 2: window shift b ←$ [0, bBound); q = x + b·m. Same rejection
	// sampling via bThreshold (0 means bBound | 2^64, every draw accepted);
	// the accepted draw reduced mod bBound is exactly uniform.
	b := binary.BigEndian.Uint64(chunk[4*ps.nPi:])
	if ps.bThreshold != 0 && b >= ps.bThreshold {
		return nil, false
	}
	b %= ps.bBound
	s.q.SetUint64(b)
	s.q.Mul(s.q, ps.m)
	s.q.Add(s.q, s.x)

	// Step 3: range rejection — exactly `bits` bits, and ≥ lo when a lower
	// bound was requested.
	if s.q.BitLen() != int(ps.bits) {
		return nil, false
	}
	if lo != nil && s.q.Cmp(lo) < 0 {
		return nil, false
	}

	// Step 4: trial division by the table primes beyond Π — kills a further
	// fraction of candidates for a fraction of a BPSW test's cost.
	// Rejections here are lossless: they only remove candidates no
	// class-conformant prime could equal.
	if !ps.passesTrialDivision(s.q, s.tdRem) {
		return nil, false
	}

	// Step 5: primality tests — BPSW (ProbablyPrime(0)) as the cheap filter,
	// then the FIPS-derived Miller-Rabin counts for the formal 4^{-N}
	// soundness bound. For Safe, (q−1)/2 = q >> 1 (q is odd) is tested
	// first: it rejects almost every candidate, so q's own tests almost
	// never run.
	if ps.class == Safe {
		s.qHalf.Rsh(s.q, 1)
		if !s.qHalf.ProbablyPrime(0) || !s.q.ProbablyPrime(0) ||
			!s.qHalf.ProbablyPrime(rounds.Half) || !s.q.ProbablyPrime(rounds.Q) {

			return nil, false
		}
	} else if !s.q.ProbablyPrime(0) || !s.q.ProbablyPrime(rounds.Q) {
		return nil, false
	}

	return new(big.Int).Set(s.q), true
}

// passesTrialDivision reports whether q survives division by every packed
// trial-division prime: q mod p must be nonzero for all classes, and for
// Safe also ≠ 1 (which would put p in (q−1)/2). rem is caller scratch.
func (ps *params) passesTrialDivision(q, rem *big.Int) bool {
	forbidOne := ps.class == Safe
	for i := range ps.tdGroups {
		grp := &ps.tdGroups[i]
		w := rem.Mod(q, grp.prod).Uint64()
		for _, p := range grp.primes {
			res := w % p
			if res == 0 || (forbidOne && res == 1) {
				return false
			}
		}
	}
	return true
}
