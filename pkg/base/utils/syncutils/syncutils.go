package syncutils

import (
	"runtime"

	"golang.org/x/sync/errgroup"
)

func ComputeConcurrently[S ~[]In, In any, Out any](params S, computeFunc func(In) Out) []Out {
	var eg errgroup.Group
	eg.SetLimit(runtime.NumCPU())

	out := make([]Out, len(params))
	for i, p := range params {
		eg.Go(func() error {
			out[i] = computeFunc(p)
			return nil
		})
	}
	_ = eg.Wait()

	return out
}
