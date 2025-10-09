// Package dudect provides statistical constant-time analysis for cryptographic implementations.
// Based on the dudect approach: https://github.com/oreparaz/dudect
package dudect

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"runtime/debug"
	"sort"
	"time"
)

// Builder creates test functions for different input classes.
// cls: 0 or 1 indicating the input class
// i: iteration number
// rng: random number generator for test-specific randomness
type Builder func(cls byte, i int, rng *Rand) func()

// Config configures the dudect analysis.
type Config struct {
	Target            string  // Name of operation being tested
	NMeasures         int     // Number of measurements to collect
	TargetNsPerSample int64   // Target nanoseconds per sample (for auto-tuning Inner)
	Inner             int     // Number of inner iterations per measurement
	DiscardFirst      int     // Warmup measurements to discard
	NumPercentiles    int     // Number of percentile crops (0 to disable)
	TThreshold        float64 // t-statistic threshold for leak detection
	Seed              uint64  // RNG seed (0 for random)
	PinOSThread       bool    // Pin to single OS thread
	DisableGC         bool    // Disable GC during measurement
}

// Result contains the analysis results.
type Result struct {
	Target      string
	MaxT        float64   // max |t| across raw + crops
	Leak        bool      // MaxT > Threshold
	Threshold   float64   // t-statistic threshold used
	RawT        float64   // |t| for raw (no cropping)
	CountsClass [2]int    // counts per class after filtering
	Percentiles []int64   // crop thresholds (ns)
	AllT        []float64 // all t-statistics [raw, crop1, crop2, ...]
}

// PreflightReport contains preflight check results.
type PreflightReport struct {
	Target        string
	TickNs        int64   // minimal non-zero timer delta
	NoopMeanNs    float64 // per measurement noop overhead
	NoopCV        float64 // coefficient of variation for noop
	OpMeanCls0Ns  float64 // mean time for class 0
	OpMeanCls1Ns  float64 // mean time for class 1
	OpCVCls0      float64 // CV for class 0
	OpCVCls1      float64 // CV for class 1
	OutlierRate0  float64 // outlier rate for class 0
	OutlierRate1  float64 // outlier rate for class 1
	RecommendedIn int     // suggested Inner value
	Notes         []string
}

func (p PreflightReport) String() string {
	return fmt.Sprintf(
		"== Preflight (%s) ==\n"+
			"timer tick: %d ns\n"+
			"noop: mean=%.1f ns CV=%.3f\n"+
			"class0 op: mean=%.1f ns CV=%.3f outliers=%.2f%%\n"+
			"class1 op: mean=%.1f ns CV=%.3f outliers=%.2f%%\n"+
			"recommended Inner: %d\n"+
			"notes: %v\n",
		p.Target, p.TickNs,
		p.NoopMeanNs, p.NoopCV,
		p.OpMeanCls0Ns, p.OpCVCls0, 100*p.OutlierRate0,
		p.OpMeanCls1Ns, p.OpCVCls1, 100*p.OutlierRate1,
		p.RecommendedIn, p.Notes)
}

// Preflight performs preliminary checks and auto-tunes parameters.
func Preflight(build Builder, cfg Config) (PreflightReport, Config) {
	defaults(&cfg)
	
	report := PreflightReport{Target: cfg.Target}
	
	// Measure timer resolution
	tickNs := measureTimerTick()
	report.TickNs = tickNs
	
	// Measure noop overhead
	noopTimes := make([]int64, 100)
	for i := range noopTimes {
		t0 := time.Now().UnixNano()
		for j := 0; j < cfg.Inner; j++ {
			// noop
		}
		noopTimes[i] = time.Now().UnixNano() - t0
	}
	noopMean, noopCV := computeStats(noopTimes)
	report.NoopMeanNs = noopMean
	report.NoopCV = noopCV
	
	if noopCV > 1.0 {
		report.Notes = append(report.Notes, 
			fmt.Sprintf("high no-op jitter CV=%.3f (pin thread, disable turbo/DVFS, close background apps)", noopCV))
	}
	
	// Measure operation timing for both classes
	rng := NewRand(0)
	opTimes0 := make([]int64, 100)
	opTimes1 := make([]int64, 100)
	
	for i := range opTimes0 {
		fn := build(0, i, rng)
		t0 := time.Now().UnixNano()
		for j := 0; j < cfg.Inner; j++ {
			fn()
		}
		opTimes0[i] = time.Now().UnixNano() - t0
		
		fn = build(1, i, rng)
		t0 = time.Now().UnixNano()
		for j := 0; j < cfg.Inner; j++ {
			fn()
		}
		opTimes1[i] = time.Now().UnixNano() - t0
	}
	
	mean0, cv0 := computeStats(opTimes0)
	mean1, cv1 := computeStats(opTimes1)
	outliers0 := countOutliers(opTimes0)
	outliers1 := countOutliers(opTimes1)
	
	report.OpMeanCls0Ns = mean0
	report.OpCVCls0 = cv0
	report.OutlierRate0 = outliers0
	report.OpMeanCls1Ns = mean1
	report.OpCVCls1 = cv1
	report.OutlierRate1 = outliers1
	
	if cv0 > 0.5 || cv1 > 0.5 {
		report.Notes = append(report.Notes, "operation jitter high; consider increasing Inner or using cycle counter")
	}
	
	if outliers0 > 0.1 || outliers1 > 0.1 {
		report.Notes = append(report.Notes, "many long-tail outliers; cropping will help but environment noise is high")
	}
	
	// Auto-tune Inner if needed
	avgOpNs := (mean0 + mean1) / 2
	if cfg.TargetNsPerSample > 0 && avgOpNs > 0 {
		recommendedInner := int(float64(cfg.TargetNsPerSample) / avgOpNs)
		if recommendedInner < 1 {
			recommendedInner = 1
		}
		report.RecommendedIn = recommendedInner
		
		if recommendedInner != cfg.Inner {
			oldInner := cfg.Inner
			cfg.Inner = recommendedInner
			report.Notes = append(report.Notes, 
				fmt.Sprintf("auto-tuned Inner from %d → %d (target ~%d ns/sample)", 
					oldInner, recommendedInner, cfg.TargetNsPerSample))
		}
	}
	
	// Check if operation is close to timer resolution
	if avgOpNs < float64(tickNs)*10 {
		report.Notes = append(report.Notes, "operation close to timer resolution; increase Inner or use cycle counter")
	}
	
	return report, cfg
}

// Run performs dudect statistical timing analysis.
func Run(build Builder, cfg Config) Result {
	defaults(&cfg)
	
	if cfg.DisableGC {
		debug.SetGCPercent(-1)
		defer debug.SetGCPercent(100)
	}
	
	oldProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(oldProcs)
	
	if cfg.PinOSThread {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
	}
	
	// Generate random classes
	seed := cfg.Seed
	if seed == 0 {
		var b [8]byte
		rand.Read(b[:])
		seed = binary.LittleEndian.Uint64(b[:])
	}
	rng := NewRand(int64(seed))
	
	n := cfg.NMeasures
	if n < 4 {
		return Result{Target: cfg.Target, Threshold: cfg.TThreshold}
	}
	
	classes := make([]byte, n)
	for i := range classes {
		if rng.Intn(2) == 1 {
			classes[i] = 1
		}
	}
	
	// Warmup
	warm := min(cfg.DiscardFirst, n)
	for i := 0; i < warm; i++ {
		fn := build(classes[i], i, rng)
		for k := 0; k < cfg.Inner; k++ {
			fn()
		}
	}
	
	// Collect measurements
	times := make([]int64, n-warm)
	clsl := make([]byte, n-warm)
	for i := warm; i < n; i++ {
		fn := build(classes[i], i, rng)
		t0 := time.Now().UnixNano()
		for k := 0; k < cfg.Inner; k++ {
			fn()
		}
		dt := time.Now().UnixNano() - t0
		times[i-warm] = dt
		clsl[i-warm] = classes[i]
	}
	
	// Remove non-positive measurements
	pos := 0
	for i := range times {
		if times[i] > 0 {
			times[pos] = times[i]
			clsl[pos] = clsl[i]
			pos++
		}
	}
	times = times[:pos]
	clsl = clsl[:pos]
	
	if len(times) < 4 {
		return Result{Target: cfg.Target, Threshold: cfg.TThreshold}
	}
	
	// Compute percentile thresholds for cropping
	percs := computePercentiles(times, cfg.NumPercentiles)
	
	// Compute t-statistics for raw and cropped data
	allT := computeTStatistics(times, clsl, percs)
	
	rawT := 0.0
	if len(allT) > 0 {
		rawT = allT[0]
	}
	
	maxT := 0.0
	for _, t := range allT {
		if at := math.Abs(t); at > maxT {
			maxT = at
		}
	}
	
	leak := (!math.IsNaN(maxT)) && (maxT > cfg.TThreshold)
	
	// Count samples per class (raw)
	var count0, count1 int
	for _, c := range clsl {
		if c == 0 {
			count0++
		} else {
			count1++
		}
	}
	
	return Result{
		Target:      cfg.Target,
		MaxT:        maxT,
		Leak:        leak,
		Threshold:   cfg.TThreshold,
		RawT:        rawT,
		CountsClass: [2]int{count0, count1},
		Percentiles: percs,
		AllT:        allT,
	}
}

// Helper functions

func defaults(c *Config) {
	if c.NMeasures == 0 {
		c.NMeasures = 20000
	}
	if c.DiscardFirst == 0 {
		c.DiscardFirst = 10
	}
	if c.Inner == 0 {
		c.Inner = 1
	}
	if c.NumPercentiles == 0 {
		c.NumPercentiles = 15
	}
	if c.TThreshold == 0 {
		c.TThreshold = 4.5
	}
	if !c.PinOSThread {
		c.PinOSThread = true
	}
	if !c.DisableGC {
		c.DisableGC = true
	}
}

func measureTimerTick() int64 {
	var minDelta int64 = math.MaxInt64
	for i := 0; i < 1000; i++ {
		t0 := time.Now().UnixNano()
		for time.Now().UnixNano() == t0 {
			// spin
		}
		delta := time.Now().UnixNano() - t0
		if delta > 0 && delta < minDelta {
			minDelta = delta
		}
	}
	return minDelta
}

func computeStats(times []int64) (mean, cv float64) {
	if len(times) == 0 {
		return 0, 0
	}
	
	sum := 0.0
	for _, t := range times {
		sum += float64(t)
	}
	mean = sum / float64(len(times))
	
	if len(times) < 2 {
		return mean, 0
	}
	
	var variance float64
	for _, t := range times {
		d := float64(t) - mean
		variance += d * d
	}
	variance /= float64(len(times) - 1)
	
	if mean > 0 {
		cv = math.Sqrt(variance) / mean
	}
	return
}

func countOutliers(times []int64) float64 {
	if len(times) < 4 {
		return 0
	}
	
	sorted := make([]int64, len(times))
	copy(sorted, times)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	
	q1 := sorted[len(sorted)/4]
	q3 := sorted[3*len(sorted)/4]
	iqr := q3 - q1
	upperBound := q3 + 3*iqr
	
	outliers := 0
	for _, t := range times {
		if t > upperBound {
			outliers++
		}
	}
	
	return float64(outliers) / float64(len(times))
}

func computePercentiles(times []int64, numPercentiles int) []int64 {
	if numPercentiles <= 0 {
		return nil
	}
	
	sorted := make([]int64, len(times))
	copy(sorted, times)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	
	percs := make([]int64, 0, numPercentiles)
	size := len(sorted)
	
	for i := 0; i < numPercentiles; i++ {
		which := 1.0 - math.Pow(0.5, 10.0*float64(i+1)/float64(numPercentiles))
		idx := int(which * float64(size))
		if idx >= size {
			idx = size - 1
		}
		percs = append(percs, sorted[idx])
	}
	
	return percs
}

type online struct {
	n        int
	mean, m2 float64
}

func computeTStatistics(times []int64, classes []byte, percentiles []int64) []float64 {
	grps := make([]struct{ c0, c1 online }, 1+len(percentiles))
	
	for i, t := range times {
		cls := classes[i]
		tf := float64(t)
		
		// Raw (no crop)
		if cls == 0 {
			updateWelford(&grps[0].c0, tf)
		} else {
			updateWelford(&grps[0].c1, tf)
		}
		
		// Cropped versions
		for j, thresh := range percentiles {
			if t < thresh {
				if cls == 0 {
					updateWelford(&grps[j+1].c0, tf)
				} else {
					updateWelford(&grps[j+1].c1, tf)
				}
			}
		}
	}
	
	allT := make([]float64, 0, len(grps))
	for _, g := range grps {
		if g.c0.n >= 2 && g.c1.n >= 2 {
			t := welchT(g.c0.n, g.c0.mean, g.c0.m2/(float64(g.c0.n)-1),
				g.c1.n, g.c1.mean, g.c1.m2/(float64(g.c1.n)-1))
			allT = append(allT, t)
		}
	}
	
	return allT
}

func updateWelford(o *online, x float64) {
	o.n++
	delta := x - o.mean
	o.mean += delta / float64(o.n)
	delta2 := x - o.mean
	o.m2 += delta * delta2
}

func welchT(n0 int, mean0, var0 float64, n1 int, mean1, var1 float64) float64 {
	s0 := var0 / float64(n0)
	s1 := var1 / float64(n1)
	t := (mean0 - mean1) / math.Sqrt(s0+s1)
	return t
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}