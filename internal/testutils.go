package internal

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

var tempDir = os.TempDir()
var csvWriteMutex sync.Mutex

// this could be set to "ms" for milliseconds, "ns" for nanoseconds or default will be microseconds.
var timeUnit = os.Getenv("EXEC_TIME_UNIT")

// GetBigEndianBytesWithLowestBitsSet creates a variable length byte array with the last addedBits bits set to 1.
// for example if byteSize is 2 and addedBits is 4, the result will be 00000000 00001111.
func GetBigEndianBytesWithLowestBitsSet(byteSize, bitToSet int) []byte {
	result := make([]byte, byteSize)
	i := 0
	for i < byteSize && bitToSet > 0 {
		if 8 > bitToSet {
			result[i] = (1 << bitToSet) - 1
			break
		}
		result[i] = 0xFF
		bitToSet -= 8
		i++
	}

	return bitstring.ReverseBytes(result)
}

// measureTime measures the time of a function.
func measureTime(f func()) float64 {
	start := time.Now()
	f()
	switch timeUnit {
	case "ms":
		return float64(time.Since(start).Milliseconds()) / float64(1000000)
	case "ns":
		return float64(time.Since(start).Nanoseconds()) / float64(1000)
	default:
		return float64(time.Since(start).Microseconds())
	}
}

// RunMeasurement measures the time of a function and draw a chart from the results.
// It also writes the results to a csv file.
func RunMeasurement(points int, name string, prepareFunc func(step int), measureFunc func()) {
	times := make([]float64, points)
	// we warm up 10% of the points to avoid cold start
	for c_i := 0; c_i < points/10; c_i++ {
		prepareFunc(c_i)
		measureTime(measureFunc)
	}

	for c_i := 0; c_i < points; c_i++ {
		prepareFunc(c_i)
		t := measureTime(measureFunc)
		times[c_i] = t
	}

	err := csvFile(name, times)
	if err != nil {
		panic(err)
	}
}

func csvFile(name string, times []float64) error {
	csvWriteMutex.Lock()
	defer csvWriteMutex.Unlock()
	log.Default().Printf("writing to csv file %s", fmt.Sprintf("%sexecution_time.csv", tempDir))
	file, err := os.OpenFile(fmt.Sprintf("%sexecution_time.csv", tempDir), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return errs.WrapFailed(err, "failed to create csv file")
	}
	defer file.Close()
	_, err = fmt.Fprintf(file, "\n%s", name)
	if err != nil {
		return errs.WrapFailed(err, "failed to append to csv file")
	}
	for _, value := range times {
		_, err := fmt.Fprintf(file, ",%f", value)
		if err != nil {
			return errs.WrapFailed(err, "failed to write to csv file")
		}
	}
	return nil
}
