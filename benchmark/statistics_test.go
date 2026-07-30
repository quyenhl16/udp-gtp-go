package benchmark

import (
	"math"
	"testing"
	"time"
)

func TestMeanConfidenceInterval95(t *testing.T) {
	t.Parallel()

	got := MeanConfidenceInterval95([]float64{1, 2, 3, 4, 5})
	if got.Count != 5 {
		t.Fatalf("Count = %d, want 5", got.Count)
	}
	if math.Abs(got.Mean-3) > 1e-12 {
		t.Fatalf("Mean = %f, want 3", got.Mean)
	}
	if math.Abs(got.Lower-1.0367568385) > 1e-6 {
		t.Errorf("Lower = %f, want about 1.036757", got.Lower)
	}
	if math.Abs(got.Upper-4.9632431615) > 1e-6 {
		t.Errorf("Upper = %f, want about 4.963243", got.Upper)
	}
}

func TestMeanConfidenceInterval95SingleAndNonFiniteSamples(t *testing.T) {
	t.Parallel()

	got := MeanConfidenceInterval95([]float64{math.NaN(), 42, math.Inf(1)})
	if got.Count != 1 || got.Mean != 42 || got.Lower != 42 || got.Upper != 42 {
		t.Fatalf("single finite sample result = %+v", got)
	}
}

func TestFormatDurationMeanCI95(t *testing.T) {
	t.Parallel()

	got := FormatDurationMeanCI95([]time.Duration{
		100 * time.Microsecond,
		100 * time.Microsecond,
		100 * time.Microsecond,
	})
	if got != "100µs [100µs, 100µs]" {
		t.Fatalf("FormatDurationMeanCI95() = %q", got)
	}
}
