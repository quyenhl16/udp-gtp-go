package benchmark

import (
	"fmt"
	"math"
	"time"
)

// MeanCI contains a sample mean and its two-sided 95% confidence interval.
type MeanCI struct {
	Count int
	Mean  float64
	Lower float64
	Upper float64
}

// MeanConfidenceInterval95 calculates a two-sided 95% confidence interval for
// the population mean. It uses Student's t distribution because benchmark run
// counts are typically small. Non-finite samples are ignored.
func MeanConfidenceInterval95(samples []float64) MeanCI {
	values := make([]float64, 0, len(samples))
	for _, sample := range samples {
		if !math.IsNaN(sample) && !math.IsInf(sample, 0) {
			values = append(values, sample)
		}
	}

	if len(values) == 0 {
		return MeanCI{}
	}

	var sum float64
	for _, value := range values {
		sum += value
	}
	mean := sum / float64(len(values))
	if len(values) == 1 {
		return MeanCI{Count: 1, Mean: mean, Lower: mean, Upper: mean}
	}

	var squaredDeviations float64
	for _, value := range values {
		delta := value - mean
		squaredDeviations += delta * delta
	}

	standardDeviation := math.Sqrt(squaredDeviations / float64(len(values)-1))
	standardError := standardDeviation / math.Sqrt(float64(len(values)))
	margin := studentTCritical95(len(values)-1) * standardError

	return MeanCI{
		Count: len(values),
		Mean:  mean,
		Lower: mean - margin,
		Upper: mean + margin,
	}
}

// FormatMeanCI95 formats a mean and interval as "mean [lower, upper]".
func FormatMeanCI95(samples []float64, precision int) string {
	estimate := MeanConfidenceInterval95(samples)
	if estimate.Count == 0 {
		return "n/a"
	}

	format := fmt.Sprintf("%%.%df [%%.%df, %%.%df]", precision, precision, precision)
	return fmt.Sprintf(format, estimate.Mean, estimate.Lower, estimate.Upper)
}

// FormatDurationMeanCI95 formats duration samples as a mean and 95% interval.
func FormatDurationMeanCI95(samples []time.Duration) string {
	values := make([]float64, 0, len(samples))
	for _, sample := range samples {
		values = append(values, float64(sample))
	}

	estimate := MeanConfidenceInterval95(values)
	if estimate.Count == 0 {
		return "n/a"
	}

	return fmt.Sprintf(
		"%s [%s, %s]",
		time.Duration(math.Round(estimate.Mean)),
		time.Duration(math.Round(estimate.Lower)),
		time.Duration(math.Round(estimate.Upper)),
	)
}

// studentTCritical95 returns the 0.975 quantile for the supplied degrees of
// freedom. The normal approximation is sufficient beyond the table.
func studentTCritical95(degreesOfFreedom int) float64 {
	critical := [...]float64{
		0,
		12.706205, 4.302653, 3.182446, 2.776445, 2.570582,
		2.446912, 2.364624, 2.306004, 2.262157, 2.228139,
		2.200985, 2.178813, 2.160369, 2.144787, 2.131450,
		2.119905, 2.109816, 2.100922, 2.093024, 2.085963,
		2.079614, 2.073873, 2.068658, 2.063899, 2.059539,
		2.055529, 2.051831, 2.048407, 2.045230, 2.042272,
	}
	if degreesOfFreedom > 0 && degreesOfFreedom < len(critical) {
		return critical[degreesOfFreedom]
	}
	return 1.96
}
