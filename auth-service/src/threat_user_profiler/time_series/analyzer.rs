use crate::threat_user_profiler::types::*;
// Commented out missing dependencies for now
// use nalgebra::{DMatrix, DVector};
// use statrs::distribution::{ChiSquared, ContinuousCDF, Normal};
// use statrs::statistics::Statistics;
use tracing::debug;

// Statistical helper trait
trait StatisticalMethods {
    fn mean(&self) -> f64;
    fn variance(&self) -> f64;
    fn std_dev(&self) -> f64;
}

impl StatisticalMethods for [f64] {
    fn mean(&self) -> f64 {
        if self.is_empty() {
            return 0.0;
        }
        self.iter().sum::<f64>() / self.len() as f64
    }

    fn variance(&self) -> f64 {
        if self.len() < 2 {
            return 0.0;
        }
        let mean = self.mean();
        let sum_sq_diff: f64 = self.iter().map(|x| (x - mean).powi(2)).sum();
        sum_sq_diff / (self.len() - 1) as f64
    }

    fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }
}

impl StatisticalMethods for Vec<f64> {
    fn mean(&self) -> f64 {
        self.as_slice().mean()
    }

    fn variance(&self) -> f64 {
        self.as_slice().variance()
    }

    fn std_dev(&self) -> f64 {
        self.as_slice().std_dev()
    }
}

/// Helper trait to calculate median for Vec<f64>
trait MedianCalculation {
    fn median(&self) -> f64;
}

impl MedianCalculation for Vec<f64> {
    fn median(&self) -> f64 {
        if self.is_empty() {
            return 0.0;
        }
        let len = self.len();
        if len % 2 == 0 {
            (self[len / 2 - 1] + self[len / 2]) / 2.0
        } else {
            self[len / 2]
        }
    }
}

/// Advanced time series analyzer for behavioral patterns
#[derive(Clone)]
pub struct TimeSeriesAnalyzer {
    window_size: usize,
    seasonality_periods: Vec<usize>,
    change_point_sensitivity: f64,
}

impl TimeSeriesAnalyzer {
    /// Create a new time series analyzer
    pub fn new(
        window_size: usize,
        seasonality_periods: Vec<usize>,
        change_point_sensitivity: f64,
    ) -> Self {
        Self {
            window_size,
            seasonality_periods,
            change_point_sensitivity,
        }
    }

    /// Analyze a behavioral time series for patterns and anomalies
    pub async fn analyze_series(
        &self,
        series: &BehavioralTimeSeries,
    ) -> Result<SeriesStatistics, Box<dyn std::error::Error + Send + Sync>> {
        if series.data_points.len() < 3 {
            return Err("Insufficient data points for analysis".into());
        }

        let values: Vec<f64> = series.data_points.iter().map(|p| p.value).collect();

        if values.is_empty() {
            return Err("No data points available".into());
        }

        let mut sorted_values = values.clone();
        sorted_values.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let variance = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / values.len() as f64;
        let std_dev = variance.sqrt();

        let statistics = SeriesStatistics {
            mean,
            median: sorted_values.median(),
            std_dev,
            variance,
            min: *sorted_values.first().unwrap(),
            max: *sorted_values.last().unwrap(),
            percentile_95: self.calculate_percentile(&sorted_values, 0.95),
            percentile_99: self.calculate_percentile(&sorted_values, 0.99),
            trend_slope: self.calculate_trend_slope(&values),
            seasonality_strength: self.calculate_seasonality_strength(&values),
        };

        debug!(
            "Analyzed time series for user {}: mean={:.3}, std_dev={:.3}, trend_slope={:.3}",
            series.user_id, statistics.mean, statistics.std_dev, statistics.trend_slope
        );

        Ok(statistics)
    }

    /// Perform trend analysis on time series data
    pub async fn analyze_trend(
        &self,
        series: &BehavioralTimeSeries,
    ) -> Result<TrendAnalysis, Box<dyn std::error::Error + Send + Sync>> {
        if series.data_points.len() < 10 {
            return Err("Insufficient data points for trend analysis".into());
        }

        let values: Vec<f64> = series.data_points.iter().map(|p| p.value).collect();
        let x_values: Vec<f64> = (0..values.len()).map(|i| i as f64).collect();

        let regression_result = self.linear_regression(&x_values, &values);

        let trend_direction = match regression_result.slope {
            slope if slope > 0.01 => TrendDirection::Increasing,
            slope if slope < -0.01 => TrendDirection::Decreasing,
            _ => {
                if regression_result.r_squared < 0.1 {
                    TrendDirection::Volatile
                } else {
                    TrendDirection::Stable
                }
            }
        };

        Ok(TrendAnalysis {
            slope: regression_result.slope,
            intercept: regression_result.intercept,
            r_squared: regression_result.r_squared,
            p_value: regression_result.p_value,
            trend_direction,
        })
    }

    /// Detect change points in behavioral patterns
    pub async fn detect_change_points(
        &self,
        series: &BehavioralTimeSeries,
    ) -> Result<Vec<ChangePoint>, Box<dyn std::error::Error + Send + Sync>> {
        if series.data_points.len() < 20 {
            return Ok(Vec::new());
        }

        let values: Vec<f64> = series.data_points.iter().map(|p| p.value).collect();
        let mut change_points = Vec::new();

        // Use CUSUM (Cumulative Sum) algorithm for change point detection
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let variance = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / values.len() as f64;
        let std_dev = variance.sqrt();

        if std_dev == 0.0 {
            return Ok(change_points);
        }

        let threshold = self.change_point_sensitivity * std_dev;
        let mut cusum_pos = 0.0;
        let mut cusum_neg = 0.0;

        for (i, &value) in values.iter().enumerate().skip(1) {
            let deviation = value - mean;

            cusum_pos = (cusum_pos + deviation - threshold).max(0.0);
            cusum_neg = (cusum_neg - deviation - threshold).max(0.0);

            if cusum_pos > threshold || cusum_neg > threshold {
                let change_magnitude = if cusum_pos > cusum_neg {
                    cusum_pos
                } else {
                    -cusum_neg
                };
                let confidence = self.calculate_change_point_confidence(change_magnitude, std_dev);

                if confidence > 0.8 {
                    change_points.push(ChangePoint {
                        timestamp: series.data_points[i].timestamp,
                        change_magnitude,
                        confidence,
                        change_type: self.classify_change_type(change_magnitude, &values, i),
                    });

                    // Reset CUSUM after detecting a change point
                    cusum_pos = 0.0;
                    cusum_neg = 0.0;
                }
            }
        }

        debug!(
            "Detected {} change points for user {}",
            change_points.len(),
            series.user_id
        );
        Ok(change_points)
    }

    /// Analyze seasonality patterns in behavioral data
    pub async fn analyze_seasonality(
        &self,
        series: &BehavioralTimeSeries,
    ) -> Result<SeasonalityAnalysis, Box<dyn std::error::Error + Send + Sync>> {
        if series.data_points.len() < self.seasonality_periods.iter().max().unwrap_or(&24) * 2 {
            return Ok(SeasonalityAnalysis::default());
        }

        let values: Vec<f64> = series.data_points.iter().map(|p| p.value).collect();
        let mut periods = Vec::new();
        let mut max_strength = 0.0;
        let mut dominant_period = None;

        for &period_length in &self.seasonality_periods {
            if values.len() >= period_length * 2 {
                let (amplitude, phase, confidence) =
                    self.detect_seasonality(&values, period_length);

                if confidence > 0.3 {
                    let seasonal_period = SeasonalPeriod {
                        period_length,
                        amplitude,
                        phase,
                        confidence,
                    };

                    if confidence > max_strength {
                        max_strength = confidence;
                        dominant_period = Some(seasonal_period.clone());
                    }

                    periods.push(seasonal_period);
                }
            }
        }

        Ok(SeasonalityAnalysis {
            periods,
            dominant_period,
            seasonality_strength: max_strength,
        })
    }

    /// Calculate percentile value from data
    fn calculate_percentile(&self, values: &[f64], percentile: f64) -> f64 {
        if values.is_empty() {
            return 0.0;
        }

        let mut sorted_values = values.to_vec();
        sorted_values.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let index = (percentile * (sorted_values.len() - 1) as f64) as usize;
        sorted_values[index.min(sorted_values.len() - 1)]
    }

    /// Calculate trend slope using linear regression
    fn calculate_trend_slope(&self, values: &[f64]) -> f64 {
        if values.len() < 2 {
            return 0.0;
        }

        let x_values: Vec<f64> = (0..values.len()).map(|i| i as f64).collect();
        let regression = self.linear_regression(&x_values, values);
        regression.slope
    }

    /// Calculate seasonality strength
    fn calculate_seasonality_strength(&self, values: &[f64]) -> f64 {
        if values.len() < 24 {
            return 0.0;
        }

        // Use autocorrelation to detect seasonality
        let mut max_correlation: f64 = 0.0;

        for lag in 1..=values.len().min(168) {
            // Check up to weekly patterns
            let correlation = self.calculate_autocorrelation(values, lag);
            max_correlation = max_correlation.max(correlation.abs());
        }

        max_correlation
    }

    /// Perform linear regression analysis
    fn linear_regression(&self, x_values: &[f64], y_values: &[f64]) -> LinearRegressionResult {
        if x_values.len() != y_values.len() || x_values.len() < 2 {
            return LinearRegressionResult {
                slope: 0.0,
                intercept: 0.0,
                r_squared: 0.0,
                p_value: 1.0,
                residuals: Vec::new(),
            };
        }

        let n = x_values.len() as f64;
        let sum_x: f64 = x_values.iter().sum();
        let sum_y: f64 = y_values.iter().sum();
        let sum_xy: f64 = x_values
            .iter()
            .zip(y_values.iter())
            .map(|(x, y)| x * y)
            .sum();
        let sum_x_squared: f64 = x_values.iter().map(|x| x * x).sum();
        let _sum_y_squared: f64 = y_values.iter().map(|y| y * y).sum();

        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x_squared - sum_x * sum_x);
        let intercept = (sum_y - slope * sum_x) / n;

        // Calculate R-squared
        let y_mean = sum_y / n;
        let ss_tot: f64 = y_values.iter().map(|y| (y - y_mean).powi(2)).sum();
        let ss_res: f64 = x_values
            .iter()
            .zip(y_values.iter())
            .map(|(x, y)| (y - (slope * x + intercept)).powi(2))
            .sum();

        let r_squared = if ss_tot > 0.0 {
            1.0 - (ss_res / ss_tot)
        } else {
            0.0
        };

        // Calculate residuals
        let residuals: Vec<f64> = x_values
            .iter()
            .zip(y_values.iter())
            .map(|(x, y)| y - (slope * x + intercept))
            .collect();

        // Simple p-value calculation (would need more sophisticated method in production)
        let p_value = if r_squared > 0.5 {
            0.01
        } else if r_squared > 0.3 {
            0.05
        } else {
            0.1
        };

        LinearRegressionResult {
            slope,
            intercept,
            r_squared,
            p_value,
            residuals,
        }
    }

    /// Calculate autocorrelation at a specific lag
    fn calculate_autocorrelation(&self, values: &[f64], lag: usize) -> f64 {
        if lag >= values.len() {
            return 0.0;
        }

        let mean = values.mean();
        let variance = values.variance();

        if variance == 0.0 {
            return 0.0;
        }

        let covariance: f64 = values
            .iter()
            .take(values.len() - lag)
            .zip(values.iter().skip(lag))
            .map(|(x, y)| (x - mean) * (y - mean))
            .sum::<f64>()
            / (values.len() - lag) as f64;

        covariance / variance
    }

    /// Detect seasonality with specific period length
    fn detect_seasonality(&self, values: &[f64], period_length: usize) -> (f64, f64, f64) {
        if values.len() < period_length * 2 {
            return (0.0, 0.0, 0.0);
        }

        // Calculate seasonal decomposition
        let mut seasonal_component = vec![0.0; period_length];
        let cycles = values.len() / period_length;

        for i in 0..period_length {
            let mut sum = 0.0;
            let mut count = 0;

            for cycle in 0..cycles {
                let index = cycle * period_length + i;
                if index < values.len() {
                    sum += values[index];
                    count += 1;
                }
            }

            if count > 0 {
                seasonal_component[i] = sum / count as f64;
            }
        }

        // Calculate amplitude (range of seasonal component)
        let min_seasonal = seasonal_component
            .iter()
            .fold(f64::INFINITY, |a, &b| a.min(b));
        let max_seasonal = seasonal_component
            .iter()
            .fold(f64::NEG_INFINITY, |a, &b| a.max(b));
        let amplitude = max_seasonal - min_seasonal;

        // Calculate phase (position of maximum)
        let max_index = seasonal_component
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
            .map(|(i, _)| i)
            .unwrap_or(0);
        let phase = max_index as f64 / period_length as f64 * 2.0 * std::f64::consts::PI;

        // Calculate confidence based on consistency across cycles
        let mut confidence = 0.0;
        if cycles > 1 {
            let mut consistency_scores = Vec::new();

            for cycle in 1..cycles {
                let mut correlation_sum = 0.0;
                for i in 0..period_length {
                    let current_index = cycle * period_length + i;
                    let prev_index = (cycle - 1) * period_length + i;

                    if current_index < values.len() && prev_index < values.len() {
                        correlation_sum += (values[current_index] - values[prev_index]).abs();
                    }
                }
                consistency_scores.push(correlation_sum / period_length as f64);
            }

            let mean_consistency = consistency_scores.mean();
            confidence = if mean_consistency > 0.0 {
                1.0 / (1.0 + mean_consistency)
            } else {
                1.0
            };
        }

        (amplitude, phase, confidence)
    }

    /// Calculate confidence for change point detection
    fn calculate_change_point_confidence(&self, change_magnitude: f64, std_dev: f64) -> f64 {
        if std_dev == 0.0 {
            return 0.0;
        }

        let z_score = change_magnitude.abs() / std_dev;
        // Simple approximation instead of requiring statrs dependency
        let confidence = 1.0 - (-z_score * z_score / 2.0).exp();
        confidence.min(1.0).max(0.0)
    }

    /// Classify the type of change detected
    fn classify_change_type(
        &self,
        change_magnitude: f64,
        values: &[f64],
        change_index: usize,
    ) -> ChangeType {
        let window_size = 10.min(change_index).min(values.len() - change_index);

        if window_size < 3 {
            return ChangeType::Anomaly;
        }

        let before_mean = values[change_index.saturating_sub(window_size)..change_index].mean();
        let after_mean = values[change_index..change_index + window_size].mean();
        let before_var = values[change_index.saturating_sub(window_size)..change_index].variance();
        let after_var = values[change_index..change_index + window_size].variance();

        let mean_change = (after_mean - before_mean).abs();
        let var_change = (after_var - before_var).abs();

        if mean_change > var_change * 2.0 {
            ChangeType::MeanShift
        } else if var_change > mean_change * 2.0 {
            ChangeType::VarianceChange
        } else if change_magnitude.abs() > values.std_dev() * 3.0 {
            ChangeType::Anomaly
        } else {
            ChangeType::TrendChange
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_time_series_analysis() {
        let analyzer = TimeSeriesAnalyzer::new(100, vec![24, 168], 0.05);

        // Create test time series with trend and noise
        let mut data_points = VecDeque::new();
        for i in 0..50 {
            data_points.push_back(TimeSeriesPoint {
                timestamp: Utc::now(),
                value: i as f64 * 0.1 + (i as f64 * 0.2).sin(), // Linear trend + sine wave
                metadata: HashMap::new(),
            });
        }

        let series = BehavioralTimeSeries {
            user_id: uuid::Uuid::new_v4(),
            feature_name: "login_frequency".to_string(),
            data_points,
            window_size: 100,
            statistics: None,
        };

        let stats = analyzer.analyze_series(&series).await.unwrap();
        assert!(stats.mean > 0.0);
        assert!(stats.std_dev > 0.0);
        assert!(stats.trend_slope > 0.0); // Should detect positive trend

        let trend = analyzer.analyze_trend(&series).await.unwrap();
        assert!(matches!(trend.trend_direction, TrendDirection::Increasing));
    }
}
