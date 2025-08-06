//! Congestion control module for Hysteria protocol
//!
//! Implements bandwidth-based congestion control as specified
//! in the Hysteria 2 protocol, including Brutal and BBR algorithms.

use crate::{HysteriaError, Result};
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use tokio::time::interval;

/// Congestion control configuration
#[derive(Debug, Clone)]
pub struct CongestionConfig {
    /// Maximum receive rate in bytes per second (0 = unlimited)
    pub max_rx_rate: u64,
    /// Maximum transmit rate in bytes per second (0 = unlimited)
    pub max_tx_rate: u64,
    /// Whether to use automatic congestion control
    pub auto_mode: bool,
    /// Measurement window duration
    pub measurement_window: Duration,
}

impl Default for CongestionConfig {
    fn default() -> Self {
        Self {
            max_rx_rate: 0, // Unlimited
            max_tx_rate: 0, // Unlimited
            auto_mode: false,
            measurement_window: Duration::from_secs(1),
        }
    }
}

/// Congestion controller for rate limiting
#[derive(Debug)]
pub struct CongestionController {
    config: CongestionConfig,
    tx_stats: TrafficStats,
    rx_stats: TrafficStats,
    last_update: Instant,
}

/// Traffic statistics for bandwidth measurement
#[derive(Debug, Clone)]
struct TrafficStats {
    bytes_transferred: u64,
    last_measurement: Instant,
    current_rate: f64, // bytes per second
    rate_history: Vec<f64>,
    max_history_size: usize,
}

impl TrafficStats {
    fn new() -> Self {
        Self {
            bytes_transferred: 0,
            last_measurement: Instant::now(),
            current_rate: 0.0,
            rate_history: Vec::new(),
            max_history_size: 10,
        }
    }

    fn update(&mut self, bytes: u64) {
        self.bytes_transferred += bytes;
        
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_measurement);
        
        if elapsed >= Duration::from_millis(100) {
            // Calculate current rate
            let rate = self.bytes_transferred as f64 / elapsed.as_secs_f64();
            self.current_rate = rate;
            
            // Update history
            self.rate_history.push(rate);
            if self.rate_history.len() > self.max_history_size {
                self.rate_history.remove(0);
            }
            
            // Reset for next measurement
            self.bytes_transferred = 0;
            self.last_measurement = now;
        }
    }

    fn get_average_rate(&self) -> f64 {
        if self.rate_history.is_empty() {
            self.current_rate
        } else {
            self.rate_history.iter().sum::<f64>() / self.rate_history.len() as f64
        }
    }
}

impl CongestionController {
    /// Create a new congestion controller
    pub fn new(config: CongestionConfig) -> Self {
        Self {
            config,
            tx_stats: TrafficStats::new(),
            rx_stats: TrafficStats::new(),
            last_update: Instant::now(),
        }
    }

    /// Record transmitted bytes
    pub fn record_tx(&mut self, bytes: u64) {
        self.tx_stats.update(bytes);
    }

    /// Record received bytes
    pub fn record_rx(&mut self, bytes: u64) {
        self.rx_stats.update(bytes);
    }

    /// Check if transmission should be throttled
    pub fn should_throttle_tx(&self) -> bool {
        if self.config.max_tx_rate == 0 || self.config.auto_mode {
            return false;
        }
        
        let current_rate = self.tx_stats.get_average_rate();
        current_rate > self.config.max_tx_rate as f64
    }

    /// Check if reception should be throttled
    pub fn should_throttle_rx(&self) -> bool {
        if self.config.max_rx_rate == 0 || self.config.auto_mode {
            return false;
        }
        
        let current_rate = self.rx_stats.get_average_rate();
        current_rate > self.config.max_rx_rate as f64
    }

    /// Get current transmission rate
    pub fn get_tx_rate(&self) -> f64 {
        self.tx_stats.get_average_rate()
    }

    /// Get current reception rate
    pub fn get_rx_rate(&self) -> f64 {
        self.rx_stats.get_average_rate()
    }

    /// Calculate delay needed for rate limiting
    pub fn calculate_tx_delay(&self, bytes: u64) -> Duration {
        if self.config.max_tx_rate == 0 || self.config.auto_mode {
            return Duration::ZERO;
        }
        
        let current_rate = self.tx_stats.get_average_rate();
        if current_rate <= self.config.max_tx_rate as f64 {
            return Duration::ZERO;
        }
        
        // Calculate delay to maintain target rate
        let target_interval = bytes as f64 / self.config.max_tx_rate as f64;
        Duration::from_secs_f64(target_interval)
    }

    /// Calculate delay needed for reception rate limiting
    pub fn calculate_rx_delay(&self, bytes: u64) -> Duration {
        if self.config.max_rx_rate == 0 || self.config.auto_mode {
            return Duration::ZERO;
        }
        
        let current_rate = self.rx_stats.get_average_rate();
        if current_rate <= self.config.max_rx_rate as f64 {
            return Duration::ZERO;
        }
        
        // Calculate delay to maintain target rate
        let target_interval = bytes as f64 / self.config.max_rx_rate as f64;
        Duration::from_secs_f64(target_interval)
    }

    /// Update configuration
    pub fn update_config(&mut self, config: CongestionConfig) {
        self.config = config;
    }

    /// Get current configuration
    pub fn get_config(&self) -> &CongestionConfig {
        &self.config
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.tx_stats = TrafficStats::new();
        self.rx_stats = TrafficStats::new();
        self.last_update = Instant::now();
    }
}

/// Rate limiter for controlling transmission rate
#[derive(Debug)]
pub struct RateLimiter {
    rate: u64, // bytes per second
    bucket_size: u64,
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(rate: u64) -> Self {
        let bucket_size = rate.max(1024); // At least 1KB bucket
        Self {
            rate,
            bucket_size,
            tokens: bucket_size as f64,
            last_refill: Instant::now(),
        }
    }

    /// Check if the given number of bytes can be transmitted
    pub fn can_transmit(&mut self, bytes: u64) -> bool {
        self.refill_tokens();
        self.tokens >= bytes as f64
    }

    /// Consume tokens for transmission
    pub fn consume(&mut self, bytes: u64) -> Result<()> {
        self.refill_tokens();
        
        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            Ok(())
        } else {
            Err(HysteriaError::congestion_control(
                "Insufficient tokens for transmission".to_string(),
            ))
        }
    }

    /// Calculate delay until enough tokens are available
    pub fn delay_until_available(&mut self, bytes: u64) -> Duration {
        self.refill_tokens();
        
        if self.tokens >= bytes as f64 {
            return Duration::ZERO;
        }
        
        let needed_tokens = bytes as f64 - self.tokens;
        let refill_time = needed_tokens / self.rate as f64;
        Duration::from_secs_f64(refill_time)
    }

    /// Refill token bucket based on elapsed time
    fn refill_tokens(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        
        let new_tokens = elapsed.as_secs_f64() * self.rate as f64;
        self.tokens = (self.tokens + new_tokens).min(self.bucket_size as f64);
        self.last_refill = now;
    }

    /// Update rate limit
    pub fn update_rate(&mut self, rate: u64) {
        self.rate = rate;
        self.bucket_size = rate.max(1024);
        // Adjust tokens if bucket size changed
        self.tokens = self.tokens.min(self.bucket_size as f64);
    }
}

/// Bandwidth measurement utility
#[derive(Debug)]
pub struct BandwidthMeter {
    measurements: Vec<(Instant, u64)>,
    window_duration: Duration,
}

impl BandwidthMeter {
    /// Create a new bandwidth meter
    pub fn new(window_duration: Duration) -> Self {
        Self {
            measurements: Vec::new(),
            window_duration,
        }
    }

    /// Record a data transfer
    pub fn record(&mut self, bytes: u64) {
        let now = Instant::now();
        self.measurements.push((now, bytes));
        self.cleanup_old_measurements(now);
    }

    /// Get current bandwidth in bytes per second
    pub fn get_bandwidth(&mut self) -> f64 {
        let now = Instant::now();
        self.cleanup_old_measurements(now);
        
        if self.measurements.is_empty() {
            return 0.0;
        }
        
        let total_bytes: u64 = self.measurements.iter().map(|(_, bytes)| bytes).sum();
        let oldest_time = self.measurements.first().unwrap().0;
        let duration = now.duration_since(oldest_time);
        
        if duration.is_zero() {
            0.0
        } else {
            total_bytes as f64 / duration.as_secs_f64()
        }
    }

    /// Remove measurements outside the window
    fn cleanup_old_measurements(&mut self, now: Instant) {
        let cutoff = now - self.window_duration;
        self.measurements.retain(|(time, _)| *time >= cutoff);
    }
}

/// Brutal congestion control algorithm implementation
/// Based on ACK rate monitoring and dynamic rate adjustment
#[derive(Debug)]
pub struct BrutalSender {
    /// Target bandwidth in bytes per second
    bps: u64,
    /// Maximum datagram size
    max_datagram_size: u64,
    /// Current ACK rate (0.0 to 1.0)
    ack_rate: f64,
    /// Packet information slots for tracking ACK/loss statistics
    pkt_info_slots: [PacketInfo; PKT_INFO_SLOT_COUNT],
    /// Pacer for controlling transmission rate
    pacer: Pacer,
    /// RTT statistics
    smoothed_rtt: Duration,
    /// Debug mode
    debug: bool,
    /// Last debug print timestamp
    last_debug_print: Instant,
}

/// Packet information for tracking ACK/loss statistics
#[derive(Debug, Clone, Copy)]
struct PacketInfo {
    timestamp: i64,
    ack_count: u64,
    loss_count: u64,
}

/// Pacer for controlling packet transmission rate
#[derive(Debug)]
struct Pacer {
    budget_at_last_sent: u64,
    max_datagram_size: u64,
    last_sent_time: Option<Instant>,
    get_bandwidth: fn(&BrutalSender) -> u64,
}

// Constants for Brutal algorithm
const PKT_INFO_SLOT_COUNT: usize = 5;
const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
const CONGESTION_WINDOW_MULTIPLIER: f64 = 2.0;
const DEBUG_PRINT_INTERVAL: Duration = Duration::from_secs(2);
const MAX_BURST_PACKETS: u64 = 10;
const INITIAL_PACKET_SIZE: u64 = 1200;

impl Default for PacketInfo {
    fn default() -> Self {
        Self {
            timestamp: 0,
            ack_count: 0,
            loss_count: 0,
        }
    }
}

impl BrutalSender {
    /// Create a new Brutal sender with specified bandwidth
    pub fn new(bps: u64) -> Self {
        let debug = std::env::var("HYSTERIA_BRUTAL_DEBUG")
            .map(|v| v.parse().unwrap_or(false))
            .unwrap_or(false);
        
        let mut sender = Self {
            bps,
            max_datagram_size: INITIAL_PACKET_SIZE,
            ack_rate: 1.0,
            pkt_info_slots: [PacketInfo::default(); PKT_INFO_SLOT_COUNT],
            pacer: Pacer::new(),
            smoothed_rtt: Duration::from_millis(100), // Default RTT
            debug,
            last_debug_print: Instant::now(),
        };
        
        sender.pacer.set_max_datagram_size(INITIAL_PACKET_SIZE);
        sender
    }
    
    /// Set RTT statistics
    pub fn set_rtt(&mut self, rtt: Duration) {
        self.smoothed_rtt = rtt;
    }
    
    /// Get time until next packet can be sent
    pub fn time_until_send(&self) -> Option<Duration> {
        self.pacer.time_until_send()
    }
    
    /// Check if there's pacing budget available
    pub fn has_pacing_budget(&self) -> bool {
        self.pacer.budget() >= self.max_datagram_size
    }
    
    /// Check if packet can be sent based on congestion window
    pub fn can_send(&self, bytes_in_flight: u64) -> bool {
        bytes_in_flight <= self.get_congestion_window()
    }
    
    /// Get current congestion window size
    pub fn get_congestion_window(&self) -> u64 {
        if self.smoothed_rtt.is_zero() {
            return 10240; // Default window
        }
        
        let cwnd = (self.bps as f64 * self.smoothed_rtt.as_secs_f64() 
                   * CONGESTION_WINDOW_MULTIPLIER / self.ack_rate) as u64;
        
        cwnd.max(self.max_datagram_size)
    }
    
    /// Record packet sent
    pub fn on_packet_sent(&mut self, sent_time: Instant, bytes: u64) {
        self.pacer.sent_packet(sent_time, bytes);
    }
    
    /// Handle congestion event with ACK and loss information
    pub fn on_congestion_event(&mut self, event_time: Instant, acked_packets: &[u64], lost_packets: &[u64]) {
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO).as_secs() as i64;
        
        let slot = (current_timestamp % PKT_INFO_SLOT_COUNT as i64) as usize;
        
        if self.pkt_info_slots[slot].timestamp == current_timestamp {
            self.pkt_info_slots[slot].loss_count += lost_packets.len() as u64;
            self.pkt_info_slots[slot].ack_count += acked_packets.len() as u64;
        } else {
            // Reset slot for new timestamp
            self.pkt_info_slots[slot] = PacketInfo {
                timestamp: current_timestamp,
                ack_count: acked_packets.len() as u64,
                loss_count: lost_packets.len() as u64,
            };
        }
        
        self.update_ack_rate(current_timestamp);
    }
    
    /// Set maximum datagram size
    pub fn set_max_datagram_size(&mut self, size: u64) {
        self.max_datagram_size = size;
        self.pacer.set_max_datagram_size(size);
        
        if self.debug {
            self.debug_print(&format!("SetMaxDatagramSize: {}", size));
        }
    }
    
    /// Update ACK rate based on recent packet statistics
    fn update_ack_rate(&mut self, current_timestamp: i64) {
        let min_timestamp = current_timestamp - PKT_INFO_SLOT_COUNT as i64;
        let mut ack_count = 0u64;
        let mut loss_count = 0u64;
        
        for info in &self.pkt_info_slots {
            if info.timestamp < min_timestamp {
                continue;
            }
            ack_count += info.ack_count;
            loss_count += info.loss_count;
        }
        
        let total_count = ack_count + loss_count;
        
        if total_count < MIN_SAMPLE_COUNT {
            self.ack_rate = 1.0;
            if self.can_print_debug() {
                self.debug_print(&format!(
                    "Not enough samples (total={}, ack={}, loss={}, rtt={}ms)",
                    total_count, ack_count, loss_count, self.smoothed_rtt.as_millis()
                ));
            }
            return;
        }
        
        let rate = ack_count as f64 / total_count as f64;
        
        if rate < MIN_ACK_RATE {
            self.ack_rate = MIN_ACK_RATE;
            if self.can_print_debug() {
                self.debug_print(&format!(
                    "ACK rate too low: {:.2}, clamped to {:.2} (total={}, ack={}, loss={}, rtt={}ms)",
                    rate, MIN_ACK_RATE, total_count, ack_count, loss_count, self.smoothed_rtt.as_millis()
                ));
            }
        } else {
            self.ack_rate = rate;
            if self.can_print_debug() {
                self.debug_print(&format!(
                    "ACK rate: {:.2} (total={}, ack={}, loss={}, rtt={}ms)",
                    rate, total_count, ack_count, loss_count, self.smoothed_rtt.as_millis()
                ));
            }
        }
    }
    
    /// Check if debug printing is allowed
    fn can_print_debug(&mut self) -> bool {
        if !self.debug {
            return false;
        }
        
        let now = Instant::now();
        if now.duration_since(self.last_debug_print) >= DEBUG_PRINT_INTERVAL {
            self.last_debug_print = now;
            true
        } else {
            false
        }
    }
    
    /// Print debug message
    fn debug_print(&self, message: &str) {
        if self.debug {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO);
            println!("[BrutalSender] [{}] {}", 
                now.as_secs() % 86400, message); // Show seconds since midnight
        }
    }
    
    /// Get current bandwidth adjusted by ACK rate
    fn get_adjusted_bandwidth(&self) -> u64 {
        (self.bps as f64 / self.ack_rate) as u64
    }
}

impl Pacer {
    fn new() -> Self {
        Self {
            budget_at_last_sent: MAX_BURST_PACKETS * INITIAL_PACKET_SIZE,
            max_datagram_size: INITIAL_PACKET_SIZE,
            last_sent_time: None,
            get_bandwidth: |sender| sender.get_adjusted_bandwidth(),
        }
    }
    
    fn sent_packet(&mut self, send_time: Instant, size: u64) {
        let budget = self.budget();
        if size > budget {
            self.budget_at_last_sent = 0;
        } else {
            self.budget_at_last_sent = budget - size;
        }
        self.last_sent_time = Some(send_time);
    }
    
    fn budget(&self) -> u64 {
        if let Some(last_sent) = self.last_sent_time {
            let now = Instant::now();
            let elapsed = now.duration_since(last_sent);
            let bandwidth = 1000000; // Placeholder - should get from sender
            
            let new_budget = self.budget_at_last_sent + 
                (bandwidth * elapsed.as_nanos() as u64) / 1_000_000_000;
            
            new_budget.min(self.max_burst_size())
        } else {
            self.max_burst_size()
        }
    }
    
    fn max_burst_size(&self) -> u64 {
        MAX_BURST_PACKETS * self.max_datagram_size
    }
    
    fn time_until_send(&self) -> Option<Duration> {
        if self.budget_at_last_sent >= self.max_datagram_size {
            return None;
        }
        
        if let Some(last_sent) = self.last_sent_time {
            let needed = self.max_datagram_size - self.budget_at_last_sent;
            let bandwidth = 1000000; // Placeholder
            let delay_nanos = (needed * 1_000_000_000) / bandwidth;
            
            Some(Duration::from_nanos(delay_nanos.max(1_000_000))) // Min 1ms
        } else {
            None
        }
    }
    
    fn set_max_datagram_size(&mut self, size: u64) {
        self.max_datagram_size = size;
    }
}

/// BBR congestion control algorithm implementation
/// Estimates bottleneck bandwidth and RTT for optimal performance
#[derive(Debug)]
pub struct BbrSender {
    /// Current BBR mode
    mode: BbrMode,
    /// Bandwidth sampler for measurements
    bandwidth_sampler: BandwidthSampler,
    /// Maximum bandwidth filter
    max_bandwidth: WindowedFilter,
    /// Minimum RTT
    min_rtt: Duration,
    /// Minimum RTT timestamp
    min_rtt_timestamp: Instant,
    /// Congestion window
    congestion_window: u64,
    /// Initial congestion window
    initial_congestion_window: u64,
    /// Maximum congestion window
    max_congestion_window: u64,
    /// Minimum congestion window
    min_congestion_window: u64,
    /// Current pacing rate
    pacing_rate: u64,
    /// Pacing gain
    pacing_gain: f64,
    /// Congestion window gain
    congestion_window_gain: f64,
    /// High gain for startup
    high_gain: f64,
    /// High CWND gain for startup
    high_cwnd_gain: f64,
    /// Drain gain
    drain_gain: f64,
    /// Round trip count
    round_trip_count: u64,
    /// Last sent packet number
    last_sent_packet: u64,
    /// Current round trip end
    current_round_trip_end: u64,
    /// Is at full bandwidth
    is_at_full_bandwidth: bool,
    /// Rounds without bandwidth gain
    rounds_without_bandwidth_gain: u64,
    /// Bandwidth at last round
    bandwidth_at_last_round: u64,
    /// Cycle current offset for PROBE_BW
    cycle_current_offset: usize,
    /// Last cycle start time
    last_cycle_start: Instant,
    /// Exit PROBE_RTT time
    exit_probe_rtt_at: Option<Instant>,
    /// PROBE_RTT round passed
    probe_rtt_round_passed: bool,
    /// Recovery state
    recovery_state: BbrRecoveryState,
    /// End recovery at packet number
    end_recovery_at: u64,
    /// Recovery window
    recovery_window: u64,
    /// Maximum datagram size
    max_datagram_size: u64,
    /// Bytes in flight
    bytes_in_flight: u64,
    /// Smoothed RTT
    smoothed_rtt: Duration,
    /// Debug mode
    debug: bool,
}

/// BBR operating modes
#[derive(Debug, Clone, Copy, PartialEq)]
enum BbrMode {
    /// Startup phase - aggressive bandwidth probing
    Startup,
    /// Drain phase - reduce queue after startup
    Drain,
    /// Probe bandwidth - steady state operation
    ProbeBw,
    /// Probe RTT - measure minimum RTT
    ProbeRtt,
}

/// BBR recovery states
#[derive(Debug, Clone, Copy, PartialEq)]
enum BbrRecoveryState {
    /// Not in recovery
    NotInRecovery,
    /// Conservation mode
    Conservation,
    /// Growth mode
    Growth,
}

/// Bandwidth sampler for BBR
#[derive(Debug)]
struct BandwidthSampler {
    samples: VecDeque<BandwidthSample>,
    total_bytes_sent: u64,
    total_bytes_acked: u64,
    last_acked_packet: u64,
}

/// Individual bandwidth sample
#[derive(Debug, Clone)]
struct BandwidthSample {
    bandwidth: u64,
    rtt: Duration,
    timestamp: Instant,
    bytes_sent: u64,
    bytes_acked: u64,
    is_app_limited: bool,
}

/// Windowed filter for tracking maximum values
#[derive(Debug)]
struct WindowedFilter {
    estimates: VecDeque<(u64, u64)>, // (value, round)
    window_size: usize,
}

// BBR constants
const BBR_MIN_BPS: u64 = 65536; // 64 kbps
const BBR_INITIAL_CWND_PACKETS: u64 = 32;
const BBR_DEFAULT_MIN_CWND: u64 = 4 * 1200; // 4 packets
const BBR_DEFAULT_HIGH_GAIN: f64 = 2.885;
const BBR_DERIVED_HIGH_GAIN: f64 = 2.773;
const BBR_DERIVED_HIGH_CWND_GAIN: f64 = 2.0;
const BBR_DRAIN_GAIN: f64 = 1.0 / BBR_DEFAULT_HIGH_GAIN;
const BBR_PACING_GAIN_CYCLE: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
const BBR_GAIN_CYCLE_LENGTH: usize = BBR_PACING_GAIN_CYCLE.len();
const BBR_BANDWIDTH_WINDOW_SIZE: usize = BBR_GAIN_CYCLE_LENGTH + 2;
const BBR_MIN_RTT_EXPIRY: Duration = Duration::from_secs(10);
const BBR_PROBE_RTT_TIME: Duration = Duration::from_millis(200);
const BBR_STARTUP_GROWTH_TARGET: f64 = 1.25;
const BBR_ROUNDS_WITHOUT_GROWTH_BEFORE_EXIT: u64 = 3;

impl BbrSender {
    /// Create a new BBR sender
    pub fn new(initial_max_datagram_size: u64) -> Self {
        let debug = std::env::var("HYSTERIA_BBR_DEBUG")
            .map(|v| v.parse().unwrap_or(false))
            .unwrap_or(false);
        
        let initial_cwnd = BBR_INITIAL_CWND_PACKETS * initial_max_datagram_size;
        let max_cwnd = initial_cwnd * 10; // Reasonable upper bound
        
        Self {
            mode: BbrMode::Startup,
            bandwidth_sampler: BandwidthSampler::new(),
            max_bandwidth: WindowedFilter::new(BBR_BANDWIDTH_WINDOW_SIZE),
            min_rtt: Duration::ZERO,
            min_rtt_timestamp: Instant::now(),
            congestion_window: initial_cwnd,
            initial_congestion_window: initial_cwnd,
            max_congestion_window: max_cwnd,
            min_congestion_window: BBR_DEFAULT_MIN_CWND,
            pacing_rate: BBR_MIN_BPS,
            pacing_gain: BBR_DEFAULT_HIGH_GAIN,
            congestion_window_gain: BBR_DERIVED_HIGH_CWND_GAIN,
            high_gain: BBR_DEFAULT_HIGH_GAIN,
            high_cwnd_gain: BBR_DERIVED_HIGH_CWND_GAIN,
            drain_gain: BBR_DRAIN_GAIN,
            round_trip_count: 0,
            last_sent_packet: 0,
            current_round_trip_end: 0,
            is_at_full_bandwidth: false,
            rounds_without_bandwidth_gain: 0,
            bandwidth_at_last_round: 0,
            cycle_current_offset: 0,
            last_cycle_start: Instant::now(),
            exit_probe_rtt_at: None,
            probe_rtt_round_passed: false,
            recovery_state: BbrRecoveryState::NotInRecovery,
            end_recovery_at: 0,
            recovery_window: 0,
            max_datagram_size: initial_max_datagram_size,
            bytes_in_flight: 0,
            smoothed_rtt: Duration::from_millis(100),
            debug,
        }
    }
    
    /// Set RTT statistics
    pub fn set_rtt(&mut self, rtt: Duration) {
        self.smoothed_rtt = rtt;
        self.maybe_update_min_rtt(Instant::now(), rtt);
    }
    
    /// Get congestion window
    pub fn get_congestion_window(&self) -> u64 {
        if self.recovery_state != BbrRecoveryState::NotInRecovery {
            return self.recovery_window.min(self.congestion_window);
        }
        self.congestion_window
    }
    
    /// Check if can send packet
    pub fn can_send(&self, bytes_in_flight: u64) -> bool {
        bytes_in_flight <= self.get_congestion_window()
    }
    
    /// Record packet sent
    pub fn on_packet_sent(&mut self, sent_time: Instant, packet_number: u64, bytes: u64, is_retransmittable: bool) {
        self.last_sent_packet = packet_number;
        if is_retransmittable {
            self.bytes_in_flight += bytes;
        }
        self.bandwidth_sampler.on_packet_sent(sent_time, packet_number, bytes);
    }
    
    /// Handle packet acknowledgment
    pub fn on_packet_acked(&mut self, packet_number: u64, acked_bytes: u64, prior_in_flight: u64, event_time: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);
        
        let sample_rtt = if let Some(sample) = self.bandwidth_sampler.on_packet_acked(packet_number, acked_bytes, event_time) {
            let rtt = sample.rtt;
            self.on_bandwidth_sample(sample.clone());
            rtt
        } else {
            self.smoothed_rtt
        };
        
        self.update_round_trip_counter(packet_number);
        self.maybe_update_min_rtt(event_time, sample_rtt);
    }
    
    /// Handle packet loss
    pub fn on_packet_lost(&mut self, packet_number: u64, lost_bytes: u64, prior_in_flight: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        self.bandwidth_sampler.on_packet_lost(packet_number);
    }
    
    /// Set maximum datagram size
    pub fn set_max_datagram_size(&mut self, size: u64) {
        self.max_datagram_size = size;
        if self.debug {
            println!("[BbrSender] SetMaxDatagramSize: {}", size);
        }
    }
    
    /// Get current pacing rate
    pub fn pacing_rate(&self) -> u64 {
        self.pacing_rate
    }
    
    /// Check if in slow start
    pub fn in_slow_start(&self) -> bool {
        self.mode == BbrMode::Startup
    }
    
    /// Check if in recovery
    pub fn in_recovery(&self) -> bool {
        self.recovery_state != BbrRecoveryState::NotInRecovery
    }
    
    // Private helper methods
    
    fn on_bandwidth_sample(&mut self, sample: BandwidthSample) {
        if !sample.is_app_limited {
            self.max_bandwidth.update(sample.bandwidth, self.round_trip_count);
        }
        
        self.update_model_and_state(sample);
    }
    
    fn update_model_and_state(&mut self, sample: BandwidthSample) {
        self.update_congestion_signals(&sample);
        self.update_ack_aggregation();
        self.check_if_full_bandwidth_reached();
        self.maybe_exit_startup_or_drain();
        self.maybe_enter_or_exit_probe_rtt();
        self.update_gains_and_pacing_rate();
        self.update_congestion_window(sample.bytes_acked);
    }
    
    fn update_round_trip_counter(&mut self, last_acked_packet: u64) -> bool {
        if last_acked_packet > self.current_round_trip_end {
            self.round_trip_count += 1;
            self.current_round_trip_end = self.last_sent_packet;
            true
        } else {
            false
        }
    }
    
    fn maybe_update_min_rtt(&mut self, now: Instant, sample_rtt: Duration) -> bool {
        if self.min_rtt.is_zero() || sample_rtt < self.min_rtt {
            self.min_rtt = sample_rtt;
            self.min_rtt_timestamp = now;
            true
        } else {
            false
        }
    }
    
    // Placeholder implementations for complex BBR logic
    fn update_congestion_signals(&mut self, _sample: &BandwidthSample) {}
    fn update_ack_aggregation(&mut self) {}
    fn check_if_full_bandwidth_reached(&mut self) {}
    fn maybe_exit_startup_or_drain(&mut self) {}
    fn maybe_enter_or_exit_probe_rtt(&mut self) {}
    fn update_gains_and_pacing_rate(&mut self) {}
    fn update_congestion_window(&mut self, _bytes_acked: u64) {}
}

impl BandwidthSampler {
    fn new() -> Self {
        Self {
            samples: VecDeque::new(),
            total_bytes_sent: 0,
            total_bytes_acked: 0,
            last_acked_packet: 0,
        }
    }
    
    fn on_packet_sent(&mut self, _sent_time: Instant, _packet_number: u64, bytes: u64) {
        self.total_bytes_sent += bytes;
    }
    
    fn on_packet_acked(&mut self, packet_number: u64, acked_bytes: u64, event_time: Instant) -> Option<BandwidthSample> {
        self.total_bytes_acked += acked_bytes;
        self.last_acked_packet = packet_number;
        
        // Simplified bandwidth calculation
        Some(BandwidthSample {
            bandwidth: acked_bytes * 8, // Convert to bits per second (simplified)
            rtt: Duration::from_millis(100), // Placeholder
            timestamp: event_time,
            bytes_sent: acked_bytes,
            bytes_acked: acked_bytes,
            is_app_limited: false,
        })
    }
    
    fn on_packet_lost(&mut self, _packet_number: u64) {
        // Handle packet loss
    }
}

impl WindowedFilter {
    fn new(window_size: usize) -> Self {
        Self {
            estimates: VecDeque::new(),
            window_size,
        }
    }
    
    fn update(&mut self, value: u64, round: u64) {
        // Remove old estimates outside the window
        while let Some(&(_, old_round)) = self.estimates.front() {
            if round.saturating_sub(old_round) >= self.window_size as u64 {
                self.estimates.pop_front();
            } else {
                break;
            }
        }
        
        // Add new estimate
        self.estimates.push_back((value, round));
    }
    
    fn get_best(&self) -> u64 {
        self.estimates.iter().map(|(value, _)| *value).max().unwrap_or(0)
    }
}

/// Congestion control algorithm selector
#[derive(Debug, Clone)]
pub enum CongestionAlgorithm {
    /// Brutal algorithm with specified bandwidth
    Brutal(u64),
    /// BBR algorithm
    Bbr,
    /// Basic bandwidth-based control
    Basic(CongestionConfig),
}

/// Congestion control factory
pub struct CongestionControlFactory;

impl CongestionControlFactory {
    /// Create a Brutal congestion controller
    pub fn create_brutal(bps: u64) -> BrutalSender {
        BrutalSender::new(bps)
    }
    
    /// Create a BBR congestion controller
    pub fn create_bbr(initial_max_datagram_size: u64) -> BbrSender {
        BbrSender::new(initial_max_datagram_size)
    }
    
    /// Create a basic congestion controller
    pub fn create_basic(config: CongestionConfig) -> CongestionController {
        CongestionController::new(config)
    }
    
    /// Create congestion controller from algorithm type
    pub fn create_from_algorithm(algorithm: CongestionAlgorithm, max_datagram_size: u64) -> Box<dyn CongestionControlTrait> {
        match algorithm {
            CongestionAlgorithm::Brutal(bps) => {
                Box::new(BrutalSender::new(bps))
            },
            CongestionAlgorithm::Bbr => {
                Box::new(BbrSender::new(max_datagram_size))
            },
            CongestionAlgorithm::Basic(config) => {
                Box::new(CongestionController::new(config))
            },
        }
    }
}

/// Common trait for all congestion control algorithms
pub trait CongestionControlTrait: std::fmt::Debug {
    /// Get congestion window size
    fn get_congestion_window(&self) -> u64;
    
    /// Check if packet can be sent
    fn can_send(&self, bytes_in_flight: u64) -> bool;
    
    /// Record packet sent
    fn on_packet_sent(&mut self, sent_time: Instant, packet_number: u64, bytes: u64, is_retransmittable: bool);
    
    /// Handle packet acknowledgment
    fn on_packet_acked(&mut self, packet_number: u64, acked_bytes: u64, prior_in_flight: u64, event_time: Instant);
    
    /// Handle packet loss
    fn on_packet_lost(&mut self, packet_number: u64, lost_bytes: u64, prior_in_flight: u64);
    
    /// Set maximum datagram size
    fn set_max_datagram_size(&mut self, size: u64);
    
    /// Set RTT statistics
    fn set_rtt(&mut self, rtt: Duration);
    
    /// Check if in slow start
    fn in_slow_start(&self) -> bool;
    
    /// Check if in recovery
    fn in_recovery(&self) -> bool;
}

// Implement the trait for BrutalSender
impl CongestionControlTrait for BrutalSender {
    fn get_congestion_window(&self) -> u64 {
        self.get_congestion_window()
    }
    
    fn can_send(&self, bytes_in_flight: u64) -> bool {
        self.can_send(bytes_in_flight)
    }
    
    fn on_packet_sent(&mut self, sent_time: Instant, _packet_number: u64, bytes: u64, _is_retransmittable: bool) {
        self.on_packet_sent(sent_time, bytes);
    }
    
    fn on_packet_acked(&mut self, _packet_number: u64, _acked_bytes: u64, _prior_in_flight: u64, _event_time: Instant) {
        // Brutal algorithm doesn't need individual packet ACK handling
        // ACK/loss events are handled in on_congestion_event
    }
    
    fn on_packet_lost(&mut self, _packet_number: u64, _lost_bytes: u64, _prior_in_flight: u64) {
        // Brutal algorithm doesn't need individual packet loss handling
        // ACK/loss events are handled in on_congestion_event
    }
    
    fn set_max_datagram_size(&mut self, size: u64) {
        self.set_max_datagram_size(size);
    }
    
    fn set_rtt(&mut self, rtt: Duration) {
        self.set_rtt(rtt);
    }
    
    fn in_slow_start(&self) -> bool {
        false // Brutal doesn't have slow start
    }
    
    fn in_recovery(&self) -> bool {
        false // Brutal doesn't have recovery state
    }
}

// Implement the trait for BbrSender
impl CongestionControlTrait for BbrSender {
    fn get_congestion_window(&self) -> u64 {
        self.get_congestion_window()
    }
    
    fn can_send(&self, bytes_in_flight: u64) -> bool {
        self.can_send(bytes_in_flight)
    }
    
    fn on_packet_sent(&mut self, sent_time: Instant, packet_number: u64, bytes: u64, is_retransmittable: bool) {
        self.on_packet_sent(sent_time, packet_number, bytes, is_retransmittable);
    }
    
    fn on_packet_acked(&mut self, packet_number: u64, acked_bytes: u64, prior_in_flight: u64, event_time: Instant) {
        self.on_packet_acked(packet_number, acked_bytes, prior_in_flight, event_time);
    }
    
    fn on_packet_lost(&mut self, packet_number: u64, lost_bytes: u64, prior_in_flight: u64) {
        self.on_packet_lost(packet_number, lost_bytes, prior_in_flight);
    }
    
    fn set_max_datagram_size(&mut self, size: u64) {
        self.set_max_datagram_size(size);
    }
    
    fn set_rtt(&mut self, rtt: Duration) {
        self.set_rtt(rtt);
    }
    
    fn in_slow_start(&self) -> bool {
        self.in_slow_start()
    }
    
    fn in_recovery(&self) -> bool {
        self.in_recovery()
    }
}

// Implement the trait for CongestionController (basic algorithm)
impl CongestionControlTrait for CongestionController {
    fn get_congestion_window(&self) -> u64 {
        // Basic algorithm uses a simple window calculation
        if self.config.max_tx_rate > 0 {
            (self.config.max_tx_rate as f64 * 0.1) as u64 // 100ms worth of data
        } else {
            65536 // Default 64KB window
        }
    }
    
    fn can_send(&self, bytes_in_flight: u64) -> bool {
        bytes_in_flight <= self.get_congestion_window() && !self.should_throttle_tx()
    }
    
    fn on_packet_sent(&mut self, _sent_time: Instant, _packet_number: u64, bytes: u64, _is_retransmittable: bool) {
        self.record_tx(bytes);
    }
    
    fn on_packet_acked(&mut self, _packet_number: u64, acked_bytes: u64, _prior_in_flight: u64, _event_time: Instant) {
        self.record_rx(acked_bytes);
    }
    
    fn on_packet_lost(&mut self, _packet_number: u64, _lost_bytes: u64, _prior_in_flight: u64) {
        // Basic algorithm doesn't handle individual packet loss
    }
    
    fn set_max_datagram_size(&mut self, _size: u64) {
        // Basic algorithm doesn't need datagram size
    }
    
    fn set_rtt(&mut self, _rtt: Duration) {
        // Basic algorithm doesn't use RTT
    }
    
    fn in_slow_start(&self) -> bool {
        false
    }
    
    fn in_recovery(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[test]
    fn test_congestion_config_default() {
        let config = CongestionConfig::default();
        assert_eq!(config.max_rx_rate, 0);
        assert_eq!(config.max_tx_rate, 0);
        assert!(!config.auto_mode);
    }

    #[test]
    fn test_congestion_controller_basic() {
        let config = CongestionConfig {
            max_tx_rate: 1000, // 1KB/s
            max_rx_rate: 2000, // 2KB/s
            auto_mode: false,
            measurement_window: Duration::from_secs(1),
        };
        
        let mut controller = CongestionController::new(config);
        
        // Initially should not throttle
        assert!(!controller.should_throttle_tx());
        assert!(!controller.should_throttle_rx());
        
        // Record some traffic
        controller.record_tx(500);
        controller.record_rx(1000);
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(1000); // 1KB/s
        
        // Should be able to transmit initially
        assert!(limiter.can_transmit(500));
        
        // Consume tokens
        limiter.consume(500).unwrap();
        
        // Should still have tokens
        assert!(limiter.can_transmit(500));
        
        // Consume remaining tokens
        limiter.consume(500).unwrap();
        
        // Should not have enough tokens for large transmission
        assert!(!limiter.can_transmit(1000));
    }

    #[test]
    fn test_bandwidth_meter() {
        let mut meter = BandwidthMeter::new(Duration::from_secs(1));
        
        // Record some data
        meter.record(1000);
        
        // Should have some bandwidth
        let bandwidth = meter.get_bandwidth();
        assert!(bandwidth > 0.0);
    }

    #[tokio::test]
    async fn test_rate_limiter_refill() {
        let mut limiter = RateLimiter::new(1000); // 1KB/s
        
        // Consume all tokens
        limiter.consume(1000).unwrap();
        assert!(!limiter.can_transmit(100));
        
        // Wait for refill
        sleep(Duration::from_millis(200)).await;
        
        // Should have some tokens now
        assert!(limiter.can_transmit(100));
    }

    #[test]
    fn test_brutal_sender() {
        let mut brutal = BrutalSender::new(1000000); // 1 Mbps
        
        // Test initial state
        assert!(brutal.get_congestion_window() > 0);
        assert!(brutal.can_send(0));
        
        // Test packet sending
        let now = Instant::now();
        brutal.on_packet_sent(now, 1000);
        
        // Test congestion event
        brutal.on_congestion_event(now, &[1, 2, 3], &[4]); // 3 acks, 1 loss
        
        // Test RTT setting
        brutal.set_rtt(Duration::from_millis(50));
        
        // Test max datagram size
        brutal.set_max_datagram_size(1500);
    }

    #[test]
    fn test_bbr_sender() {
        let mut bbr = BbrSender::new(1500);
        
        // Test initial state
        assert!(bbr.get_congestion_window() > 0);
        assert!(bbr.can_send(0));
        assert!(bbr.in_slow_start());
        assert!(!bbr.in_recovery());
        
        // Test packet operations
        let now = Instant::now();
        bbr.on_packet_sent(now, 1, 1000, true);
        bbr.on_packet_acked(1, 1000, 0, now);
        bbr.on_packet_lost(2, 1000, 1000);
        
        // Test configuration
        bbr.set_max_datagram_size(1400);
        bbr.set_rtt(Duration::from_millis(30));
    }

    #[test]
    fn test_congestion_control_factory() {
        // Test Brutal creation
        let brutal = CongestionControlFactory::create_brutal(2000000);
        assert!(brutal.get_congestion_window() > 0);
        
        // Test BBR creation
        let bbr = CongestionControlFactory::create_bbr(1500);
        assert!(bbr.get_congestion_window() > 0);
        
        // Test Basic creation
        let config = CongestionConfig {
            max_tx_rate: 1000000,
            max_rx_rate: 1000000,
            ..Default::default()
        };
        let basic = CongestionControlFactory::create_basic(config);
        assert!(basic.get_congestion_window() > 0);
    }

    #[test]
    fn test_congestion_algorithm_enum() {
        // Test algorithm creation from enum
        let brutal_algo = CongestionAlgorithm::Brutal(1500000);
        let brutal_controller = CongestionControlFactory::create_from_algorithm(brutal_algo, 1500);
        assert!(brutal_controller.get_congestion_window() > 0);
        
        let bbr_algo = CongestionAlgorithm::Bbr;
        let bbr_controller = CongestionControlFactory::create_from_algorithm(bbr_algo, 1500);
        assert!(bbr_controller.get_congestion_window() > 0);
        
        let basic_config = CongestionConfig {
            max_tx_rate: 800000,
            max_rx_rate: 800000,
            ..Default::default()
        };
        let basic_algo = CongestionAlgorithm::Basic(basic_config);
        let basic_controller = CongestionControlFactory::create_from_algorithm(basic_algo, 1500);
        assert!(basic_controller.get_congestion_window() > 0);
    }

    #[test]
    fn test_congestion_control_trait() {
        let mut controller: Box<dyn CongestionControlTrait> = 
            Box::new(BrutalSender::new(1000000));
        
        // Test trait methods
        assert!(controller.get_congestion_window() > 0);
        assert!(controller.can_send(0));
        assert!(!controller.in_slow_start());
        assert!(!controller.in_recovery());
        
        let now = Instant::now();
        controller.on_packet_sent(now, 1, 1000, true);
        controller.on_packet_acked(1, 1000, 0, now);
        controller.on_packet_lost(2, 1000, 1000);
        controller.set_max_datagram_size(1400);
        controller.set_rtt(Duration::from_millis(40));
    }

    #[test]
    fn test_windowed_filter() {
        let mut filter = WindowedFilter::new(5);
        
        // Test updates
        filter.update(100, 1);
        assert_eq!(filter.get_best(), 100);
        
        filter.update(200, 2);
        assert_eq!(filter.get_best(), 200);
        
        filter.update(50, 3);
        assert_eq!(filter.get_best(), 200); // Should still be max
    }
}