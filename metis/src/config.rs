use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Percentage of tcp_sendmsg connections to capture (0.0–100.0). Supports fractional
    /// values. The decision is made once per connection, on its first tcp_sendmsg call, and
    /// then applies to every packet on that connection — so a sampled-in connection never
    /// loses e.g. a MySQL handshake packet while later query packets are captured.
    /// Applies to all modules that use the tcp_sendmsg probe.
    pub tcp_sendmsg_sample_rate: f32,
    pub telegraf: TelegrafConfig,
    pub modules: ModulesConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tcp_sendmsg_sample_rate: 100.0,
            telegraf: TelegrafConfig::default(),
            modules: ModulesConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MetricProtocol {
    /// InfluxDB line protocol (Telegraf `inputs.socket_listener` or `inputs.influxdb_listener`).
    Influx,
    /// DogStatsD-extended StatsD (Telegraf `inputs.statsd` with `datadog_extensions = true`).
    Statsd,
}

impl Default for MetricProtocol {
    fn default() -> Self {
        Self::Influx
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelegrafConfig {
    pub address: String,
    pub protocol: MetricProtocol,
}

impl Default for TelegrafConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:8125".to_string(),
            protocol: MetricProtocol::default(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ModulesConfig {
    pub tcp: TcpConfig,
    pub mysql: MysqlConfig,
    pub http: HttpConfig,
    pub dns: DnsConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    pub enabled: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TcpConfig {
    pub enabled: bool,
    /// Ports to filter on. Omit or set to [] to capture all ports.
    pub ports: Option<Vec<u16>>,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self { enabled: true, ports: None }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MysqlConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
}

impl Default for MysqlConfig {
    fn default() -> Self {
        Self { enabled: true, ports: vec![3306] }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self { enabled: false, ports: vec![80] }
    }
}
