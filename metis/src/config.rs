use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Percentage of tcp_sendmsg events to capture (0.0–100.0). Supports fractional values.
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

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelegrafConfig {
    /// UDP address of the Telegraf InfluxDB line-protocol listener.
    pub address: String,
}

impl Default for TelegrafConfig {
    fn default() -> Self {
        Self { address: "127.0.0.1:8125".to_string() }
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ModulesConfig {
    pub tcp: TcpConfig,
    pub mysql: MysqlConfig,
    pub http: HttpConfig,
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
