use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Percentage of tcp_sendmsg events to capture (0.0–100.0). Supports fractional values.
    /// Applies to all modules that use the tcp_sendmsg probe.
    pub tcp_sendmsg_sample_rate: f32,
    pub modules: ModulesConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tcp_sendmsg_sample_rate: 100.0,
            modules: ModulesConfig::default(),
        }
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
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MysqlConfig {
    pub enabled: bool,
}

impl Default for MysqlConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    pub enabled: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}
