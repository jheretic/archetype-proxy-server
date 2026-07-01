//! clap v4 (derive) front-end. Parses argv only; the env/file/discovery
//! layers and the precedence/merge logic live in `config.rs`. CLI is the
//! highest-precedence layer, so clap's native non-zero exit on a bad value is
//! exactly the behaviour we want (no silent fallback).

use std::net::SocketAddr;

use clap::{Parser, Subcommand};

use crate::config::PartialStatic;

/// Log verbosity for the tracing `EnvFilter` default directive. `RUST_LOG`,
/// when set, OVERRIDES this (see `main.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "lower")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "archetype-proxy-server", version, about)]
pub struct Args {
    /// Path to the TOML config file (positional). `--config` takes precedence.
    #[arg(value_name = "CONFIG_PATH")]
    pub config_path: Option<String>,

    /// Path to the TOML config file.
    #[arg(long, value_name = "PATH")]
    pub config: Option<String>,

    /// Listen address override, e.g. 127.0.0.1:8443.
    #[arg(long, value_name = "ADDR")]
    pub listen: Option<SocketAddr>,

    /// Max decrypted request / upstream response body size, in bytes.
    #[arg(long, value_name = "N")]
    pub max_body_bytes: Option<usize>,

    /// Enable Docker label discovery (default off; mirrors --kubernetes).
    #[arg(long)]
    pub docker: bool,

    /// Enable Kubernetes annotation discovery.
    #[arg(long)]
    pub kubernetes: bool,

    /// Log level for the default tracing filter. `RUST_LOG` overrides this.
    #[arg(long, value_enum, value_name = "LEVEL")]
    pub log_level: Option<LogLevel>,

    /// Increase verbosity (-v=debug, -vv/-vvv=trace). `--log-level` wins if
    /// both are given. `RUST_LOG` overrides either.
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Print the resolved config + provenance, then exit.
    Dump,
}

impl Args {
    /// `--config` wins over the positional path (matches the legacy parser).
    pub fn config_path(&self) -> Option<&str> {
        self.config
            .as_deref()
            .or(self.config_path.as_deref())
    }

    pub fn dump(&self) -> bool {
        matches!(self.command, Some(Commands::Dump))
    }

    /// Effective level: explicit `--log-level` wins; else `-v` count maps
    /// 0=info, 1=debug, 2+=trace.
    const fn level(&self) -> LogLevel {
        if let Some(level) = self.log_level {
            return level;
        }
        match self.verbose {
            0 => LogLevel::Info,
            1 => LogLevel::Debug,
            _ => LogLevel::Trace,
        }
    }

    /// Crate-scoped default `EnvFilter` directive, mirroring the legacy
    /// `archetype_proxy_server=info` fallback in `main.rs` but honoring the
    /// `--log-level`/`-v` flags. `RUST_LOG` still overrides this.
    pub fn log_directive(&self) -> String {
        format!("archetype_proxy_server={}", self.level().as_str())
    }

    /// Map parsed flags into the existing `PartialStatic` override layer.
    /// `--docker` / `--kubernetes` are enable-only flags (mirroring each other):
    /// present => `Some(true)`, absent => `None` (inherit lower config layers).
    /// To disable discovery enabled by a TOML/env layer, set it false there.
    pub fn overrides(&self) -> PartialStatic {
        PartialStatic {
            listen: self.listen,
            max_body_bytes: self.max_body_bytes,
            docker_enabled: if self.docker { Some(true) } else { None },
            kubernetes_enabled: if self.kubernetes { Some(true) } else { None },
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(a: &[&str]) -> Result<Args, clap::Error> {
        let mut argv = vec!["archetype-proxy-server"];
        argv.extend_from_slice(a);
        Args::try_parse_from(argv)
    }

    #[test]
    fn valid_max_body_bytes_parses() {
        let args = parse(&["--max-body-bytes", "1024"]).unwrap();
        assert_eq!(args.overrides().max_body_bytes, Some(1024));
    }

    #[test]
    fn invalid_max_body_bytes_errors() {
        // CLI is highest-precedence: a bad value must error, not fall back.
        assert!(parse(&["--max-body-bytes", "nope"]).is_err());
    }

    #[test]
    fn missing_flag_value_errors() {
        assert!(parse(&["--listen"]).is_err());
    }

    #[test]
    fn invalid_listen_errors() {
        assert!(parse(&["--listen", "not-an-addr"]).is_err());
    }

    #[test]
    fn positional_config_path_and_dump() {
        let args = parse(&["./my.toml", "dump"]).unwrap();
        assert_eq!(args.config_path(), Some("./my.toml"));
        assert!(args.dump());
    }

    #[test]
    fn config_flag_wins_over_positional() {
        let args = parse(&["pos.toml", "--config", "flag.toml"]).unwrap();
        assert_eq!(args.config_path(), Some("flag.toml"));
    }

    #[test]
    fn docker_flag_enable_only() {
        // Enable-only, mirroring --kubernetes: absent => None (inherit lower
        // layers), present => Some(true). No --no-docker; disable via TOML/env.
        assert_eq!(parse(&[]).unwrap().overrides().docker_enabled, None);
        assert_eq!(
            parse(&["--docker"]).unwrap().overrides().docker_enabled,
            Some(true)
        );
        // --no-docker is no longer a valid flag.
        assert!(parse(&["--no-docker"]).is_err());
    }

    #[test]
    fn log_directive_level_and_verbosity() {
        assert_eq!(
            parse(&[]).unwrap().log_directive(),
            "archetype_proxy_server=info"
        );
        assert_eq!(
            parse(&["-v"]).unwrap().log_directive(),
            "archetype_proxy_server=debug"
        );
        assert_eq!(
            parse(&["-vv"]).unwrap().log_directive(),
            "archetype_proxy_server=trace"
        );
        assert_eq!(
            parse(&["-vvv"]).unwrap().log_directive(),
            "archetype_proxy_server=trace"
        );
        // Explicit --log-level wins over -v.
        assert_eq!(
            parse(&["--log-level", "warn", "-vv"])
                .unwrap()
                .log_directive(),
            "archetype_proxy_server=warn"
        );
        assert_eq!(
            parse(&["--log-level", "off"]).unwrap().log_directive(),
            "archetype_proxy_server=off"
        );
    }

    #[test]
    fn log_level_and_dump_coexist() {
        // Verbosity flag must not regress the dump subcommand.
        let args = parse(&["-vv", "dump"]).unwrap();
        assert!(args.dump());
        assert_eq!(args.log_directive(), "archetype_proxy_server=trace");
    }

    #[test]
    fn kubernetes_flag() {
        assert_eq!(parse(&[]).unwrap().overrides().kubernetes_enabled, None);
        assert_eq!(
            parse(&["--kubernetes"]).unwrap().overrides().kubernetes_enabled,
            Some(true)
        );
    }
}
