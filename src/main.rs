use std::{
    env,
    fs::File,
    io::{BufRead as _, BufReader, Read},
    sync::Arc,
};

use chrono::{DateTime, Datelike, Local, NaiveDateTime, TimeZone, Utc};
use rayon::prelude::*;
use regex::Regex;

mod client;
use client::send_ssh_rejection_event;
use serde::Deserialize;

enum LogType {
    RejectedConnection {
        ip: String,
        timestamp: i64,
        source_digest: String,
    },
    Unknown {
        source_digest: String,
    },
}

pub fn parse_log_datetime_to_epoch_ms(date_str: &str) -> Result<i64, chrono::ParseError> {
    let current_year = Local::now().year();
    let full_date_str = format!("{} {}", current_year, date_str);
    let format = "%Y %b %e %H:%M:%S";

    let naive = NaiveDateTime::parse_from_str(&full_date_str, format)?;
    let local_dt: DateTime<Local> = Local
        .from_local_datetime(&naive)
        .single()
        .expect("Ambiguous or invalid local datetime");

    Ok(local_dt.with_timezone(&Utc).timestamp_millis())
}

impl From<&String> for LogType {
    fn from(value: &String) -> Self {
        let source_digest = md5::compute(value.as_bytes());

        let regex_string = r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\ssshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\w+)\s+from\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+port\s+\d+\s+ssh2";
        Regex::new(regex_string)
            .unwrap()
            .captures(value)
            .map(|caps| {
                let ip = caps.name("ip").unwrap().as_str().to_string();
                let timestamp = caps.name("timestamp").unwrap().as_str().to_string();
                LogType::RejectedConnection {
                    ip,
                    timestamp: parse_log_datetime_to_epoch_ms(&timestamp).unwrap_or(0),
                    source_digest: format!("{:x}", source_digest),
                }
            })
            .unwrap_or_else(|| LogType::Unknown {
                source_digest: format!("{:x}", source_digest),
            })
    }
}

#[derive(Deserialize)]
struct Config {
    base_url: String,
    public_token: String,
    secret_token: String,
    endpoint_id: String,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: {} <log_file> <config_file>", args[0]);
        return;
    }

    let config_string = std::fs::read_to_string(&args[2]).expect("Failed to read config file");
    let config: Config = toml::from_str(&config_string).expect("Failed to parse config file");

    let file = File::open(&args[1]).expect("Failed to open file");
    let reader = BufReader::new(file);

    let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();

    let base_url = Arc::new(config.base_url);
    let public_token = Arc::new(config.public_token);
    let secret_token = Arc::new(config.secret_token);
    let endpoint_id = Arc::new(config.endpoint_id);

    lines.par_iter().for_each(|line| {
        let log_type: LogType = LogType::from(line);

        if let LogType::RejectedConnection {
            ip,
            timestamp,
            source_digest,
        } = log_type
        {
            let result = send_ssh_rejection_event(
                base_url.as_str(),
                public_token.as_str(),
                secret_token.as_str(),
                endpoint_id.as_str(),
                timestamp,
                &ip,
                22,
                "root",
                &source_digest,
            );

            match result {
                Ok(_) => println!("Event sent successfully: IP {}, Time {}", ip, timestamp),
                Err(e) => eprintln!("Error sending event: {}", e),
            }
        }
    });
}
