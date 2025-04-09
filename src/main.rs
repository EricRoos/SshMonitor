use std::{
    env,
    fs::File,
    io::{BufRead as _, BufReader},
};

use regex::Regex;

enum LogType {
    RejectedConnection {
        ip: String,
        timestamp: String,
        source_digest: String,
    },
    Unknown {
        source_digest: String,
    },
}

impl From<&String> for LogType {
    fn from(value: &String) -> Self {
        let source_digest = md5::compute(value.as_bytes());
        //example match string for a RejectedConnection
        // Unknown log types:
        // Apr  8 20:15:05 s228610 sshd[1685667]: Failed password for root from 218.92.0.252 port 1348 ssh2
        // Apr  8 19:40:16 s228610 sshd[1685263]: Failed password for invalid user foundry from 14.103.122.180 port 43838 ssh2
        let regex_string = r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\ssshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\w+)\s+from\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+port\s+\d+\s+ssh2";
        Regex::new(regex_string)
            .unwrap()
            .captures(value)
            .map(|caps| {
                let ip = caps.name("ip").unwrap().as_str().to_string();
                let timestamp = caps.name("timestamp").unwrap().as_str().to_string();
                LogType::RejectedConnection {
                    ip,
                    timestamp,
                    source_digest: format!("{:x}", source_digest),
                }
            })
            .unwrap_or_else(|| LogType::Unknown {
                source_digest: format!("{:x}", source_digest),
            })
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <log_file>", args[0]);
        return;
    }
    let source_file = File::open(&args[1]);
    BufReader::new(source_file.unwrap())
        .lines()
        .map_while(Result::ok)
        .for_each(|line| {
            let log_type: LogType = LogType::from(&line);
            match log_type {
                LogType::RejectedConnection {
                    ip,
                    timestamp,
                    source_digest,
                } => {
                    println!("IP: {}, Timestamp: {}", ip, timestamp);
                }
                LogType::Unknown { source_digest } => {}
            }
        });
}
