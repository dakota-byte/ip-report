use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use reqwest::Client;
use serde_json::Value;

mod tui;

/// Query VirusTotal for everything it knows about an IP address.
#[derive(Parser, Debug)]
#[command(name = "ip-report", version, about)]
struct Args {
    /// The IP address to look up (e.g. 8.8.8.8)
    #[arg(default_value = "1.1.1.1")]
    ip: String,

    /// Print the raw JSON responses instead of a summary
    #[arg(long)]
    raw: bool,

    /// Print to stdout instead of launching the interactive terminal UI
    #[arg(long)]
    no_tui: bool,
}

/// The VirusTotal v3 endpoints that apply to an IP address.
const ENDPOINTS: &[(&str, &str)] = &[
    ("report", ""),
    ("comments", "/comments"),
    ("resolutions", "/resolutions"),
    ("historical_ssl_certificates", "/historical_ssl_certificates"),
    ("historical_whois", "/historical_whois"),
];

#[tokio::main]
async fn main() -> Result<()> {
    // Load VT_API_KEY (and anything else) from a local .env if present.
    let _ = dotenvy::dotenv();

    let args = Args::parse();

    let api_key = std::env::var("VT_API_KEY")
        .context("VT_API_KEY is not set (add it to your environment or .env file)")?;

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("ip-report/0.1")
        .build()?;

    let base = format!("https://www.virustotal.com/api/v3/ip_addresses/{}", args.ip);

    if !args.no_tui {
        let results = fetch_all(&client, &args.ip, &api_key).await;
        return tui::run(&client, &api_key, &args.ip, results, args.raw).await;
    }

    for (name, suffix) in ENDPOINTS {
        let url = format!("{base}{suffix}");
        println!("\n=== {name} ===");

        match fetch(&client, &url, &api_key).await {
            Ok(json) => {
                if args.raw {
                    println!("{}", serde_json::to_string_pretty(&json)?);
                } else {
                    summarize(name, &json);
                }
            }
            Err(err) => eprintln!("error fetching {name}: {err:#}"),
        }
    }

    Ok(())
}

/// Fetch every endpoint for an IP, returning one result per endpoint.
pub(crate) async fn fetch_all(
    client: &Client,
    ip: &str,
    api_key: &str,
) -> Vec<(&'static str, Result<Value>)> {
    let base = format!("https://www.virustotal.com/api/v3/ip_addresses/{ip}");
    let mut results = Vec::with_capacity(ENDPOINTS.len());
    for (name, suffix) in ENDPOINTS {
        let url = format!("{base}{suffix}");
        let result = fetch(client, &url, api_key).await;
        results.push((*name, result));
    }
    results
}

/// Perform a single authenticated GET request and parse the JSON body.
async fn fetch(client: &Client, url: &str, api_key: &str) -> Result<Value> {
    let resp = client
        .get(url)
        .header("x-apikey", api_key)
        .send()
        .await
        .with_context(|| format!("request to {url} failed"))?;

    let status = resp.status();
    let body = resp.text().await?;

    if !status.is_success() {
        bail!("HTTP {status}: {body}");
    }

    let json: Value = serde_json::from_str(&body).context("failed to parse JSON response")?;
    Ok(json)
}

/// Print a short human-readable summary of a response.
pub(crate) fn summarize(name: &str, json: &Value) {
    match name {
        "report" => {
            let attrs = &json["data"]["attributes"];
            println!("reputation: {}", attrs["reputation"]);
            println!("country:    {}", attrs["country"]);
            println!("as_owner:   {}", attrs["as_owner"]);
            println!("asn:        {}", attrs["asn"]);
            println!("network:    {}", attrs["network"]);

            if let Some(stats) = attrs["last_analysis_stats"].as_object() {
                println!("last_analysis_stats:");
                for (k, v) in stats {
                    println!("  {k}: {v}");
                }
            }
        }
        _ => {
            let items = json["data"].as_array();
            match items {
                Some(items) if items.is_empty() => println!("(no items)"),
                Some(items) => {
                    for (i, item) in items.iter().enumerate() {
                        println!("--- [{i}] ---");
                        print_item(name, item);
                    }
                }
                None => println!("(no data)"),
            }
        }
    }
}

/// Print a single item from a list-style endpoint.
fn print_item(name: &str, item: &Value) {
    let attrs = &item["attributes"];
    match name {
        "comments" => {
            println!("date:    {}", attrs["date"]);
            println!("votes:   +{} / -{}", attrs["votes"]["positive"], attrs["votes"]["negative"]);
            println!("tags:    {}", join_array(&attrs["tags"]));
            println!("text:    {}", attrs["text"].as_str().unwrap_or("").trim());
        }
        "resolutions" => {
            println!("date:    {}", attrs["date"]);
            println!("host:    {}", attrs["host_name"]);
            println!("ip:      {}", attrs["ip_address"]);
        }
        "historical_ssl_certificates" => {
            println!("issuer:  {}", attrs["issuer"]["CN"]);
            println!("subject: {}", attrs["subject"]["CN"]);
            println!("valid:   {} -> {}", attrs["validity"]["not_before"], attrs["validity"]["not_after"]);
            println!("serial:  {}", attrs["serial_number"]);
        }
        "historical_whois" => {
            println!("date:    {}", attrs["date"]);
            println!("registrar: {}", attrs["registrar"]);
            println!("netname: {}", attrs["netname"]);
            println!("country: {}", attrs["country"]);
            println!("org:     {}", attrs["org"]);
        }
        _ => {
            println!("{}", serde_json::to_string_pretty(item).unwrap_or_default());
        }
    }
}

/// Join a JSON array of strings with ", ".
fn join_array(value: &Value) -> String {
    value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}
