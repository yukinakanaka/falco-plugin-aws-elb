use std::io::Read;

use aws_sdk_s3::Client as S3Client;
use falco_plugin::{
    anyhow,
    serde::{Deserialize, Serialize},
};
use flate2::read::GzDecoder;

/// ELB access log entry
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ElbLogEntry {
    pub request_type: String,
    pub timestamp: String,
    pub elb_name: String,
    pub client_ip: String,
    pub client_port: u16,
    pub target_ip: String,
    pub target_port: u16,
    pub request_processing_time: f64,
    pub target_processing_time: f64,
    pub response_processing_time: f64,
    pub elb_status_code: u16,
    pub target_status_code: String,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub request_verb: String,
    pub request_url: String,
    pub request_proto: String,
    pub user_agent: String,
    pub ssl_cipher: String,
    pub ssl_protocol: String,
    pub target_group_arn: String,
    pub trace_id: String,
    pub domain_name: String,
    pub chosen_cert_arn: String,
    pub matched_rule_priority: String,
    pub request_creation_time: String,
    pub actions_executed: String,
    pub redirect_url: String,
    pub error_reason: String,
    pub target_port_list: String,
    pub target_status_code_list: String,
    pub classification: String,
    pub classification_reason: String,
    pub conn_trace_id: String,
}

pub fn parse_elb_log_line(line: &str) -> anyhow::Result<ElbLogEntry> {
    let parts = shlex::split(line)
        .ok_or_else(|| anyhow::anyhow!("Failed to split ELB log line: {}", line))?;

    if parts.len() != 30 {
        return Err(anyhow::anyhow!(
            "Invalid ELB log line format: expected at least 30 fields, got {}",
            parts.len()
        ));
    }

    // Parse client IP and port
    // TODO: Support IPv6 addresses
    let client_parts: Vec<&str> = parts[3].split(':').collect();
    let client_ip = client_parts[0].to_string();
    let client_port = client_parts
        .get(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);

    // Parse target IP and port
    // TODO: Support IPv6 addresses
    let target_parts: Vec<&str> = parts[4].split(':').collect();
    let target_ip = target_parts[0].to_string();
    let target_port = target_parts
        .get(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);

    // Parse request line (verb, URL, protocol)
    let request_line = parts[12].trim_matches('"');
    let request_parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    let request_verb = request_parts.first().unwrap_or(&"").to_string();
    let request_url = request_parts.get(1).unwrap_or(&"").to_string();
    let request_proto = request_parts.get(2).unwrap_or(&"").to_string();

    Ok(ElbLogEntry {
        request_type: parts[0].to_string(),
        timestamp: parts[1].to_string(),
        elb_name: parts[2].to_string(),
        client_ip,
        client_port,
        target_ip,
        target_port,
        request_processing_time: parts[5].parse().unwrap_or(0.0),
        target_processing_time: parts[6].parse().unwrap_or(0.0),
        response_processing_time: parts[7].parse().unwrap_or(0.0),
        elb_status_code: parts[8].parse().unwrap_or(0),
        target_status_code: parts[9].to_string(),
        received_bytes: parts[10].parse().unwrap_or(0),
        sent_bytes: parts[11].parse().unwrap_or(0),
        request_verb,
        request_url,
        request_proto,
        user_agent: parts[13].trim_matches('"').to_string(),
        ssl_cipher: parts[14].to_string(),
        ssl_protocol: parts[15].to_string(),
        target_group_arn: parts[16].to_string(),
        trace_id: parts[17].trim_matches('"').to_string(),
        domain_name: parts[18].trim_matches('"').to_string(),
        chosen_cert_arn: parts[19].trim_matches('"').to_string(),
        matched_rule_priority: parts[20].to_string(),
        request_creation_time: parts[21].to_string(),
        actions_executed: parts[22].trim_matches('"').to_string(),
        redirect_url: parts[23].trim_matches('"').to_string(),
        error_reason: parts[24].trim_matches('"').to_string(),
        target_port_list: parts[25].trim_matches('"').to_string(),
        target_status_code_list: parts[26].trim_matches('"').to_string(),
        classification: parts[27].trim_matches('"').to_string(),
        classification_reason: parts[28].trim_matches('"').to_string(),
        conn_trace_id: parts.get(29).map_or("", |v| v).to_string(),
    })
}

pub async fn list_objects(
    s3_client: &S3Client,
    bucket: &str,
    prefix: &str,
    start_after: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let mut list_request = s3_client.list_objects_v2().bucket(bucket).prefix(prefix);

    // Use the last processed key as starting point for pagination
    if let Some(last_key) = start_after {
        list_request = list_request.start_after(last_key);
    }

    let response = list_request.send().await?;

    let mut objects: Vec<_> = response
        .contents
        .unwrap_or_default()
        .into_iter()
        .filter_map(|obj| obj.key)
        .filter(|key| key.ends_with(".log") || key.ends_with(".log.gz"))
        .collect();

    objects.sort();
    Ok(objects)
}

pub async fn download_and_parse_object(
    s3_client: &S3Client,
    bucket: &str,
    object_key: &str,
) -> anyhow::Result<Vec<ElbLogEntry>> {
    // Download the object from S3
    let response = s3_client
        .get_object()
        .bucket(bucket)
        .key(object_key)
        .send()
        .await?;

    let body = response.body.collect().await?;
    let data = body.into_bytes();

    // Check if the file is gzipped
    let content = if object_key.ends_with(".gz") {
        let mut decoder = GzDecoder::new(&data[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        String::from_utf8(decompressed)?
    } else {
        String::from_utf8(data.to_vec())?
    };

    // Parse the log file line by line
    let events: Vec<_> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| match parse_elb_log_line(line) {
            Ok(event) => Some(event),
            Err(e) => {
                eprintln!("Failed to parse ELB log line: {e}");
                None
            }
        })
        .collect();

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_elb_log_line_with_all_fields() {
        // Extended log line with all 34 fields
        let log_line = r#"http 2025-07-14T19:20:19.723971Z app/falco-plugin-test/2a734d996bad0aea 134.122.93.131:36872 10.0.1.100:8080 0.001 0.023 0.000 200 200 165 337 "GET http://35.79.85.199:80/.env HTTP/1.1" "Mozilla/5.0; Keydrop.io/1.0(onlyscans.com/about);" TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 arn:aws:elasticloadbalancing:ap-northeast-1:1234567890123:targetgroup/falco-plugin-elb-target/d13385018c2fab37 "Root=1-68755873-3a09c648672bada5548dc5d0" "api.example.com" "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012" 100 2025-07-14T19:20:19.723000Z "forward,authenticate-cognito" "https://redirect.example.com/login" "AuthInvalidCookie" "10.0.1.100:8080" "200" "Acceptable" "SpaceInUri" TID_2d650523100657438a47a1b30bdb606d"#;

        let result = parse_elb_log_line(log_line);
        assert!(result.is_ok());

        let entry = result.unwrap();
        assert_eq!(entry.request_type, "http");
        assert_eq!(entry.timestamp, "2025-07-14T19:20:19.723971Z");
        assert_eq!(entry.elb_name, "app/falco-plugin-test/2a734d996bad0aea");
        assert_eq!(entry.client_ip, "134.122.93.131");
        assert_eq!(entry.client_port, 36872);
        assert_eq!(entry.target_ip, "10.0.1.100");
        assert_eq!(entry.target_port, 8080);
        assert_eq!(entry.request_processing_time, 0.001);
        assert_eq!(entry.target_processing_time, 0.023);
        assert_eq!(entry.response_processing_time, 0.000);
        assert_eq!(entry.elb_status_code, 200);
        assert_eq!(entry.target_status_code, "200");
        assert_eq!(entry.received_bytes, 165);
        assert_eq!(entry.sent_bytes, 337);
        assert_eq!(entry.request_verb, "GET");
        assert_eq!(entry.request_url, "http://35.79.85.199:80/.env");
        assert_eq!(entry.request_proto, "HTTP/1.1");
        assert_eq!(
            entry.user_agent,
            "Mozilla/5.0; Keydrop.io/1.0(onlyscans.com/about);"
        );
        assert_eq!(entry.ssl_cipher, "TLSv1.2");
        assert_eq!(entry.ssl_protocol, "ECDHE-RSA-AES128-GCM-SHA256");
        assert_eq!(
            entry.target_group_arn,
            "arn:aws:elasticloadbalancing:ap-northeast-1:1234567890123:targetgroup/falco-plugin-elb-target/d13385018c2fab37"
        );
        assert_eq!(entry.trace_id, "Root=1-68755873-3a09c648672bada5548dc5d0");
        assert_eq!(entry.domain_name, "api.example.com");
        assert_eq!(
            entry.chosen_cert_arn,
            "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
        );
        assert_eq!(entry.matched_rule_priority, "100");
        assert_eq!(entry.request_creation_time, "2025-07-14T19:20:19.723000Z");
        assert_eq!(entry.actions_executed, "forward,authenticate-cognito");
        assert_eq!(entry.redirect_url, "https://redirect.example.com/login");
        assert_eq!(entry.error_reason, "AuthInvalidCookie");
        assert_eq!(entry.target_port_list, "10.0.1.100:8080");
        assert_eq!(entry.target_status_code_list, "200");
        assert_eq!(entry.classification, "Acceptable");
        assert_eq!(entry.classification_reason, "SpaceInUri");
        assert_eq!(entry.conn_trace_id, "TID_2d650523100657438a47a1b30bdb606d");
    }

    #[test]
    fn test_parse_elb_log_with_dash_values() {
        let log_line = r#"http 2025-07-14T19:20:19.723971Z app/falco-plugin-test/2a734d996bad0aea 134.122.93.131:36872 - -1 -1 -1 503 - 141 337 "GET http://35.79.85.199:80/.env HTTP/1.1" "Mozilla/5.0; Keydrop.io/1.0(onlyscans.com/about);" - - arn:aws:elasticloadbalancing:ap-northeast-1:1234567890123:targetgroup/falco-plugin-elb-target/d13385018c2fab37 "Root=1-68755873-3a09c648672bada5548dc5d0" "-" "-" 0 2025-07-14T19:20:19.723000Z "forward" "-" "-" "-" "-" "-" "-" TID_2d650523100657438a47a1b30bdb606d"#;

        let result = parse_elb_log_line(log_line);
        assert!(result.is_ok());

        let entry = result.unwrap();
        assert_eq!(entry.request_type, "http");
        assert_eq!(entry.target_ip, "-");
        assert_eq!(entry.target_port, 0);
        assert_eq!(entry.request_processing_time, -1.0);
        assert_eq!(entry.target_processing_time, -1.0);
        assert_eq!(entry.response_processing_time, -1.0);
        assert_eq!(entry.elb_status_code, 503);
        assert_eq!(entry.target_status_code, "-");
        assert_eq!(entry.ssl_cipher, "-");
        assert_eq!(entry.ssl_protocol, "-");
        assert_eq!(entry.domain_name, "-");
        assert_eq!(entry.chosen_cert_arn, "-");
        assert_eq!(entry.redirect_url, "-");
        assert_eq!(entry.error_reason, "-");
        assert_eq!(entry.target_port_list, "-");
        assert_eq!(entry.target_status_code_list, "-");
        assert_eq!(entry.classification, "-");
        assert_eq!(entry.classification_reason, "-");
    }

    #[test]
    fn test_parse_https_log_line() {
        let log_line = r#"https 2025-07-14T19:20:19.723971Z app/falco-plugin-test/2a734d996bad0aea 134.122.93.131:36872 10.0.1.100:8080 0.001 0.023 0.000 200 200 165 337 "POST https://api.example.com/v1/users HTTP/1.1" "curl/7.68.0" TLSv1.3 ECDHE-RSA-AES256-GCM-SHA384 arn:aws:elasticloadbalancing:ap-northeast-1:1234567890123:targetgroup/falco-plugin-elb-target/d13385018c2fab37 "Root=1-68755873-3a09c648672bada5548dc5d0" "api.example.com" "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012" 100 2025-07-14T19:20:19.723000Z "forward" "-" "-" "10.0.1.100:8080" "200" "-" "-" TID_2d650523100657438a47a1b30bdb606d"#;

        let result = parse_elb_log_line(log_line);
        assert!(result.is_ok());

        let entry = result.unwrap();
        assert_eq!(entry.request_type, "https");
        assert_eq!(entry.request_verb, "POST");
        assert_eq!(entry.request_url, "https://api.example.com/v1/users");
        assert_eq!(entry.request_proto, "HTTP/1.1");
        assert_eq!(entry.ssl_cipher, "TLSv1.3");
        assert_eq!(entry.ssl_protocol, "ECDHE-RSA-AES256-GCM-SHA384");
        assert_eq!(entry.domain_name, "api.example.com");
        assert_eq!(
            entry.chosen_cert_arn,
            "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
        );
    }

    #[test]
    fn test_parse_websocket_log_line() {
        let log_line = r#"ws 2025-07-14T19:20:19.723971Z app/falco-plugin-test/2a734d996bad0aea 134.122.93.131:36872 10.0.1.100:8080 0.001 0.023 0.000 101 101 165 337 "GET ws://api.example.com/websocket HTTP/1.1" "Mozilla/5.0 (compatible; websocket)" - - arn:aws:elasticloadbalancing:ap-northeast-1:1234567890123:targetgroup/falco-plugin-elb-target/d13385018c2fab37 "Root=1-68755873-3a09c648672bada5548dc5d0" "api.example.com" "-" 100 2025-07-14T19:20:19.723000Z "forward" "-" "-" "10.0.1.100:8080" "101" "-" "-" TID_2d650523100657438a47a1b30bdb606d"#;

        let result = parse_elb_log_line(log_line);
        assert!(result.is_ok());

        let entry = result.unwrap();
        assert_eq!(entry.request_type, "ws");
        assert_eq!(entry.elb_status_code, 101);
        assert_eq!(entry.target_status_code, "101");
        assert_eq!(entry.request_verb, "GET");
        assert_eq!(entry.request_url, "ws://api.example.com/websocket");
        assert_eq!(entry.user_agent, "Mozilla/5.0 (compatible; websocket)");
    }

    #[test]
    fn test_parse_h2_log_line() {
        let log_line = r#"h2 2025-07-14T19:20:19.723971Z app/falco-plugin-test/2a734d996bad0aea 134.122.93.131:36872 10.0.1.100:8080 0.001 0.023 0.000 200 200 165 337 "GET https://api.example.com/v2/health HTTP/2.0" "Mozilla/5.0 (HTTP/2.0)" TLSv1.3 ECDHE-RSA-AES256-GCM-SHA384 arn:aws:elasticloadbalancing:ap-northeast-1:1234567890123:targetgroup/falco-plugin-elb-target/d13385018c2fab37 "Root=1-68755873-3a09c648672bada5548dc5d0" "api.example.com" "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012" 100 2025-07-14T19:20:19.723000Z "forward" "-" "-" "10.0.1.100:8080" "200" "-" "-" TID_2d650523100657438a47a1b30bdb606d"#;

        let result = parse_elb_log_line(log_line);
        assert!(result.is_ok());

        let entry = result.unwrap();
        assert_eq!(entry.request_type, "h2");
        assert_eq!(entry.request_proto, "HTTP/2.0");
        assert_eq!(entry.ssl_cipher, "TLSv1.3");
        assert_eq!(entry.ssl_protocol, "ECDHE-RSA-AES256-GCM-SHA384");
    }

    #[test]
    fn test_parse_grpcs_log_line() {
        let log_line = r#"grpcs 2025-07-14T19:20:19.723971Z app/falco-plugin-test/2a734d996bad0aea 134.122.93.131:36872 10.0.1.100:8080 0.001 0.023 0.000 200 200 165 337 "POST https://api.example.com/grpc.Service/Method HTTP/2.0" "grpc-go/1.40.0" TLSv1.3 ECDHE-RSA-AES256-GCM-SHA384 arn:aws:elasticloadbalancing:ap-northeast-1:1234567890123:targetgroup/falco-plugin-elb-target/d13385018c2fab37 "Root=1-68755873-3a09c648672bada5548dc5d0" "api.example.com" "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012" 100 2025-07-14T19:20:19.723000Z "forward" "-" "-" "10.0.1.100:8080" "200" "-" "-" TID_2d650523100657438a47a1b30bdb606d"#;

        let result = parse_elb_log_line(log_line);
        assert!(result.is_ok());

        let entry = result.unwrap();
        assert_eq!(entry.request_type, "grpcs");
        assert_eq!(entry.request_verb, "POST");
        assert_eq!(
            entry.request_url,
            "https://api.example.com/grpc.Service/Method"
        );
        assert_eq!(entry.user_agent, "grpc-go/1.40.0");
    }

    #[test]
    fn test_parse_elb_log_insufficient_fields() {
        let log_line = "http 2025-07-14T19:20:19.723971Z app/falco-plugin-test/2a734d996bad0aea 134.122.93.131:36872";

        let result = parse_elb_log_line(log_line);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid ELB log line format")
        );
    }

    #[test]
    fn test_parse_empty_log_line() {
        let result = parse_elb_log_line("");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid ELB log line format")
        );
    }

    #[test]
    fn test_parse_elb_log_with_invalid_numeric_values() {
        let log_line = r#"http 2025-07-14T19:20:19.723971Z app/falco-plugin-test/2a734d996bad0aea 134.122.93.131:invalid_port 10.0.1.100:invalid_port invalid_time invalid_time invalid_time invalid_status invalid_status invalid_bytes invalid_bytes "GET http://35.79.85.199:80/.env HTTP/1.1" "Mozilla/5.0" - - arn:aws:elasticloadbalancing:ap-northeast-1:1234567890123:targetgroup/falco-plugin-elb-target/d13385018c2fab37 "Root=1-68755873-3a09c648672bada5548dc5d0" "-" "-" 0 2025-07-14T19:20:19.723000Z "forward" "-" "-" "-" "-" "-" "-" TID_2d650523100657438a47a1b30bdb606d"#;

        let result = parse_elb_log_line(log_line);
        assert!(result.is_ok());

        let entry = result.unwrap();
        // All invalid numeric values should default to 0 or 0.0
        assert_eq!(entry.client_port, 0);
        assert_eq!(entry.target_port, 0);
        assert_eq!(entry.request_processing_time, 0.0);
        assert_eq!(entry.target_processing_time, 0.0);
        assert_eq!(entry.response_processing_time, 0.0);
        assert_eq!(entry.elb_status_code, 0);
        assert_eq!(entry.received_bytes, 0);
        assert_eq!(entry.sent_bytes, 0);
    }

    #[test]
    fn test_parse_elb_log_with_classification_fields() {
        let log_line = r#"http 2025-07-14T19:20:19.723971Z app/falco-plugin-test/2a734d996bad0aea 134.122.93.131:36872 10.0.1.100:8080 0.001 0.023 0.000 400 400 141 337 "GET /path with spaces HTTP/1.1" "BadBot/1.0" - - arn:aws:elasticloadbalancing:ap-northeast-1:1234567890123:targetgroup/falco-plugin-elb-target/d13385018c2fab37 "Root=1-68755873-3a09c648672bada5548dc5d0" "-" "-" 0 2025-07-14T19:20:19.723000Z "forward" "-" "-" "10.0.1.100:8080" "400" "Severe" "HeaderName" TID_2d650523100657438a47a1b30bdb606d"#;

        let result = parse_elb_log_line(log_line);
        assert!(result.is_ok());

        let entry = result.unwrap();
        assert_eq!(entry.classification, "Severe");
        assert_eq!(entry.classification_reason, "HeaderName");
        assert_eq!(entry.request_url, "/path");
        assert_eq!(entry.user_agent, "BadBot/1.0");
    }
}
