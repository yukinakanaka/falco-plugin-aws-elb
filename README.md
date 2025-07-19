# Falco AWS ELB Plugin

This directory contains the AWS ELB plugin, which reads AWS Elastic Load Balancer (ELB) access logs and injects them as events into Falco for security analysis and monitoring.

The plugin reads ELB access logs from S3 buckets and generates synthetic events for security monitoring purposes.

## Event Source

The event source for AWS ELB events is `awselb`.

## Supported Fields

All fields of the ELB access log are available. For more details, please refer to the [AWS Document: Access log entries](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html#access-log-entry-format)

|                  NAME                  |   TYPE   | ARG  |                         DESCRIPTION                          |
|----------------------------------------|----------|------|--------------------------------------------------------------|
| `awselb.request_type`                  | `string` | None | The type of request (HTTP/HTTPS)                            |
| `awselb.timestamp`                     | `string` | None | The timestamp of the request                                 |
| `awselb.name`                          | `string` | None | The name of the ELB                                          |
| `awselb.client_ip`                     | `string` | None | The IP address of the client                                 |
| `awselb.client_port`                   | `uint64` | None | The port number of the client                                |
| `awselb.target_ip`                     | `string` | None | The IP address of the target                                 |
| `awselb.target_port`                   | `uint64` | None | The port number of the target                                |
| `awselb.request_processing_time`       | `uint64` | None | The request processing time in seconds                       |
| `awselb.target_processing_time`        | `uint64` | None | The target processing time in seconds                        |
| `awselb.response_processing_time`      | `uint64` | None | The response processing time in seconds                      |
| `awselb.elb_status_code`               | `uint64` | None | The HTTP status code returned by the ELB                    |
| `awselb.target_status_code`            | `uint64` | None | The HTTP status code returned by the target                 |
| `awselb.received_bytes`                | `uint64` | None | The size of the request in bytes                             |
| `awselb.sent_bytes`                    | `uint64` | None | The size of the response in bytes                            |
| `awselb.request_verb`                  | `string` | None | The HTTP request method                                      |
| `awselb.request_url`                   | `string` | None | The request URL                                              |
| `awselb.request_proto`                 | `string` | None | The request protocol version                                 |
| `awselb.user_agent`                    | `string` | None | The User-Agent header from the client                       |
| `awselb.ssl_cipher`                    | `string` | None | The SSL cipher used for the connection                       |
| `awselb.ssl_protocol`                  | `string` | None | The SSL protocol version used                                |
| `awselb.target_group_arn`              | `string` | None | The ARN of the target group                                  |
| `awselb.trace_id`                      | `string` | None | The trace ID for the request                                 |
| `awselb.domain_name`                   | `string` | None | The domain name used in the request                          |
| `awselb.chosen_cert_arn`               | `string` | None | The ARN of the chosen certificate                            |
| `awselb.matched_rule_priority`         | `uint64` | None | The priority of the matched rule                             |
| `awselb.request_creation_time`         | `string` | None | The time when the request was created                        |
| `awselb.actions_executed`              | `string` | None | The actions executed for the request                         |
| `awselb.redirect_url`                  | `string` | None | The redirect URL if applicable                               |
| `awselb.error_reason`                  | `string` | None | The error reason if applicable                               |
| `awselb.target_port_list`              | `string` | None | The list of target ports                                     |
| `awselb.target_status_code_list`       | `string` | None | The list of target status codes                              |
| `awselb.classification`                | `string` | None | The classification of the request                            |
| `awselb.classification_reason`         | `string` | None | The reason for the classification                            |
| `awselb.conn_trace_id`                 | `string` | None | The connection trace ID                                      |

## Configuration

### Plugin Initialization

The format of the initialization string is a json object. Here's an example:

```json
{"region": "us-west-2", "s3Bucket": "your-elb-logs-bucket", "s3Prefix": "elb-access-logs/"}
```

The json object has the following properties:

* `region`: AWS region for ELB operations (required)
* `s3Bucket`: S3 bucket name containing ELB access logs (required)
* `s3Prefix`: S3 prefix for ELB access logs (required)

The init string can be the empty string, which is treated identically to `{}`.

### Plugin Open Params

N/A

### Run with Falco

Here is a complete `falco.yaml` snippet showing valid configurations for the `awselb` plugin:

```yaml
plugins:
  - name: awselb
    library_path: libawselb.so
    init_config: '{"region": "us-west-2", "s3Bucket": "your-elb-logs-bucket", "s3Prefix": "elb-access-logs/"}'
    open_params: '{}'

# Optional. If not specified the first entry in plugins is used.
load_plugins: [awselb]
```

Run Falco using `awselb_rules.yaml`

```bash
sudo ./usr/bin/falco -c falco.yaml -r awselb_rules.yaml --disable-source=syscall
```

## AWS Credentials

The plugin uses the standard AWS credential chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. AWS credentials file (`~/.aws/credentials`)
3. IAM instance profile (when running on EC2)
4. IAM roles for service accounts (when running on EKS)

### Required IAM Permissions

The plugin requires the following IAM permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::your-elb-logs-bucket",
                "arn:aws:s3:::your-elb-logs-bucket/*"
            ]
        }
    ]
}
```

## Contributing
Want to contribute? Great! Check out our [Contributing Guide](./CONTRIBUTING.md) to get started.
