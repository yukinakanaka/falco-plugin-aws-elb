# Contributing to Falco AWS ELB Plugin

This guide walks you through setting up a local development environment and testing the Falco AWS ELB plugin.

## Develop locally
### Prerequisites
- make
- [rustup](https://www.rust-lang.org/tools/install)
- [docker](https://docs.docker.com/engine/install/)
- [awscli](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)

#### (Optional) Lima VM
You can set up the environment using a [lima](https://lima-vm.io/docs/installation/) VM.

**Note**: This lima template is only tested on macOS with Apple Silicon.
```bash
limactl start ./contrib/falco-vm.yaml
```

### Set up S3 bucket and AWS credentials

- Configure AWS CLI profiles for LocalStack (both user and root):
    ```bash
    # For user
    mkdir -p ~/.aws

    cat << EOF >> ~/.aws/credentials
    [localstack]
    aws_access_key_id = test
    aws_secret_access_key = test
    EOF

    cat << EOF >> ~/.aws/config
    [profile localstack]
    region = us-east-1
    output = text
    endpoint_url = http://localhost:4566
    EOF

    # For root
    sudo mkdir -p /root/.aws

    sudo tee /root/.aws/credentials << EOF
    [localstack]
    aws_access_key_id = test
    aws_secret_access_key = test
    EOF

    sudo tee /root/.aws/config << EOF
    [profile localstack]
    region = us-east-1
    output = text
    endpoint_url = http://localhost:4566
    EOF
    ```

- Start LocalStack and create the S3 bucket:
The `init-s3.py` script automatically creates an S3 bucket named `aws-elb-logs`.
    ```bash
    docker compose -f contrib/localstack.yaml up -d
    ```
- Verify the S3 bucket was created successfully:
    ```bash
    AWS_PROFILE=localstack aws s3 ls
    ```

### Build AWS ELB plugin

1. Build the plugin
   ```bash
   make debug
   ```

2. Install the plugin
   ```bash
   sudo mv libawselb.so /usr/share/falco/plugins/
   ```

### Test the plugin

1. Upload sample log file to S3
   ```bash
   AWS_PROFILE=localstack aws s3 cp ./tests/data/log-001.log.gz s3://aws-elb-logs/AWSLogs/log-001.log.gz
   ```

2. Run Falco with debug rules
   
   Note: ELB Plugin settings are configured in `falco.yaml` and all ELB Events are detected by the rule defined in `debug_rules.yaml`
   
   ```bash
   sudo AWS_PROFILE=localstack /usr/bin/falco -c contrib/falco.yaml -r contrib/debug_rules.yaml
   ```

3. Verify AWS ELB events appear in Falco logs

Expected output example:
```
23:05:03.222702000: Debug Some AWS ELB Event (evtnum=453 info={"request_type":"http","timestamp":"2025-07-15T23:54:29.488466Z","elb_name":"app/falco-plugin-test/2a734d996bad0aea","client_ip":"198.235.24.104","client_port":54174,"target_ip":"-","target_port":0,"request_processing_time":-1.0,"target_processing_time":-1.0,"response_processing_time":-1.0,"elb_status_code":503,"target_status_code":"-","received_bytes":185,"sent_bytes":332,"request_verb":"GET","request_url":"http://falco-plugin-test-1099684140.us-east-1.elb.amazonaws.com:80/","request_proto":"HTTP/1.0","user_agent":"Hello from Palo Alto Networks, find out more about our scans in https://docs-cortex.paloaltonetworks.com/r/1/Cortex-Xpanse/Scanning-activity","ssl_cipher":"-","ssl_protocol":"-","target_group_arn":"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/falco-plugin-elb-target/d13385018c2fab37","trace_id":"Root=1-6876ea35-127e227c330ffb6021b4a5bb","domain_name":"-","chosen_cert_arn":"-","matched_rule_priority":"0","request_creation_time":"2025-07-15T23:54:29.488000Z","actions_executed":"forward","redirect_url":"-","error_reason":"-","target_port_list":"-","target_status_code_list":"-","classification":"-","classification_reason":"-","conn_trace_id":"TID_7f7d0729d7a3d24885a5b1305bfb889b"} ts=2025-07-19T14:05:03.222702000+0000 elb_name=app/falco-plugin-test/2a734d996bad0aea elb_status_code=503)
```

### Additional testing

#### Test with newly updated S3 files
1. Upload additional log files
   ```bash
   AWS_PROFILE=localstack aws s3 cp ./tests/data/log-002.log.gz s3://aws-elb-logs/AWSLogs/log-002.log.gz
   ```

2. Verify new events are detected
   The plugin should automatically detect and process the new file.

### Clean up

When you're done testing, clean up your environment:

1. Remove test files from S3
   ```bash
   AWS_PROFILE=localstack aws s3 rm --recursive s3://aws-elb-logs/AWSLogs/
   ```

2. Stop LocalStack
   ```bash
   docker compose -f ./contrib/localstack.yaml stop
   ```

3. Remove the plugin library
   ```bash
   sudo rm /usr/share/falco/plugins/libawselb.so
   ```
