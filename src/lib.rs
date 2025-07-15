mod aws;
use std::{
    ffi::{CStr, CString},
    sync::{Arc, Mutex},
    time::Duration,
};

use aws::*;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::Client as S3Client;
use falco_plugin::{
    FailureReason, anyhow,
    base::{Json, Plugin},
    event::events::types::EventType,
    extract::{EventInput, ExtractFieldInfo, ExtractPlugin, ExtractRequest, field},
    extract_plugin, plugin,
    schemars::JsonSchema,
    serde::Deserialize,
    source::{EventBatch, PluginEvent, SourcePlugin, SourcePluginInstance},
    source_plugin,
    tables::TablesInput,
};
use tokio::runtime::Runtime;

/// Plugin configuration
#[derive(JsonSchema, Deserialize, Clone)]
#[schemars(crate = "falco_plugin::schemars")]
#[serde(rename_all = "camelCase", crate = "falco_plugin::serde")]
pub struct Config {
    /// AWS Region for ELB operations
    region: String,

    /// S3 bucket name for ELB access logs
    s3_bucket: String,

    /// S3 prefix for ELB access logs
    s3_prefix: String,
}

/// Plugin state
pub struct AwsElbPlugin {
    config: Config,
    runtime: Arc<Mutex<Runtime>>,
    s3_client: Arc<S3Client>,
}

impl Plugin for AwsElbPlugin {
    const NAME: &'static CStr = c"awselb";
    const PLUGIN_VERSION: &'static CStr = c"0.1.0";
    const DESCRIPTION: &'static CStr = c"AWS Elastic Load Balancer access logs plugin";
    const CONTACT: &'static CStr = c"https://github.com/yukinakanaka/falco-plugin-aws-elb";
    type ConfigType = Json<Config>;

    fn new(_input: Option<&TablesInput>, Json(config): Self::ConfigType) -> anyhow::Result<Self> {
        let runtime =
            Arc::new(Mutex::new(Runtime::new().map_err(|e| {
                anyhow::anyhow!("Failed to create tokio runtime: {}", e)
            })?));

        let guard = runtime.lock().unwrap();
        let region = config.region.clone();
        let s3_client = guard.block_on(async move {
            let config = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(region))
                .load()
                .await;

            let s3_client = S3Client::new(&config);

            Arc::new(s3_client)
        });
        drop(guard);
        let plugin = Self {
            config,
            runtime,
            s3_client,
        };

        Ok(plugin)
    }
}

/// Plugin instance state
pub struct AwsElbPluginInstance {
    s3_bucket: String,
    s3_prefix: String,
    events_buffer: Vec<ElbLogEntry>,
    buffer_index: usize,
    s3_objects: Vec<String>,
    current_object_index: usize,
    last_processed_key: Option<String>,
}

impl AwsElbPluginInstance {
    fn has_buffered_event(&self) -> bool {
        self.buffer_index < self.events_buffer.len()
    }

    fn add_next_event_to_batch(&mut self, batch: &mut EventBatch) -> anyhow::Result<()> {
        if let Some(event) = self.events_buffer.get(self.buffer_index) {
            let event_json = serde_json::to_string(event)?;
            let event_data = event_json.as_bytes().to_vec();
            let plugin_event = Self::plugin_event(&event_data);
            batch.add(plugin_event)?;
            self.buffer_index += 1;
        }
        Ok(())
    }

    fn fetch_more_s3_objects(
        &mut self,
        plugin: &mut <AwsElbPluginInstance as SourcePluginInstance>::Plugin,
    ) -> anyhow::Result<()> {
        // If we don't have any S3 objects listed yet, or we've processed all of them, get more
        if self.s3_objects.is_empty() || self.current_object_index >= self.s3_objects.len() {
            let runtime = plugin.runtime.clone();
            let guard = runtime.lock().unwrap();

            let new_objects = guard.block_on(async {
                list_objects(
                    &plugin.s3_client,
                    &self.s3_bucket,
                    &self.s3_prefix,
                    self.last_processed_key.as_deref(),
                )
                .await
            })?;

            self.s3_objects = new_objects;
            self.current_object_index = 0;
        }
        Ok(())
    }

    fn download_next_s3_object(
        &mut self,
        plugin: &mut <AwsElbPluginInstance as SourcePluginInstance>::Plugin,
    ) -> anyhow::Result<Vec<ElbLogEntry>> {
        let object_key = self.s3_objects[self.current_object_index].clone();
        self.current_object_index += 1;
        self.last_processed_key = Some(object_key.clone());

        let runtime = plugin.runtime.clone();
        let guard = runtime.lock().unwrap();

        guard.block_on(async {
            download_and_parse_object(&plugin.s3_client, &self.s3_bucket, &object_key).await
        })
    }

    fn refill_buffer(&mut self, new_events: Vec<ElbLogEntry>) {
        self.events_buffer.extend(new_events);
        self.buffer_index = 0;
    }
}

impl SourcePluginInstance for AwsElbPluginInstance {
    type Plugin = AwsElbPlugin;

    fn next_batch(
        &mut self,
        plugin: &mut Self::Plugin,
        batch: &mut EventBatch,
    ) -> anyhow::Result<()> {
        // Try to process event from buffer first
        if self.has_buffered_event() {
            self.add_next_event_to_batch(batch)?;
            return Ok(());
        }

        // Buffer is empty, fetch more data from S3
        self.fetch_more_s3_objects(plugin)?;

        // If still no objects after listing, sleep and return timeout error
        // The plugin framework will retry the call to `next_batch` later.
        if self.current_object_index >= self.s3_objects.len() {
            // TODO: Use a more sophisticated sleep strategy. Handle graceful shutdown.
            std::thread::sleep(Duration::from_secs(1));
            return Err(anyhow::anyhow!("no events right now").context(FailureReason::Timeout));
        }

        // Download and process the next S3 object
        let new_events = self.download_next_s3_object(plugin)?;
        self.refill_buffer(new_events);

        // Process first event from newly filled buffer
        if self.has_buffered_event() {
            self.add_next_event_to_batch(batch)?;
        }
        Ok(())
    }
}

impl SourcePlugin for AwsElbPlugin {
    type Instance = AwsElbPluginInstance;
    const EVENT_SOURCE: &'static CStr = c"awselb";
    const PLUGIN_ID: u32 = 25;

    fn open(&mut self, _params: Option<&str>) -> anyhow::Result<Self::Instance> {
        Ok(Self::Instance {
            s3_bucket: self.config.s3_bucket.clone(),
            s3_prefix: self.config.s3_prefix.clone(),
            events_buffer: Vec::new(),
            buffer_index: 0,
            s3_objects: Vec::new(),
            current_object_index: 0,
            last_processed_key: None,
        })
    }

    fn event_to_string(&mut self, event: &EventInput) -> anyhow::Result<CString> {
        let event = event.event()?;
        let event = event.load::<PluginEvent>()?;
        match event.params.event_data {
            Some(payload) => {
                let json_str = String::from_utf8(payload.to_vec())?;
                Ok(CString::new(json_str)?)
            }
            None => Ok(CString::new("{}")?),
        }
    }
}

// Common extraction logic
macro_rules! extract_log_entry {
    ($self:ident, $req:ident) => {{
        let event = $req.event.event()?;
        let event = event.load::<PluginEvent>()?;
        if let Some(payload) = event.params.event_data {
            let json_str = String::from_utf8(payload.to_vec())?;
            let log_entry: ElbLogEntry = serde_json::from_str(&json_str)?;
            Ok(log_entry)
        } else {
            Err(anyhow::anyhow!("No event data found"))
        }
    }};
}

// Macro to generate extraction functions for string fields
macro_rules! extract_string_field {
    ($fn_name:ident, $field:ident) => {
        fn $fn_name(&mut self, req: ExtractRequest<Self>) -> anyhow::Result<CString> {
            let log_entry = extract_log_entry!(self, req)?;
            Ok(CString::new(log_entry.$field)?)
        }
    };
}

// Macro to generate extraction functions for numeric fields
macro_rules! extract_numeric_field {
    ($fn_name:ident, $field:ident, $return_type:ty) => {
        fn $fn_name(&mut self, req: ExtractRequest<Self>) -> anyhow::Result<$return_type> {
            let log_entry = extract_log_entry!(self, req)?;
            Ok(log_entry.$field as $return_type)
        }
    };
}

// Macro to generate extraction functions for f64 fields as strings
macro_rules! extract_float_as_string {
    ($fn_name:ident, $field:ident) => {
        fn $fn_name(&mut self, req: ExtractRequest<Self>) -> anyhow::Result<CString> {
            let log_entry = extract_log_entry!(self, req)?;
            Ok(CString::new(log_entry.$field.to_string())?)
        }
    };
}

// Macro to generate field definitions
macro_rules! extract_fields {
    (
        $(
            $field_name:literal => $fn_name:ident: $description:literal
        ),* $(,)?
    ) => {
        &[
            $(
                field($field_name, &Self::$fn_name).with_description($description),
            )*
        ]
    };
}

impl AwsElbPlugin {
    // String field extraction functions
    extract_string_field!(extract_request_type, request_type);
    extract_string_field!(extract_timestamp, timestamp);
    extract_string_field!(extract_elb_name, elb_name);
    extract_string_field!(extract_client_ip, client_ip);
    extract_string_field!(extract_target_ip, target_ip);
    extract_string_field!(extract_target_status_code, target_status_code);
    extract_string_field!(extract_request_verb, request_verb);
    extract_string_field!(extract_request_url, request_url);
    extract_string_field!(extract_request_proto, request_proto);
    extract_string_field!(extract_user_agent, user_agent);
    extract_string_field!(extract_ssl_cipher, ssl_cipher);
    extract_string_field!(extract_ssl_protocol, ssl_protocol);
    extract_string_field!(extract_target_group_arn, target_group_arn);
    extract_string_field!(extract_trace_id, trace_id);
    extract_string_field!(extract_domain_name, domain_name);
    extract_string_field!(extract_chosen_cert_arn, chosen_cert_arn);
    extract_string_field!(extract_matched_rule_priority, matched_rule_priority);
    extract_string_field!(extract_request_creation_time, request_creation_time);
    extract_string_field!(extract_actions_executed, actions_executed);
    extract_string_field!(extract_redirect_url, redirect_url);
    extract_string_field!(extract_error_reason, error_reason);
    extract_string_field!(extract_target_port_list, target_port_list);
    extract_string_field!(extract_target_status_code_list, target_status_code_list);
    extract_string_field!(extract_classification, classification);
    extract_string_field!(extract_classification_reason, classification_reason);
    extract_string_field!(extract_conn_trace_id, conn_trace_id);

    // Numeric field extraction functions
    extract_numeric_field!(extract_client_port, client_port, u64);
    extract_numeric_field!(extract_target_port, target_port, u64);
    extract_numeric_field!(extract_elb_status_code, elb_status_code, u64);
    extract_numeric_field!(extract_received_bytes, received_bytes, u64);
    extract_numeric_field!(extract_sent_bytes, sent_bytes, u64);

    // f64 fields extracted as strings
    extract_float_as_string!(extract_request_processing_time, request_processing_time);
    extract_float_as_string!(extract_target_processing_time, target_processing_time);
    extract_float_as_string!(extract_response_processing_time, response_processing_time);
}

impl ExtractPlugin for AwsElbPlugin {
    const EVENT_TYPES: &'static [EventType] = &[];
    const EVENT_SOURCES: &'static [&'static str] = &["awselb"];
    type ExtractContext = ();

    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = extract_fields!(
        "awselb.request_type" => extract_request_type: "The type of request (HTTP/HTTPS)",
        "awselb.timestamp" => extract_timestamp: "The timestamp of the request",
        "awselb.name" => extract_elb_name: "The name of the ELB",
        "awselb.client_ip" => extract_client_ip: "The IP address of the client",
        "awselb.client_port" => extract_client_port: "The port number of the client",
        "awselb.target_ip" => extract_target_ip: "The IP address of the target",
        "awselb.target_port" => extract_target_port: "The port number of the target",
        "awselb.request_processing_time" => extract_request_processing_time: "The request processing time in seconds",
        "awselb.target_processing_time" => extract_target_processing_time: "The target processing time in seconds",
        "awselb.response_processing_time" => extract_response_processing_time: "The response processing time in seconds",
        "awselb.elb_status_code" => extract_elb_status_code: "The HTTP status code returned by the ELB",
        "awselb.target_status_code" => extract_target_status_code: "The HTTP status code returned by the target",
        "awselb.received_bytes" => extract_received_bytes: "The size of the request in bytes",
        "awselb.sent_bytes" => extract_sent_bytes: "The size of the response in bytes",
        "awselb.request_verb" => extract_request_verb: "The HTTP request method",
        "awselb.request_url" => extract_request_url: "The request URL",
        "awselb.request_proto" => extract_request_proto: "The request protocol version",
        "awselb.user_agent" => extract_user_agent: "The User-Agent header from the client",
        "awselb.ssl_cipher" => extract_ssl_cipher: "The SSL cipher used for the connection",
        "awselb.ssl_protocol" => extract_ssl_protocol: "The SSL protocol version used",
        "awselb.target_group_arn" => extract_target_group_arn: "The ARN of the target group",
        "awselb.trace_id" => extract_trace_id: "The trace ID for the request",
        "awselb.domain_name" => extract_domain_name: "The domain name used in the request",
        "awselb.chosen_cert_arn" => extract_chosen_cert_arn: "The ARN of the chosen certificate",
        "awselb.matched_rule_priority" => extract_matched_rule_priority: "The priority of the matched rule",
        "awselb.request_creation_time" => extract_request_creation_time: "The time when the request was created",
        "awselb.actions_executed" => extract_actions_executed: "The actions executed for the request",
        "awselb.redirect_url" => extract_redirect_url: "The redirect URL if applicable",
        "awselb.error_reason" => extract_error_reason: "The error reason if applicable",
        "awselb.target_port_list" => extract_target_port_list: "The list of target ports",
        "awselb.target_status_code_list" => extract_target_status_code_list: "The list of target status codes",
        "awselb.classification" => extract_classification: "The classification of the request",
        "awselb.classification_reason" => extract_classification_reason: "The reason for the classification",
        "awselb.conn_trace_id" => extract_conn_trace_id: "The connection trace ID",
    );
}

plugin!(AwsElbPlugin);
source_plugin!(AwsElbPlugin);
extract_plugin!(AwsElbPlugin);
