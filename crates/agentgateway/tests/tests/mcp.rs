use itertools::Itertools;
use rmcp::model::*;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::time::Duration;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::gateway::AgentGateway;
use crate::common::mcp::{
	ComprehensiveClient, MockMcpServer, multiplex_config, setup_comprehensive_client,
	start_mock_mcp_server,
};

struct MultiplexTestFixture {
	client: ComprehensiveClient,
	update_count: Arc<AtomicUsize>,
	_gw: AgentGateway,
	_mcp1: MockMcpServer,
	_mcp2: MockMcpServer,
	_s3_mock: MockServer,
}

impl MultiplexTestFixture {
	async fn setup() -> anyhow::Result<Self> {
		agent_core::telemetry::testing::setup_test_logging();

		let mcp1 = start_mock_mcp_server("s1", true).await;
		let mcp2 = start_mock_mcp_server("s2", false).await;

		let s3_mock = MockServer::start().await;
		Mock::given(method("POST"))
			.respond_with(ResponseTemplate::new(500).set_body_string("CRASH"))
			.mount(&s3_mock)
			.await;

		let config = multiplex_config(&mcp1, &mcp2, *s3_mock.address());
		let gw = AgentGateway::new(config).await?;
		let mcp_url = format!("http://localhost:{}/mcp", gw.port());
		let update_count = Arc::new(AtomicUsize::new(0));
		let client = setup_comprehensive_client(&mcp_url, update_count.clone()).await?;

		Ok(Self {
			client,
			update_count,
			_gw: gw,
			_mcp1: mcp1,
			_mcp2: mcp2,
			_s3_mock: s3_mock,
		})
	}
}

fn assert_prefixed_by(name: &str, target: &str) {
	assert!(
		name.starts_with(&format!("{target}__")),
		"expected '{name}' to be prefixed by '{target}__'"
	);
}

fn assert_wrapped_uri_for_target(uri: &str, target: &str) {
	assert!(
		uri.starts_with(&format!("agw://{target}/")),
		"expected URI '{uri}' to be wrapped for target '{target}'"
	);
}

#[tokio::test]
async fn e2e_tools_aggregation_and_rbac_filtering() -> anyhow::Result<()> {
	let fixture = MultiplexTestFixture::setup().await?;
	let client = &fixture.client;

	let tools = client.list_tools(None).await?;
	let names = tools.tools.iter().map(|t| t.name.to_string()).collect_vec();
	let s1_echo = names
		.iter()
		.find(|name| name.as_str() == "s1__echo")
		.expect("s1__echo missing");
	assert_prefixed_by(s1_echo, "s1");
	assert!(
		!names.contains(&"s2__echo".into()),
		"RBAC failed to filter s2__echo"
	);
	assert!(
		!names.iter().any(|n| n.starts_with("s3__")),
		"Broken backend tools leaked into list"
	);

	let tool_resp = client
		.call_tool(CallToolRequestParams {
			name: "s1__echo".into(),
			arguments: Some(json!({"val": "hello"}).as_object().unwrap().clone()),
			meta: None,
			task: None,
		})
		.await?;

	let tool_val = serde_json::to_value(&tool_resp.content[0])?;
	assert_eq!(
		tool_val.get("text").and_then(|v| v.as_str()),
		Some("s1: hello")
	);
	Ok(())
}

#[tokio::test]
async fn e2e_resources_list_partial_success_with_one_failing_upstream() -> anyhow::Result<()> {
	let fixture = MultiplexTestFixture::setup().await?;
	let client = &fixture.client;

	let resources = client.list_resources(None).await?;
	let names = resources
		.resources
		.iter()
		.map(|r| r.name.to_string())
		.collect_vec();
	assert!(names.contains(&"s1__data".to_string()));
	assert!(names.contains(&"s2__data".to_string()));
	assert!(
		!names.iter().any(|name| name.starts_with("s3__")),
		"partial-success fanout failed; expected failing upstream s3 to be excluded"
	);
	Ok(())
}

#[tokio::test]
async fn e2e_tasks_lifecycle_multiplex() -> anyhow::Result<()> {
	let fixture = MultiplexTestFixture::setup().await?;
	let client = &fixture.client;

	let task_call = client
		.send_request(ClientRequest::CallToolRequest(CallToolRequest {
			method: Default::default(),
			params: CallToolRequestParams {
				meta: None,
				task: json!({}).as_object().cloned(),
				name: "s1__echo".into(),
				arguments: Some(json!({"val": "task-hello"}).as_object().unwrap().clone()),
			},
			extensions: Default::default(),
		}))
		.await?;
	let task_id = match task_call {
		ServerResult::CreateTaskResult(result) => result.task.task_id,
		other => panic!("Expected CreateTaskResult for task call, got: {:?}", other),
	};
	assert_prefixed_by(&task_id, "s1");

	let listed_tasks = client
		.send_request(ClientRequest::ListTasksRequest(ListTasksRequest {
			method: Default::default(),
			params: Some(PaginatedRequestParams {
				meta: None,
				cursor: None,
			}),
			extensions: Default::default(),
		}))
		.await?;
	let listed_tasks = match listed_tasks {
		ServerResult::ListTasksResult(result) => result,
		other => panic!("Expected ListTasksResult, got: {:?}", other),
	};
	assert!(
		listed_tasks
			.tasks
			.iter()
			.any(|task| task.task_id == task_id),
		"Task not returned in list/tasks response"
	);

	let task_info = client
		.send_request(ClientRequest::GetTaskInfoRequest(GetTaskInfoRequest {
			method: Default::default(),
			params: GetTaskInfoParams {
				meta: None,
				task_id: task_id.clone(),
			},
			extensions: Default::default(),
		}))
		.await?;
	let task_info = match task_info {
		ServerResult::GetTaskResult(result) => result.task,
		other => panic!("Expected GetTaskResult for tasks/info, got: {:?}", other),
	};
	assert_eq!(task_info.task_id, task_id);
	assert_eq!(task_info.status, TaskStatus::Completed);

	let task_payload = client
		.send_request(ClientRequest::GetTaskResultRequest(GetTaskResultRequest {
			method: Default::default(),
			params: GetTaskResultParams {
				meta: None,
				task_id: task_id.clone(),
			},
			extensions: Default::default(),
		}))
		.await?;
	let task_payload = match task_payload {
		ServerResult::CustomResult(result) => result.0,
		other => panic!("Expected CustomResult for tasks/result, got: {:?}", other),
	};
	assert_eq!(
		task_payload.get("tool").and_then(|v| v.as_str()),
		Some("echo")
	);
	assert_eq!(
		task_payload
			.get("arguments")
			.and_then(|v| v.get("val"))
			.and_then(|v| v.as_str()),
		Some("task-hello")
	);

	let task_cancel = client
		.send_request(ClientRequest::CancelTaskRequest(CancelTaskRequest {
			method: Default::default(),
			params: CancelTaskParams {
				meta: None,
				task_id: task_id.clone(),
			},
			extensions: Default::default(),
		}))
		.await?;
	let task_cancel = match task_cancel {
		ServerResult::GetTaskResult(result) => result.task,
		other => panic!("Expected GetTaskResult for tasks/cancel, got: {:?}", other),
	};
	assert_eq!(task_cancel.task_id, task_id);
	assert_eq!(task_cancel.status, TaskStatus::Cancelled);
	Ok(())
}

#[tokio::test]
async fn e2e_prompts_multiplex_roundtrip() -> anyhow::Result<()> {
	let fixture = MultiplexTestFixture::setup().await?;
	let client = &fixture.client;

	let prompts = client.list_prompts(None).await?;
	assert!(prompts.prompts.iter().any(|p| p.name == "s1__test_prompt"));

	let prompt_resp = client
		.get_prompt(GetPromptRequestParams {
			name: "s1__test_prompt".into(),
			arguments: Some(json!({"val": "world"}).as_object().unwrap().clone()),
			meta: None,
		})
		.await?;

	let prompt_val = serde_json::to_value(&prompt_resp.messages[0].content)?;
	assert_eq!(
		prompt_val.get("text").and_then(|v| v.as_str()),
		Some("val: world")
	);
	Ok(())
}

#[tokio::test]
async fn e2e_resources_multiplex_uri_wrapping_and_read_roundtrip() -> anyhow::Result<()> {
	let fixture = MultiplexTestFixture::setup().await?;
	let client = &fixture.client;

	let resources = client.list_resources(None).await?;
	let s1_res = resources
		.resources
		.iter()
		.find(|r| r.name == "s1__data")
		.expect("s1__res missing");
	assert_wrapped_uri_for_target(&s1_res.uri, "s1");

	let s1_template = resources
		.resources
		.iter()
		.find(|r| r.name == "s1__template")
		.expect("s1__template missing");
	assert!(
		s1_template.uri.contains("{id}"),
		"Braces were incorrectly encoded in template: {}",
		s1_template.uri
	);

	// Verify Reading through Wrapped URI
	let r_resp = client
		.read_resource(ReadResourceRequestParams {
			uri: s1_res.uri.clone(),
			meta: None,
		})
		.await?;

	let resource_val = serde_json::to_value(&r_resp.contents[0])?;
	assert_eq!(
		resource_val.get("text").and_then(|v| v.as_str()),
		Some("server-data")
	);
	Ok(())
}

#[tokio::test]
async fn e2e_elicitation_roundtrip_multiplex() -> anyhow::Result<()> {
	let fixture = MultiplexTestFixture::setup().await?;
	let client = &fixture.client;

	let e_resp = client
		.call_tool(CallToolRequestParams {
			name: "s1__elicitation".into(),
			arguments: None,
			meta: None,
			task: None,
		})
		.await?;
	assert_eq!(
		e_resp.structured_content.unwrap().get("color").unwrap(),
		"diamond"
	);
	Ok(())
}

#[tokio::test]
async fn e2e_resource_update_notification_after_subscribe() -> anyhow::Result<()> {
	let fixture = MultiplexTestFixture::setup().await?;
	let client = &fixture.client;

	let resources = client.list_resources(None).await?;
	let s1_res = resources
		.resources
		.iter()
		.find(|r| r.name == "s1__data")
		.expect("s1__res missing");

	client
		.subscribe(SubscribeRequestParams {
			uri: s1_res.uri.clone(),
			meta: None,
		})
		.await?;

	client
		.call_tool(CallToolRequestParams {
			name: "s1__trigger_update".into(),
			arguments: None,
			meta: None,
			task: None,
		})
		.await?;

	let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
	while fixture.update_count.load(Ordering::SeqCst) == 0 && tokio::time::Instant::now() < deadline {
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	assert!(
		fixture.update_count.load(Ordering::SeqCst) > 0,
		"expected at least one resources/updated notification after subscribe"
	);

	Ok(())
}
