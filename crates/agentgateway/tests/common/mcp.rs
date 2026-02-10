use rmcp::model::*;
use rmcp::service::*;
use rmcp::{RoleServer, ServerHandler, ServiceExt, prompt_router, tool_handler, tool_router};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;

pub(crate) type ComprehensiveClient = RunningService<RoleClient, ComprehensiveClientHandler>;

pub(crate) async fn setup_comprehensive_client(
	url: &str,
	update_count: Arc<AtomicUsize>,
) -> anyhow::Result<ComprehensiveClient> {
	use rmcp::transport::StreamableHttpClientTransport;
	let transport = StreamableHttpClientTransport::from_uri(url.to_string());

	let client_info = ClientInfo {
		meta: None,
		protocol_version: Default::default(),
		capabilities: ClientCapabilities::builder()
			.enable_tasks_with(TasksCapability::client_default())
			.enable_elicitation_with(ElicitationCapability {
				form: Some(FormElicitationCapability {
					schema_validation: Some(true),
				}),
				url: Some(UrlElicitationCapability::default()),
			})
			.build(),
		client_info: Implementation {
			name: "comprehensive-client".to_string(),
			version: "1.0.0".to_string(),
			title: None,
			description: None,
			website_url: None,
			icons: None,
		},
	};

	let client = ComprehensiveClientHandler {
		info: client_info,
		update_count,
	}
	.serve(transport)
	.await
	.map_err(|e| anyhow::anyhow!("failed to serve: {:?}", e))?;

	Ok(client)
}

pub(crate) struct ComprehensiveClientHandler {
	info: ClientInfo,
	update_count: Arc<AtomicUsize>,
}

impl rmcp::ClientHandler for ComprehensiveClientHandler {
	fn get_info(&self) -> ClientInfo {
		self.info.clone()
	}

	fn create_elicitation(
		&self,
		_req: CreateElicitationRequestParams,
		_: RequestContext<rmcp::RoleClient>,
	) -> impl std::future::Future<Output = Result<CreateElicitationResult, ErrorData>> + Send + '_ {
		std::future::ready(Ok(CreateElicitationResult {
			action: ElicitationAction::Accept,
			content: Some(json!({"color": "diamond"})),
		}))
	}

	fn on_resource_updated(
		&self,
		_req: ResourceUpdatedNotificationParam,
		_: NotificationContext<rmcp::RoleClient>,
	) -> impl std::future::Future<Output = ()> + Send + '_ {
		self.update_count.fetch_add(1, Ordering::SeqCst);
		std::future::ready(())
	}
}

pub(crate) async fn start_mock_mcp_server(label: &'static str, stateful: bool) -> MockMcpServer {
	use rmcp::transport::StreamableHttpServerConfig;
	use rmcp::transport::streamable_http_server::StreamableHttpService;
	use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;

	let service = StreamableHttpService::new(
		move || Ok(RobustHandler::new(label)),
		LocalSessionManager::default().into(),
		StreamableHttpServerConfig {
			stateful_mode: stateful,
			..Default::default()
		},
	);

	let (tx, rx) = tokio::sync::oneshot::channel();
	let router = axum::Router::new().nest_service("/mcp", service);
	let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = tcp_listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(tcp_listener, router)
			.with_graceful_shutdown(async {
				let _ = rx.await;
			})
			.await;
	});
	MockMcpServer { addr, _cancel: tx }
}

pub(crate) fn multiplex_config(
	mcp1: &MockMcpServer,
	mcp2: &MockMcpServer,
	broken_mcp_addr: std::net::SocketAddr,
) -> String {
	format!(
		r#"
config: {{}}
binds:
- port: $PORT
  listeners:
  - name: comprehensive-gateway
    routes:
    - matches:
      - path:
          pathPrefix: /mcp
      backends:
      - mcp:
          targets:
          - name: s1
            mcp:
              host: http://{}/mcp
          - name: s2
            mcp:
              host: http://{}/mcp
          - name: s3
            mcp:
              host: http://{}/mcp
      policies:
        mcpAuthorization:
          rules:
          - 'true'
          - deny: 'mcp.tool.target == "s2" && mcp.tool.name == "echo"'
"#,
		mcp1.addr, mcp2.addr, broken_mcp_addr
	)
}

pub(crate) struct MockMcpServer {
	pub(crate) addr: std::net::SocketAddr,
	_cancel: tokio::sync::oneshot::Sender<()>,
}

#[derive(Clone)]
struct RobustHandler {
	label: &'static str,
	tool_router: rmcp::handler::server::router::tool::ToolRouter<RobustHandler>,
	prompt_router: rmcp::handler::server::router::prompt::PromptRouter<RobustHandler>,
	tasks: Arc<Mutex<TaskStore>>,
}

impl RobustHandler {
	fn new(label: &'static str) -> Self {
		Self {
			label,
			tool_router: Self::tool_router(),
			prompt_router: Self::prompt_router(),
			tasks: Arc::new(Mutex::new(TaskStore::default())),
		}
	}
}

#[tool_router]
impl RobustHandler {
	#[rmcp::tool(description = "Echo", execution(task_support = "optional"))]
	fn echo(
		&self,
		rmcp::handler::server::wrapper::Parameters(val): rmcp::handler::server::wrapper::Parameters<
			serde_json::Value,
		>,
	) -> Result<CallToolResult, ErrorData> {
		let text = val.get("val").and_then(|v| v.as_str()).unwrap_or("empty");
		Ok(CallToolResult::success(vec![Annotated::new(
			RawContent::text(format!("{}: {}", self.label, text)),
			None,
		)]))
	}

	#[rmcp::tool(description = "Trigger Elicitation")]
	async fn elicitation(
		&self,
		ctx: RequestContext<RoleServer>,
	) -> Result<CallToolResult, ErrorData> {
		let params = CreateElicitationRequestParams::FormElicitationParams {
			meta: None,
			message: "select gem".to_string(),
			requested_schema: ElicitationSchema::builder()
				.required_string("color")
				.build()
				.unwrap(),
		};
		let req = CreateElicitationRequest {
			method: Default::default(),
			params,
			extensions: Default::default(),
		};
		let resp = ctx
			.peer
			.send_request(ServerRequest::CreateElicitationRequest(req))
			.await
			.map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
		if let ClientResult::CreateElicitationResult(res) = resp {
			Ok(CallToolResult {
				content: vec![Annotated::new(RawContent::text("accepted"), None)],
				structured_content: res.content,
				is_error: Some(false),
				meta: None,
			})
		} else {
			Err(ErrorData::internal_error("Unexpected response", None))
		}
	}

	#[rmcp::tool(description = "Trigger Resource Update")]
	async fn trigger_update(
		&self,
		ctx: RequestContext<RoleServer>,
	) -> Result<CallToolResult, ErrorData> {
		let notif = ResourceUpdatedNotification {
			method: Default::default(),
			params: ResourceUpdatedNotificationParam {
				uri: "memo://data".to_string(),
			},
			extensions: Default::default(),
		};
		ctx
			.peer
			.send_notification(ServerNotification::ResourceUpdatedNotification(notif))
			.await
			.map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
		Ok(CallToolResult::success(vec![Annotated::new(
			RawContent::text("notified"),
			None,
		)]))
	}
}

#[prompt_router]
impl RobustHandler {
	#[rmcp::prompt(name = "test_prompt")]
	fn test_prompt(
		&self,
		rmcp::handler::server::wrapper::Parameters(val): rmcp::handler::server::wrapper::Parameters<
			serde_json::Value,
		>,
	) -> Result<GetPromptResult, ErrorData> {
		let msg = val.get("val").and_then(|v| v.as_str()).unwrap_or("none");
		Ok(GetPromptResult {
			description: None,
			messages: vec![PromptMessage {
				role: PromptMessageRole::User,
				content: PromptMessageContent::Text {
					text: format!("val: {}", msg),
				},
			}],
		})
	}
}

#[tool_handler]
#[rmcp::prompt_handler]
impl ServerHandler for RobustHandler {
	fn get_info(&self) -> ServerInfo {
		ServerInfo {
			protocol_version: ProtocolVersion::V_2025_06_18,
			capabilities: ServerCapabilities::builder()
				.enable_tools()
				.enable_resources()
				.enable_prompts()
				.enable_tasks_with(TasksCapability::server_default())
				.build(),
			server_info: Implementation::from_build_env(),
			instructions: None,
		}
	}

	fn list_resources(
		&self,
		_: Option<PaginatedRequestParams>,
		_: RequestContext<RoleServer>,
	) -> impl std::future::Future<Output = Result<ListResourcesResult, ErrorData>> + Send {
		std::future::ready(Ok(ListResourcesResult {
			resources: vec![
				RawResource::new("memo://data", "data").no_annotation(),
				RawResource::new("memo://{id}", "template").no_annotation(),
			],
			next_cursor: None,
			meta: None,
		}))
	}

	fn read_resource(
		&self,
		params: ReadResourceRequestParams,
		_: RequestContext<RoleServer>,
	) -> impl std::future::Future<Output = Result<ReadResourceResult, ErrorData>> + Send {
		std::future::ready(Ok(ReadResourceResult {
			contents: vec![ResourceContents::TextResourceContents {
				uri: params.uri,
				mime_type: Some("text/plain".to_string()),
				text: "server-data".to_string(),
				meta: None,
			}],
		}))
	}

	fn subscribe(
		&self,
		_params: SubscribeRequestParams,
		_: RequestContext<RoleServer>,
	) -> impl std::future::Future<Output = Result<(), ErrorData>> + Send {
		std::future::ready(Ok(()))
	}

	async fn enqueue_task(
		&self,
		request: CallToolRequestParams,
		_: RequestContext<RoleServer>,
	) -> Result<CreateTaskResult, ErrorData> {
		let mut tasks = self.tasks.lock().await;
		let result = json!({
			"tool": request.name.to_string(),
			"arguments": request.arguments,
		});
		let task = tasks.create_task(result);
		Ok(CreateTaskResult { task })
	}

	async fn list_tasks(
		&self,
		_: Option<PaginatedRequestParams>,
		_: RequestContext<RoleServer>,
	) -> Result<ListTasksResult, ErrorData> {
		let tasks = self.tasks.lock().await;
		Ok(ListTasksResult {
			tasks: tasks
				.tasks
				.values()
				.map(|entry| entry.task.clone())
				.collect(),
			next_cursor: None,
			total: None,
		})
	}

	async fn get_task_info(
		&self,
		request: GetTaskInfoParams,
		_: RequestContext<RoleServer>,
	) -> Result<GetTaskResult, ErrorData> {
		let mut tasks = self.tasks.lock().await;
		if let Some(entry) = tasks.tasks.get_mut(&request.task_id) {
			if entry.task.status == TaskStatus::Working && entry.result.is_some() {
				entry.task.status = TaskStatus::Completed;
				entry.task.status_message = Some("completed".to_string());
				entry.task.last_updated_at = entry.task.created_at.clone();
			}
			return Ok(GetTaskResult {
				meta: None,
				task: entry.task.clone(),
			});
		}

		Err(ErrorData::invalid_params(
			"task not found".to_string(),
			None,
		))
	}

	async fn get_task_result(
		&self,
		request: GetTaskResultParams,
		_: RequestContext<RoleServer>,
	) -> Result<GetTaskPayloadResult, ErrorData> {
		let mut tasks = self.tasks.lock().await;
		let entry = tasks.tasks.get_mut(&request.task_id);
		let Some(entry) = entry else {
			return Err(ErrorData::invalid_params(
				"task not found".to_string(),
				None,
			));
		};
		if let Some(result) = entry.result.clone() {
			entry.task.status = TaskStatus::Completed;
			entry.task.status_message = Some("completed".to_string());
			entry.task.last_updated_at = entry.task.created_at.clone();
			return Ok(GetTaskPayloadResult(result));
		}
		Err(ErrorData::invalid_params(
			"task not ready".to_string(),
			None,
		))
	}

	async fn cancel_task(
		&self,
		request: CancelTaskParams,
		_: RequestContext<RoleServer>,
	) -> Result<CancelTaskResult, ErrorData> {
		let mut tasks = self.tasks.lock().await;
		if let Some(entry) = tasks.tasks.get_mut(&request.task_id) {
			entry.task.status = TaskStatus::Cancelled;
			entry.task.status_message = Some("cancelled".to_string());
			entry.task.last_updated_at = entry.task.created_at.clone();
			entry.result = None;
			return Ok(CancelTaskResult {
				meta: None,
				task: entry.task.clone(),
			});
		}
		Err(ErrorData::invalid_params(
			"task not found".to_string(),
			None,
		))
	}
}

#[derive(Debug, Default)]
struct TaskStore {
	next_id: u64,
	tasks: HashMap<String, TaskEntry>,
}

#[derive(Debug)]
struct TaskEntry {
	task: Task,
	result: Option<serde_json::Value>,
}

impl TaskStore {
	fn create_task(&mut self, result: serde_json::Value) -> Task {
		let task_id = format!("task-{}", self.next_id);
		self.next_id += 1;
		let created_at = "2026-01-01T00:00:00Z".to_string();
		let task = Task {
			task_id: task_id.clone(),
			status: TaskStatus::Working,
			status_message: Some("queued".to_string()),
			created_at: created_at.clone(),
			last_updated_at: created_at,
			ttl: None,
			poll_interval: Some(10),
		};
		self.tasks.insert(
			task_id,
			TaskEntry {
				task: task.clone(),
				result: Some(result),
			},
		);
		task
	}
}
