## Telemetry Example

This example shows how to use the agentgateway to visualize traces and metrics for MCP calls.
This builds upon the [RBAC sample](../authorization).
While you can use tracing without RBAC, this example uses both together to showcase augmenting traces with information from the authenicated user.

### Running the example

```bash
cargo run -- -f examples/telemetry/config.yaml
```

Let's look at the config to understand what's going on.

In addition to the baseline configuration we had previously, we have a new `config` `tracing` section, which tells the proxy how to trace requests.

```yaml
config:
  tracing:
    otlpEndpoint: http://localhost:4317
```

Here, we configure sending traces to an [OTLP](https://opentelemetry.io/docs/specs/otel/protocol/) endpoint.

For metrics, they are enabled by default so no configuration is needed

Next, we will want to get a tracing backend running.
You can use any OTLP endpoint if you already have one, or run a local [Jaeger](https://www.jaegertracing.io/) instance by running `docker compose up -d`

Send a few requests from the MCP inspector to generate some telemetry.

Now we can open the [Jaeger UI](http://localhost:16686/search) and search for our spans:

![Jaeger](./img/jaeger.png)

We can also see the metrics (typically, Prometheus would scrape these):

```
$ curl localhost:15020/metrics -s | grep -v '#'
tool_calls_total{server="everything",name="echo"} 1
tool_calls_total{server="everything",name="add"} 1
list_calls_total{resource_type="tool"} 3
agentgateway_requests_total{gateway="bind/3000",method="POST",status="200"} 9
agentgateway_requests_total{gateway="bind/3000",method="POST",status="202"} 4
agentgateway_requests_total{gateway="bind/3000",method="GET",status="200"} 1
agentgateway_requests_total{gateway="bind/3000",method="DELETE",status="202"} 2
```

## Advanced CEL Expressions for LLM Observability

The gateway supports powerful CEL (Common Expression Language) expressions for customizing observability data. Here are examples for AWS Bedrock and other LLM providers.

### Cache Effectiveness Tracking

Track prompt caching effectiveness to optimize costs:

```yaml
# Calculate cache hit rate
tracing:
  fields:
    add:
      cache.hit_rate: 'llm.cache_read_tokens > 0 ? llm.cache_read_tokens / llm.input_tokens : 0.0'
      cache.enabled: 'llm.cache_read_tokens > 0 || llm.cache_write_tokens > 0'

# Only log cache misses (for optimization debugging)
logging:
  filter: 'llm.cache_read_tokens == 0 && llm.input_tokens > 1000'
```

### Provider Latency Analysis

Compare gateway-measured vs provider-measured latency to identify network overhead:

```yaml
# Calculate gateway overhead (gateway time - provider time)
tracing:
  fields:
    add:
      latency.gateway_overhead_ms: 'duration - llm.provider_latency_ms'
      latency.overhead_percent: '((duration - llm.provider_latency_ms) / duration) * 100'

# Alert on high overhead
logging:
  filter: '(duration - llm.provider_latency_ms) > 500'  # >500ms overhead
```

### Guardrail Monitoring

Track Bedrock guardrail interventions for compliance monitoring:

```yaml
# Track guardrail interventions in metrics
metricFields:
  add:
    guardrail_status: 'llm.provider_metadata.guardrail_trace.intervened ? "blocked" : "passed"'

# Log only guardrail blocks with full details
logging:
  filter: 'llm.provider_metadata.guardrail_trace.intervened'
  fields:
    add:
      guardrail.triggered_policies: 'llm.provider_metadata.guardrail_trace.triggered_policies'
      guardrail.failed_count: 'llm.provider_metadata.guardrail_trace.failed_policies'
```

### Cost Optimization

Calculate effective token costs accounting for cache discounts:

```yaml
# Calculate effective token cost with cache discount
# Assume cache reads cost 10% of normal input tokens
tracing:
  fields:
    add:
      cost.effective_input_tokens: |
        (llm.input_tokens - llm.cache_read_tokens) + (llm.cache_read_tokens * 0.1)

      # Track cache savings percentage
      cost.cache_savings_percent: |
        llm.cache_read_tokens > 0
          ? ((llm.cache_read_tokens * 0.9) / llm.input_tokens) * 100
          : 0
```

### Conditional Expensive Fields

Only log prompts and completions for errors or high-value requests (performance optimization):

```yaml
# Only log prompts/completions for errors or large responses
tracing:
  fields:
    add:
      prompt: 'response.code >= 400 || llm.output_tokens > 5000 ? llm.prompt : null'
      completion: 'response.code >= 400 || llm.output_tokens > 5000 ? llm.completion : null'
```

### Complete Example

See `bedrock-observability.yaml` for a comprehensive Bedrock observability configuration with all features enabled.

### Available CEL Attributes

**LLM Basic Attributes** (always available when `llm` is accessed):
- `llm.streaming` - Whether response is streamed
- `llm.request_model` - Model requested
- `llm.response_model` - Model that responded
- `llm.provider` - Provider name (e.g., "aws.bedrock")
- `llm.input_tokens` - Input token count
- `llm.output_tokens` - Output token count
- `llm.total_tokens` - Total token count
- `llm.params.*` - Request parameters (temperature, top_p, etc.)

**LLM Cache Attributes** (lazy-loaded when `llm.cache` is accessed):
- `llm.cache_read_tokens` - Tokens read from cache
- `llm.cache_write_tokens` - Tokens written to cache
- `llm.cache_hit_rate` - Calculated hit rate (0.0-1.0)

**LLM Provider Metadata** (lazy-loaded when `llm.provider_metadata` is accessed):
- `llm.provider_latency_ms` - Provider-reported latency
- `llm.provider_stop_reason` - Detailed stop reason
- `llm.provider_request_id` - Provider request ID (e.g., AWS Request ID)
- `llm.provider_region` - Provider region (e.g., "us-east-1")

**Performance Note**: Lazy-loaded attributes (cache, provider_metadata, prompt, completion) only incur overhead when explicitly referenced in CEL expressions.
