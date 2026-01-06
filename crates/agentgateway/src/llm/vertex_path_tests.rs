    use super::Provider;
    use crate::llm::RouteType;
    use agent_core::strng;

    #[test]
    fn test_get_path_for_model_explicit_routes() {
        let provider = Provider {
            model: None,
            region: Some(strng::literal!("us-central1")),
            project_id: strng::literal!("test-project"),
        };

        // Test Messages route with an explicitly Anthropic prefixed model
        let path = provider.get_path_for_model(RouteType::Messages, Some("anthropic/my-custom-model"), false);
        assert_eq!(
            path,
            "/v1/projects/test-project/locations/us-central1/publishers/anthropic/models/my-custom-model:rawPredict"
        );

        // Test Messages route with a non-Anthropic model (e.g. gemini) -> Should use Generic Endpoint
        let path = provider.get_path_for_model(RouteType::Messages, Some("gemini-pro"), false);
        assert_eq!(
            path,
            "/v1beta1/projects/test-project/locations/us-central1/endpoints/openapi/chat/completions"
        );

        // Test TokenCount route -> Should ALWAYS use Anthropic Endpoint (as it is specific feature)
        // (Even if model doesn't look like Anthropic, if user asks for TokenCount we assume Anthropic endpoint structure for now, 
        //  as Generic endpoint doesn't support this route type in the same way via Gateway)
        let path = provider.get_path_for_model(RouteType::AnthropicTokenCount, Some("my-custom-model"), false);
        assert_eq!(
            path,
            "/v1/projects/test-project/locations/us-central1/publishers/anthropic/models/my-custom-model:countTokens"
        );
    }

    #[test]
    fn test_get_path_for_model_completions_route() {
        let provider = Provider {
            model: None,
            region: Some(strng::literal!("us-central1")),
            project_id: strng::literal!("test-project"),
        };

        // Test Completions route with non-standard model (should fallback to generic Vertex URL)
        let path = provider.get_path_for_model(RouteType::Completions, Some("my-custom-model"), false);
        assert_eq!(
            path,
            "/v1beta1/projects/test-project/locations/us-central1/endpoints/openapi/chat/completions"
        );

        // Test Completions route with Claude model (should detect and use Anthropic URL)
        let path = provider.get_path_for_model(RouteType::Completions, Some("claude-3-5-sonnet"), false);
        assert_eq!(
            path,
            "/v1/projects/test-project/locations/us-central1/publishers/anthropic/models/claude-3-5-sonnet:rawPredict"
        );
    }
