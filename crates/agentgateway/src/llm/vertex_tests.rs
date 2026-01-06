    use super::Provider;
    use crate::llm::types::messages;
    use agent_core::strng;
    use bytes::Bytes;

    #[tokio::test]
    async fn test_prepare_anthropic_request_body() {
        let provider = Provider {
            model: Some(strng::literal!("claude-3-5-sonnet@20240620")),
            region: Some(strng::literal!("us-central1")),
            project_id: strng::literal!("test-project"),
        };

        let messages_req = messages::Request {
            model: Some("claude-3-5-sonnet@20240620".to_string()),
            messages: vec![messages::RequestMessage {
                role: "user".to_string(),
                content: Some(messages::RequestContent::Text("Hello".to_string())),
                rest: Default::default(),
            }],
            max_tokens: Some(1024),
            stream: Some(true),
            temperature: None,
            top_p: None,
            rest: Default::default(),
        };

        let body = serde_json::to_vec(&messages_req).unwrap();
        let prepared_body = provider.prepare_anthropic_request_body(body).unwrap();
        let prepared_json: serde_json::Value = serde_json::from_slice(&prepared_body).unwrap();

        assert_eq!(prepared_json["anthropic_version"], "vertex-2023-10-16");
        assert!(prepared_json.get("model").is_none());
        assert_eq!(prepared_json["messages"][0]["role"], "user");
        assert_eq!(prepared_json["messages"][0]["content"], "Hello");
        assert_eq!(prepared_json["max_tokens"], 1024);
        assert_eq!(prepared_json["stream"], true);
    }

    #[test]
    fn test_translate_token_count_response() {
        let vertex_response = r#"{ "totalTokens": 123 }"#;
        let bytes = Bytes::from(vertex_response);
        let (translated_bytes, count) = super::translate_token_count_response(bytes).unwrap();
        
        assert_eq!(count, 123);
        let anthropic_response: serde_json::Value = serde_json::from_slice(&translated_bytes).unwrap();
        assert_eq!(anthropic_response["input_tokens"], 123);
    }
