package controller

import (
	agwplugins "github.com/agentgateway/agentgateway/controller/pkg/agentgateway/plugins"
	agentgatewaybackend "github.com/agentgateway/agentgateway/controller/pkg/syncer/backend"
)

func Plugins(agw *agwplugins.AgwCollections) []agwplugins.AgwPlugin {
	return []agwplugins.AgwPlugin{
		agwplugins.NewAgentPlugin(agw),
		agwplugins.NewInferencePlugin(agw),
		agwplugins.NewA2APlugin(agw),
		agwplugins.NewBackendTLSPlugin(agw),
		agentgatewaybackend.NewBackendPlugin(agw),
	}
}
