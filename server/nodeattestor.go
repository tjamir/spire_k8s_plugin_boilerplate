package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/common/plugin/k8s/apiserver"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "k8s_psat_ext"
)

var (
	// This compile time assertion ensures the plugin conforms properly to the
	// pluginsdk.NeedsLogger interface.
	// TODO: Remove if the plugin does not need the logger.
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)

	// This compile time assertion ensures the plugin conforms properly to the
	// pluginsdk.NeedsHostServices interface.
	// TODO: Remove if the plugin does not need host services.
	_ pluginsdk.NeedsHostServices = (*Plugin)(nil)
)

// Config defines the configuration for the plugin.
// TODO: Add relevant configurables or remove if no configuration is required.
type Config struct {
	trustDomain string   `hcl:"trust_domain"`
	clusters    []string `hcl:"cluster"`
	tokenPath   string   `hcl:"token_path"`
}

// Plugin implements the NodeAttestor plugin
type Plugin struct {
	// UnimplementedNodeAttestorServer is embedded to satisfy gRPC
	nodeattestorv1.UnimplementedNodeAttestorServer

	// UnimplementedConfigServer is embedded to satisfy gRPC
	// TODO: Remove if this plugin does not require configuration
	configv1.UnimplementedConfigServer

	// Configuration should be set atomically
	// TODO: Remove if this plugin does not require configuration
	configMtx sync.RWMutex
	config    *Config

	// The logger received from the framework via the SetLogger method
	// TODO: Remove if this plugin does not need the logger.
	logger hclog.Logger
}

// SetLogger is called by the framework when the plugin is loaded and provides
// the plugin with a logger wired up to SPIRE's logging facilities.
// TODO: Remove if the plugin does not need the logger.
func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

// BrokerHostServices is called by the framework when the plugin is loaded to
// give the plugin a chance to obtain clients to SPIRE host services.
// TODO: Remove if the plugin does not need host services.
func (p *Plugin) BrokerHostServices(broker pluginsdk.ServiceBroker) error {
	// TODO: Use the broker to obtain host service clients
	return nil
}

// Attest implements the NodeAttestor Attest RPC
func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	config, err := p.getConfig()
	if err != nil {
		return err
	}

	payload := req.GetPayload()
	if payload == nil {
		return status.Error(codes.InvalidArgument, "missing attestation payload")
	}

	// TODO: Implement the RPC behavior. The following line silences compiler
	// warnings and can be removed once the configuration is referenced by the
	// implementation.
	config = config

	attestationData := new(k8s.PSATAttestationData)
	if err := json.Unmarshal(payload, attestationData); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal data payload: %v", err)
	}

	if attestationData.Cluster == "" {
		return status.Error(codes.InvalidArgument, "missing cluster in attestation data")
	}

	if attestationData.Token == "" {
		return status.Error(codes.InvalidArgument, "missing token in attestation data")
	}

	cluster := config.clusters[attestationData.Cluster]
	if cluster == nil {
		return status.Errorf(codes.InvalidArgument, "not configured for cluster %q", attestationData.Cluster)
	}

	tokenStatus, err := cluster.client.ValidateToken(stream.Context(), attestationData.Token, cluster.audience)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to validate token with TokenReview API: %v", err)
	}

	if !tokenStatus.Authenticated {
		return status.Error(codes.PermissionDenied, "token not authenticated according to TokenReview API")
	}

	namespace, serviceAccountName, err := k8s.GetNamesFromTokenStatus(tokenStatus)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to parse username from token review status: %v", err)
	}
	fullServiceAccountName := fmt.Sprintf("%v:%v", namespace, serviceAccountName)

	if !cluster.serviceAccounts[fullServiceAccountName] {
		return status.Errorf(codes.PermissionDenied, "%q is not an allowed service account", fullServiceAccountName)
	}

	podName, err := k8s.GetPodNameFromTokenStatus(tokenStatus)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to get pod name from token review status: %v", err)
	}

	podUID, err := k8s.GetPodUIDFromTokenStatus(tokenStatus)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to get pod UID from token review status: %v", err)
	}

	pod, err := cluster.client.GetPod(stream.Context(), namespace, podName)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to get pod from k8s API server: %v", err)
	}

	node, err := cluster.client.GetNode(stream.Context(), pod.Spec.NodeName)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to get node from k8s API server: %v", err)
	}

	nodeUID := string(node.UID)
	if nodeUID == "" {
		return status.Errorf(codes.Internal, "node UID is empty")
	}

	selectorValues := []string{
		k8s.MakeSelectorValue("cluster", attestationData.Cluster),
		k8s.MakeSelectorValue("agent_ns", namespace),
		k8s.MakeSelectorValue("agent_sa", serviceAccountName),
		k8s.MakeSelectorValue("agent_pod_name", podName),
		k8s.MakeSelectorValue("agent_pod_uid", podUID),
		k8s.MakeSelectorValue("agent_node_ip", pod.Status.HostIP),
		k8s.MakeSelectorValue("agent_node_name", pod.Spec.NodeName),
		k8s.MakeSelectorValue("agent_node_uid", nodeUID),
	}

	for key, value := range node.Labels {
		if cluster.allowedNodeLabelKeys[key] {
			selectorValues = append(selectorValues, k8s.MakeSelectorValue("agent_node_label", key, value))
		}
	}

	for key, value := range pod.Labels {
		if cluster.allowedPodLabelKeys[key] {
			selectorValues = append(selectorValues, k8s.MakeSelectorValue("agent_pod_label", key, value))
		}
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				CanReattest:    true,
				SpiffeId:       k8s.AgentID(pluginName, config.trustDomain, attestationData.Cluster, nodeUID),
				SelectorValues: selectorValues,
			},
		},
	})
}

// Configure configures the plugin. This is invoked by SPIRE when the plugin is
// first loaded. In the future, tt may be invoked to reconfigure the plugin.
// As such, it should replace the previous configuration atomically.
// TODO: Remove if no configuration is required
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	// TODO: Validate configuration before setting/replacing existing
	// configuration
	if req.CoreConfiguration == nil {
		return nil, status.Error(codes.InvalidArgument, "core configuration is required")
	}
	if req.CoreConfiguration.TrustDomain == "" {
		return nil, status.Error(codes.InvalidArgument, "core configuration missing trust domain")
	}

	if len(config.clusters) == 0 {
		return nil, status.Error(codes.InvalidArgument, "configuration must have at least one cluster")
	}

	config := &attestorConfig{
		trustDomain: req.CoreConfiguration.TrustDomain,
		clusters:    make(map[string]*clusterConfig),
	}

	for name, cluster := range config.clusters {
		if len(cluster.ServiceAccountAllowList) == 0 {
			return nil, status.Errorf(codes.InvalidArgument, "cluster %q configuration must have at least one service account allowed", name)
		}

		serviceAccounts := make(map[string]bool)
		for _, serviceAccount := range cluster.ServiceAccountAllowList {
			serviceAccounts[serviceAccount] = true
		}

		var audience []string
		if cluster.Audience == nil {
			audience = defaultAudience
		} else {
			audience = *cluster.Audience
		}

		allowedNodeLabelKeys := make(map[string]bool)
		for _, label := range cluster.AllowedNodeLabelKeys {
			allowedNodeLabelKeys[label] = true
		}

		allowedPodLabelKeys := make(map[string]bool)
		for _, label := range cluster.AllowedPodLabelKeys {
			allowedPodLabelKeys[label] = true
		}

		config.clusters[name] = &clusterConfig{
			serviceAccounts:      serviceAccounts,
			audience:             audience,
			client:               apiserver.New(cluster.KubeConfigFile),
			allowedNodeLabelKeys: allowedNodeLabelKeys,
			allowedPodLabelKeys:  allowedPodLabelKeys,
		}
	}

	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

// setConfig replaces the configuration atomically under a write lock.
// TODO: Remove if no configuration is required
func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	p.config = config
	p.configMtx.Unlock()
}

// getConfig gets the configuration under a read lock.
// TODO: Remove if no configuration is required
func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func main() {
	plugin := new(Plugin)
	// Serve the plugin. This function call will not return. If there is a
	// failure to serve, the process will exit with a non-zero exit code.
	pluginmain.Serve(
		nodeattestorv1.NodeAttestorPluginServer(plugin),
		// TODO: Remove if no configuration is required
		configv1.ConfigServiceServer(plugin),
	)
}
