// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Vincent056/celscanner"
	"github.com/Vincent056/celscanner/fetchers"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
	"github.com/oscal-compass/oscal-sdk-go/extensions"
	"gopkg.in/yaml.v3"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	pluginconfig "github.com/Vincent056/compliance-sdk-plugin/config"
)

var (
	_ policy.Provider = (*PluginServer)(nil)
)

type PluginServer struct {
	Config        *pluginconfig.Config
	restConfig    *rest.Config
	clientset     *kubernetes.Clientset
	runtimeClient runtimeclient.Client
	ruleStore     *RuleStore
}

func New() PluginServer {
	return PluginServer{
		Config: pluginconfig.NewConfig(),
	}
}

// MappingConfig represents the structure of a mapping file
type MappingConfig struct {
	Version    string                       `yaml:"version"`
	Mappings   map[string]MappingDefinition `yaml:"mappings"`
	Parameters map[string]ParameterDef      `yaml:"parameters"`
	Templates  map[string]interface{}       `yaml:"templates"`
}

// MappingDefinition defines how a RuleSet maps to CEL rules
type MappingDefinition struct {
	Type        string          `yaml:"type"` // "stored_rules" or "inline"
	RuleIDs     []string        `yaml:"rule_ids,omitempty"`
	Rules       []InlineCELRule `yaml:"rules,omitempty"`
	Description string          `yaml:"description"`
}

// InlineCELRule represents an inline CEL rule definition
type InlineCELRule struct {
	ID         string     `yaml:"id"`
	Expression string     `yaml:"expression"`
	Inputs     []InputDef `yaml:"inputs"`
}

// InputDef represents an input definition
type InputDef struct {
	Name         string            `yaml:"name"`
	Type         string            `yaml:"type"`
	Resource     string            `yaml:"resource,omitempty"`
	Path         string            `yaml:"path,omitempty"`
	URL          string            `yaml:"url,omitempty"`
	Command      string            `yaml:"command,omitempty"`
	Args         []string          `yaml:"args,omitempty"`
	Namespace    string            `yaml:"namespace,omitempty"`
	Region       string            `yaml:"region,omitempty"`
	Profile      string            `yaml:"profile,omitempty"`
	ResourceType string            `yaml:"resource_type,omitempty"`
	Filters      map[string]string `yaml:"filters,omitempty"`
}

// ParameterDef represents a parameter definition
type ParameterDef struct {
	Default     string `yaml:"default"`
	Description string `yaml:"description"`
}

// Configure implements the policy.Provider interface
func (s *PluginServer) Configure(ctx context.Context, configMap map[string]string) error {
	hclog.Default().Info("Configuring CELScanner plugin")
	if err := s.Config.LoadSettings(configMap); err != nil {
		return fmt.Errorf("failed to load settings: %w", err)
	}

	// Setup Kubernetes clients if enabled
	if s.Config.Features.KubernetesEnabled {
		if err := s.setupKubernetesClients(); err != nil {
			hclog.Default().Warn("Failed to setup Kubernetes clients", "error", err)
			// Don't fail hard, just disable Kubernetes features
			s.Config.Features.KubernetesEnabled = false
		} else {
			hclog.Default().Info("Kubernetes clients configured successfully")
		}
	}

	// Initialize rule store if workspace is configured
	if s.Config.Files.Workspace != "" {
		rulesDir := filepath.Join(s.Config.Files.Workspace, "rules")
		store, err := NewRuleStore(rulesDir)
		if err != nil {
			hclog.Default().Warn("Failed to initialize rule store", "error", err)
		} else {
			s.ruleStore = store
			hclog.Default().Info("Rule store initialized", "path", rulesDir, "rule_count", len(store.rules))
		}
	}

	return nil
}

// Generate implements the policy.Provider interface
func (s *PluginServer) Generate(ctx context.Context, oscalPolicy policy.Policy) error {
	hclog.Default().Info("Generating CEL policies from OSCAL", "rulesets", len(oscalPolicy))

	// Create policy directory
	policyDir := filepath.Join(s.Config.Files.Workspace, pluginconfig.PluginDir, pluginconfig.PolicyDir)
	if err := os.MkdirAll(policyDir, 0755); err != nil {
		return fmt.Errorf("failed to create policy directory: %w", err)
	}

	// Load mapping configuration if available
	mappingConfig, err := s.loadMappingConfig()
	if err != nil {
		hclog.Default().Warn("Failed to load mapping config, using built-in mappings", "error", err)
	}

	// Convert OSCAL rules to CEL rules
	celRules := []celscanner.CelRule{}

	for _, ruleSet := range oscalPolicy {
		hclog.Default().Debug("Processing RuleSet", "rule_id", ruleSet.Rule.ID, "checks", len(ruleSet.Checks))

		// Get CEL rules for this RuleSet
		rulesForSet, err := s.getCELRulesForRuleSet(ruleSet, mappingConfig)
		if err != nil {
			hclog.Default().Error("Failed to get CEL rules for RuleSet", "rule_id", ruleSet.Rule.ID, "error", err)
			continue
		}

		if len(rulesForSet) == 0 {
			hclog.Default().Warn("No CEL rules generated for RuleSet", "rule_id", ruleSet.Rule.ID)
			continue
		}

		celRules = append(celRules, rulesForSet...)
		hclog.Default().Info("Generated CEL rules for RuleSet", "rule_id", ruleSet.Rule.ID, "cel_rules", len(rulesForSet))
	}

	// Save CEL rules to file
	rulesFile := filepath.Join(policyDir, "cel-rules.yaml")
	rulesData, err := yaml.Marshal(celRules)
	if err != nil {
		return fmt.Errorf("failed to marshal CEL rules: %w", err)
	}

	if err := os.WriteFile(rulesFile, rulesData, 0644); err != nil {
		return fmt.Errorf("failed to write CEL rules: %w", err)
	}

	hclog.Default().Info("Generated CEL policies", "count", len(celRules), "file", rulesFile)
	return nil
}

// GetResults implements the policy.Provider interface
func (s *PluginServer) GetResults(ctx context.Context, oscalPolicy policy.Policy) (policy.PVPResult, error) {
	hclog.Default().Info("Getting CEL scan results")

	pvpResult := policy.PVPResult{}
	observations := []policy.ObservationByCheck{}

	// Load CEL rules
	rulesFile := filepath.Join(s.Config.Files.Workspace, pluginconfig.PluginDir, pluginconfig.PolicyDir, "cel-rules.yaml")
	rulesBytes, err := os.ReadFile(rulesFile)
	if err != nil {
		return pvpResult, fmt.Errorf("failed to read CEL rules: %w", err)
	}

	// We need to unmarshal into a generic structure first since CelRule is an interface
	var rulesData []map[string]interface{}
	if err := yaml.Unmarshal(rulesBytes, &rulesData); err != nil {
		return pvpResult, fmt.Errorf("failed to unmarshal CEL rules: %w", err)
	}

	// Convert to CelRule objects
	var celRules []celscanner.CelRule
	foundAWSInput := false
	// Track thresholds (e.g., MaxAgeDays) per rule to craft result reasons
	thresholdByRuleID := make(map[string]string)

	// Prefer threshold from OSCAL parameters passed into GetResults
	daysThreshold := ""
	for _, rs := range oscalPolicy {
		for _, prm := range rs.Rule.Parameters {
			if prm.Value == "" {
				continue
			}
			if prm.ID == "MaxKeyAge" || prm.ID == "MaxAgeDays" || strings.EqualFold(prm.ID, "max_key_age") || strings.EqualFold(prm.ID, "max_age_days") {
				daysThreshold = prm.Value
			}
		}
	}
	for _, ruleData := range rulesData {
		// For now, create simple rules from the data
		// In practice, you'd need a proper deserialization method
		id, _ := ruleData["id"].(string)
		expr, _ := ruleData["celexpr"].(string)

		// Set threshold for this rule: prefer OSCAL param value if present, otherwise parse from expression
		if id != "" {
			if daysThreshold != "" {
				thresholdByRuleID[id] = daysThreshold
			} else if expr != "" {
				if thr := extractDaysThreshold(expr); thr != "" {
					thresholdByRuleID[id] = thr
				}
			}
		}

		if id != "" && expr != "" {
			ruleBuilder := celscanner.NewRuleBuilder(id).
				SetExpression(expr)

			// Add inputs from the rule data
			if inputs, ok := ruleData["ruleinputs"].([]interface{}); ok && len(inputs) > 0 {
				for _, inputData := range inputs {
					if input, ok := inputData.(map[string]interface{}); ok {
						inputName, _ := input["inputname"].(string)
						inputType, _ := input["inputtype"].(string)

						if inputType == "kubernetes" {
							if inputSpec, ok := input["inputspec"].(map[string]interface{}); ok {
								group, _ := inputSpec["group"].(string)
								version, _ := inputSpec["ver"].(string)
								resourceType, _ := inputSpec["restype"].(string)
								namespace, _ := inputSpec["ns"].(string)
								resourceName, _ := inputSpec["resname"].(string)

								ruleBuilder.WithKubernetesInput(inputName, group, version, resourceType, namespace, resourceName)
							}
						} else if inputType == "aws" {
							if inputSpec, ok := input["inputspec"].(map[string]interface{}); ok {
								region, _ := inputSpec["awsregion"].(string)
								resourceType, _ := inputSpec["awsresourcetype"].(string)
								profile, _ := inputSpec["awsprofile"].(string)
								var filters map[string][]string
								if f, ok := inputSpec["awsfilters"].(map[string]interface{}); ok {
									filters = make(map[string][]string)
									for k, v := range f {
										switch tv := v.(type) {
										case []interface{}:
											for _, item := range tv {
												if s, ok := item.(string); ok && s != "" {
													filters[k] = append(filters[k], s)
												}
											}
										case string:
											if tv != "" {
												filters[k] = []string{tv}
											}
										}
									}
								}
								ruleBuilder.WithAWSInput(inputName, region, resourceType, filters, profile)
								foundAWSInput = true
							}
						}
					}
				}
			}

			if rule, err := ruleBuilder.Build(); err == nil {
				celRules = append(celRules, rule)
			} else {
				hclog.Default().Warn("Failed to build rule", "id", id, "error", err)
			}
		}
	}

	// Ensure AWS fetcher is enabled if any rule requires AWS inputs
	if foundAWSInput && !s.Config.Features.AWSEnabled {
		s.Config.Features.AWSEnabled = true
		hclog.Default().Info("AWS fetching enabled based on rule requirements")
	}

	// Create scanner based on configuration
	// For now, only support local scanner
	scanner := s.createLocalScanner()

	// Run scans
	scanConfig := celscanner.ScanConfig{
		Rules: celRules,
	}

	hclog.Default().Debug("Running scan with rules", "rule_count", len(celRules))
	results, err := scanner.Scan(ctx, scanConfig)
	if err != nil {
		return pvpResult, fmt.Errorf("failed to scan: %w", err)
	}
	hclog.Default().Debug("Scan completed", "result_count", len(results))

	// Convert CEL results to PVP observations
	for _, result := range results {
		observation := policy.ObservationByCheck{
			CheckID:     result.ID,
			Title:       result.ID,
			Description: fmt.Sprintf("CEL check result for %s", result.ID),
			Methods:     []string{"AUTOMATED"},
			Collected:   time.Now(),
		}

		// Map CEL result status to PVP result
		var pvpResultStatus policy.Result
		switch result.Status {
		case celscanner.CheckResultPass:
			pvpResultStatus = policy.ResultPass
		case celscanner.CheckResultFail:
			pvpResultStatus = policy.ResultFail
		case celscanner.CheckResultError:
			pvpResultStatus = policy.ResultError
		default:
			pvpResultStatus = policy.ResultInvalid
		}

		// Create subject for this observation
		subject := policy.Subject{
			Title:       s.Config.Parameters.TargetName,
			Type:        "inventory-item",
			ResourceID:  s.Config.Parameters.TargetID,
			Result:      pvpResultStatus,
			EvaluatedOn: time.Now(),
		}

		// If we know the threshold used for this rule, craft a human-readable reason
		if thr, ok := thresholdByRuleID[result.ID]; ok && thr != "" {
			if result.Status == celscanner.CheckResultPass {
				subject.Reason = fmt.Sprintf("api key not older than %s days", thr)
			} else if result.Status == celscanner.CheckResultFail {
				subject.Reason = fmt.Sprintf("api key older than %s days", thr)
			} else {
				// Preserve error message for non pass/fail
				subject.Reason = result.ErrorMessage
			}
		} else {
			// Fallback
			subject.Reason = result.ErrorMessage
		}

		observation.Subjects = append(observation.Subjects, subject)
		observations = append(observations, observation)
	}

	pvpResult.ObservationsByCheck = observations

	// Save results to file
	resultsDir := filepath.Join(s.Config.Files.Workspace, pluginconfig.PluginDir, pluginconfig.ResultsDir)
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return pvpResult, fmt.Errorf("failed to create results directory: %w", err)
	}

	resultsFile := filepath.Join(resultsDir, "cel-results.yaml")
	resultsData, err := yaml.Marshal(pvpResult)
	if err != nil {
		return pvpResult, fmt.Errorf("failed to marshal results: %w", err)
	}

	if err := os.WriteFile(resultsFile, resultsData, 0644); err != nil {
		hclog.Default().Error("Failed to write results file", "error", err)
	}

	hclog.Default().Info("Completed CEL scan", "observations", len(observations))

	for _, obs := range pvpResult.ObservationsByCheck {
		for _, sub := range obs.Subjects {
			ev := Evidence{
				Metadata: Metadata{
					ID:        uuid.NewString(),
					Collected: time.Now().UTC(),
					Source:    "celscanner",
					PolicyID:  obs.CheckID, // TODO: use rule id not check id
					Decision:  resultToDecision(sub.Result),
					Subject: Resource{
						Name: sub.ResourceID,
					},
				},
				Details: []Resource{
					{
						Name:      "cel-results.yaml",
						MediaType: "text/plain",
						URI:       resultsFile,
					},
				},
			}
			err = PushEvidence(ctx, "http://localhost:8083/v1/push", ev)
			if err != nil {
				hclog.Default().Error("failed to push evidence", "error", err)
			}
		}
	}

	return pvpResult, nil
}

// createLocalScanner creates a scanner using local CEL evaluation
func (s *PluginServer) createLocalScanner() *celscanner.Scanner {
	// Create composite fetcher based on configuration
	fetcherBuilder := fetchers.NewCompositeFetcherBuilder()

	if s.Config.Features.KubernetesEnabled && s.runtimeClient != nil && s.clientset != nil {
		// Add Kubernetes fetcher with live clients
		fetcherBuilder.WithKubernetes(s.runtimeClient, s.clientset)
		hclog.Default().Info("Kubernetes fetching enabled with live cluster connection")
	}

	if s.Config.Features.FilesystemEnabled {
		fetcherBuilder.WithFilesystem("")
		hclog.Default().Info("Filesystem fetching enabled")
	}

	if s.Config.Features.HTTPEnabled {
		fetcherBuilder.WithHTTP(30*time.Second, true, 3)
		hclog.Default().Info("HTTP fetching enabled")
	}

	if s.Config.Features.SystemEnabled {
		// For security, only allow checking system service status
		fetcherBuilder.WithSystem(false) // Disable general system commands
		hclog.Default().Info("System service status checking enabled (limited mode)")
		// TODO: Implement custom service status fetcher with restricted capabilities
	}

	if s.Config.Features.AWSEnabled {
		// Configure AWS fetcher
		region := s.Config.AWS.Region
		if region == "" {
			region = "us-east-2" // Default region
		}
		profile := s.Config.AWS.Profile
		timeout := time.Duration(s.Config.AWS.Timeout) * time.Second
		if timeout == 0 {
			timeout = 30 * time.Second
		}

		awsFetcher := fetchers.NewAWSFetcher(region, profile, timeout)
		fetcherBuilder.WithCustomFetcher(celscanner.InputTypeAWS, awsFetcher)
		hclog.Default().Info("AWS fetching enabled", "region", region, "profile", profile)
	}

	fetcher := fetcherBuilder.Build()
	return celscanner.NewScanner(fetcher, &celLogger{})
}

// createRPCScanner creates a scanner using the CEL RPC server
func (s *PluginServer) createRPCScanner() *celscanner.Scanner {
	// This would create a scanner that uses the RPC client
	// For now, we'll use the local scanner as a placeholder
	hclog.Default().Info("Using RPC-based scanner")
	return s.createLocalScanner()
}

// mapCheckToExpression maps OSCAL check names to CEL expressions
// This is a placeholder - in reality, this mapping would come from configuration
func (s *PluginServer) mapCheckToExpression(checkName string) string {
	// Example mappings
	mappings := map[string]string{
		"pod-security-context":  "has(resource.spec.securityContext)",
		"resource-limits":       "resource.spec.containers.all(c, has(c.resources.limits))",
		"privileged-containers": "!resource.spec.containers.exists(c, c.securityContext.privileged == true)",
		// System service checks (limited to service status only)
		"sshd-service-enabled": `service.success && contains(service.output, "enabled")`,
		"sshd-service-running": `service.success && contains(service.output, "active")`,
		"firewalld-enabled":    `service.success && contains(service.output, "enabled")`,
		"firewalld-running":    `service.success && contains(service.output, "active")`,
		"selinux-enforcing":    `selinux.success && contains(selinux.output, "Enforcing")`,
	}

	// Try to load custom mappings from file if specified
	if s.Config.Files.MappingFile != "" {
		customMappings, err := s.loadMappingsFromFile(s.Config.Files.MappingFile)
		if err != nil {
			hclog.Default().Warn("Failed to load custom mappings", "error", err)
		} else {
			// Merge custom mappings, overriding defaults
			for k, v := range customMappings {
				mappings[k] = v
			}
		}
	}

	if expr, ok := mappings[checkName]; ok {
		return expr
	}

	return ""
}

// celLogger implements the celscanner.Logger interface
type celLogger struct{}

func (l *celLogger) Debug(msg string, args ...interface{}) {
	hclog.Default().Debug(fmt.Sprintf(msg, args...))
}

func (l *celLogger) Info(msg string, args ...interface{}) {
	hclog.Default().Info(fmt.Sprintf(msg, args...))
}

func (l *celLogger) Warn(msg string, args ...interface{}) {
	hclog.Default().Warn(fmt.Sprintf(msg, args...))
}

func (l *celLogger) Error(msg string, args ...interface{}) {
	hclog.Default().Error(fmt.Sprintf(msg, args...))
}

// extractServiceName extracts the service name from a check ID
func extractServiceName(checkID string) string {
	// Extract service name from check IDs like "sshd-service-enabled"
	if strings.Contains(checkID, "sshd") {
		return "sshd"
	} else if strings.Contains(checkID, "firewalld") {
		return "firewalld"
	} else if strings.Contains(checkID, "selinux") {
		return "selinux"
	}
	// Default fallback
	parts := strings.Split(checkID, "-")
	if len(parts) > 0 {
		return parts[0]
	}
	return "unknown"
}

// setupKubernetesClients sets up Kubernetes clients for the plugin
func (s *PluginServer) setupKubernetesClients() error {
	kubeconfigPath := s.getKubeconfigPath()
	if kubeconfigPath == "" {
		return fmt.Errorf("no kubeconfig found")
	}

	hclog.Default().Debug("Using kubeconfig", "path", kubeconfigPath)

	// Create rest config
	restConfig, err := s.createKubeConfig(kubeconfigPath)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes config: %w", err)
	}
	s.restConfig = restConfig

	// Create standard Kubernetes clientset
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes clientset: %w", err)
	}
	s.clientset = clientset

	// Create controller-runtime client
	runtimeClient, err := runtimeclient.New(restConfig, runtimeclient.Options{})
	if err != nil {
		return fmt.Errorf("failed to create runtime client: %w", err)
	}
	s.runtimeClient = runtimeClient

	return nil
}

// getKubeconfigPath returns the path to kubeconfig file
func (s *PluginServer) getKubeconfigPath() string {
	// Check if explicitly set in config
	if s.Config.Parameters.Namespace != "" {
		// This might contain a kubeconfig path override
	}

	// Check KUBECONFIG environment variable first
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		return kubeconfig
	}

	// Check default location
	if home := homedir.HomeDir(); home != "" {
		kubeconfigPath := filepath.Join(home, ".kube", "config")
		if _, err := os.Stat(kubeconfigPath); err == nil {
			return kubeconfigPath
		}
	}

	return ""
}

// createKubeConfig creates a Kubernetes rest config from kubeconfig file
func (s *PluginServer) createKubeConfig(kubeconfigPath string) (*rest.Config, error) {
	// Try to use in-cluster config first (if running in a pod)
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}

	// Use kubeconfig file
	if kubeconfigPath != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}

	// Fallback to controller-runtime's config loader
	return config.GetConfig()
}

// loadMappingConfig loads the mapping configuration from file
func (s *PluginServer) loadMappingConfig() (*MappingConfig, error) {
	if s.Config.Files.MappingFile == "" {
		return nil, fmt.Errorf("no mapping file configured")
	}

	data, err := os.ReadFile(s.Config.Files.MappingFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read mapping file: %w", err)
	}

	var config MappingConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal mapping config: %w", err)
	}

	return &config, nil
}

// getCELRulesForRuleSet converts a RuleSet to CEL rules based on mapping configuration
func (s *PluginServer) getCELRulesForRuleSet(ruleSet extensions.RuleSet, mappingConfig *MappingConfig) ([]celscanner.CelRule, error) {
	var celRules []celscanner.CelRule

	// Create parameter context for substitution
	paramCtx := NewParameterContext(ruleSet)
	hclog.Default().Debug("Created parameter context for RuleSet", "rule_id", ruleSet.Rule.ID, "param_count", len(paramCtx.Parameters))
	paramCtx.LogParameters()

	// Apply plugin-config defaults to parameter context for missing values (e.g., AWS region/profile)
	s.applyConfigDefaultsToParamCtx(paramCtx)

	// First, try to map the RuleSet.Rule.ID
	if mappingConfig != nil {
		if mapping, exists := mappingConfig.Mappings[ruleSet.Rule.ID]; exists {
			rules, err := s.processMappingDefinitionWithParams(ruleSet, mapping, paramCtx)
			if err != nil {
				return nil, err
			}
			celRules = append(celRules, rules...)
		}

		// Also check for Check IDs
		for _, check := range ruleSet.Checks {
			if mapping, exists := mappingConfig.Mappings[check.ID]; exists {
				rules, err := s.processMappingDefinitionWithParams(ruleSet, mapping, paramCtx)
				if err != nil {
					hclog.Default().Warn("Failed to process mapping for check", "check_id", check.ID, "error", err)
					continue
				}
				celRules = append(celRules, rules...)
			}
		}
	}

	// If no mapping found, fall back to built-in mappings
	if len(celRules) == 0 {
		for _, check := range ruleSet.Checks {
			rule, err := s.createDefaultCELRuleWithParams(ruleSet, check, paramCtx)
			if err != nil {
				hclog.Default().Warn("Failed to create default CEL rule", "check_id", check.ID, "error", err)
				continue
			}
			if rule != nil {
				celRules = append(celRules, rule)
			}
		}
	}

	return celRules, nil
}

// processMappingDefinition processes a mapping definition to create CEL rules (deprecated, use processMappingDefinitionWithParams)
func (s *PluginServer) processMappingDefinition(ruleSet extensions.RuleSet, mapping MappingDefinition) ([]celscanner.CelRule, error) {
	// Create a parameter context for backward compatibility
	paramCtx := NewParameterContext(ruleSet)
	// Apply plugin-config defaults for missing parameters
	s.applyConfigDefaultsToParamCtx(paramCtx)
	return s.processMappingDefinitionWithParams(ruleSet, mapping, paramCtx)
}

// processMappingDefinitionWithParams processes a mapping definition to create CEL rules with parameter substitution
func (s *PluginServer) processMappingDefinitionWithParams(ruleSet extensions.RuleSet, mapping MappingDefinition, paramCtx *ParameterContext) ([]celscanner.CelRule, error) {
	var celRules []celscanner.CelRule

	switch mapping.Type {
	case "stored_rules":
		// Load rules from rule store
		if s.ruleStore == nil {
			return nil, fmt.Errorf("rule store not initialized")
		}

		for _, ruleID := range mapping.RuleIDs {
			storedRule, err := s.ruleStore.Get(ruleID)
			if err != nil {
				hclog.Default().Warn("Failed to get stored rule", "rule_id", ruleID, "error", err)
				continue
			}

			celRule, err := s.ruleStore.ConvertToCelRuleWithParams(storedRule, paramCtx)
			if err != nil {
				hclog.Default().Warn("Failed to convert stored rule", "rule_id", ruleID, "error", err)
				continue
			}

			// Add RuleSet metadata to the CEL rule
			s.addRuleSetMetadata(celRule, ruleSet)
			celRules = append(celRules, celRule)
		}

	case "inline":
		// Create rules from inline definitions
		for _, inlineRule := range mapping.Rules {
			celRule, err := s.createCELRuleFromInlineWithParams(ruleSet, inlineRule, paramCtx)
			if err != nil {
				hclog.Default().Warn("Failed to create inline CEL rule", "rule_id", inlineRule.ID, "error", err)
				continue
			}
			celRules = append(celRules, celRule)
		}

	default:
		return nil, fmt.Errorf("unknown mapping type: %s", mapping.Type)
	}

	return celRules, nil
}

// createCELRuleFromInline creates a CEL rule from an inline definition (deprecated, use createCELRuleFromInlineWithParams)
func (s *PluginServer) createCELRuleFromInline(ruleSet extensions.RuleSet, inline InlineCELRule) (celscanner.CelRule, error) {
	// Create a parameter context for backward compatibility
	paramCtx := NewParameterContext(ruleSet)
	// Apply plugin-config defaults for missing parameters
	s.applyConfigDefaultsToParamCtx(paramCtx)
	return s.createCELRuleFromInlineWithParams(ruleSet, inline, paramCtx)
}

// createCELRuleFromInlineWithParams creates a CEL rule from an inline definition with parameter substitution
func (s *PluginServer) createCELRuleFromInlineWithParams(ruleSet extensions.RuleSet, inline InlineCELRule, paramCtx *ParameterContext) (celscanner.CelRule, error) {
	// Apply parameter substitution to the inline rule
	parameterizedRule, err := paramCtx.SubstituteInlineCELRule(inline)
	if err != nil {
		return nil, fmt.Errorf("failed to apply parameter substitution: %w", err)
	}

	// Process the CEL expression for advanced parameterization
	processedExpression, err := paramCtx.ProcessParameterizedExpression(parameterizedRule.Expression)
	if err != nil {
		return nil, fmt.Errorf("failed to process parameterized expression: %w", err)
	}

	hclog.Default().Debug("Applied parameter substitution to inline rule",
		"rule_id", inline.ID,
		"original_expression", inline.Expression,
		"parameterized_expression", processedExpression)

	builder := celscanner.NewRuleBuilder(parameterizedRule.ID).
		SetExpression(processedExpression).
		WithName(parameterizedRule.ID).
		WithDescription(fmt.Sprintf("Inline rule for %s", ruleSet.Rule.ID))

	// Add inputs (parameterized versions)
	for _, input := range parameterizedRule.Inputs {
		switch input.Type {
		case "kubernetes":
			builder.WithKubernetesInput(input.Name, "", "v1", input.Resource, input.Namespace, "")
		case "file":
			builder.WithFileInput(input.Name, input.Path, ".", false, false)
		case "http":
			builder.WithHTTPInput(input.Name, input.URL, "GET", nil, nil)
		case "system":
			if input.Command != "" {
				builder.WithSystemInput(input.Name, "", input.Command, input.Args)
			}
		case "aws":
			// Convert map[string]string filters to map[string][]string
			var filters map[string][]string
			if input.Filters != nil {
				filters = make(map[string][]string)
				for k, v := range input.Filters {
					filters[k] = []string{v}
				}
			}

			// Use region from input, fallback to config, then default
			region := input.Region
			if region == "" {
				region = s.Config.AWS.Region
			}
			if region == "" {
				region = "us-east-1"
			}

			// Use profile from input, fallback to config
			profile := input.Profile
			if profile == "" {
				profile = s.Config.AWS.Profile
			}

			// Use resource type from input
			resourceType := input.ResourceType
			if resourceType == "" {
				resourceType = input.Resource // fallback to resource field
			}

			builder.WithAWSInput(input.Name, region, resourceType, filters, profile)
		}
	}

	// Add RuleSet metadata
	builder.WithExtension("oscal_rule_id", ruleSet.Rule.ID)
	builder.WithExtension("ruleset_description", ruleSet.Rule.Description)

	return builder.Build()
}

// createDefaultCELRule creates a CEL rule using built-in mappings (deprecated, use createDefaultCELRuleWithParams)
func (s *PluginServer) createDefaultCELRule(ruleSet extensions.RuleSet, check extensions.Check) (celscanner.CelRule, error) {
	// Create a parameter context for backward compatibility
	paramCtx := NewParameterContext(ruleSet)
	// Apply plugin-config defaults for missing parameters
	s.applyConfigDefaultsToParamCtx(paramCtx)
	return s.createDefaultCELRuleWithParams(ruleSet, check, paramCtx)
}

// createDefaultCELRuleWithParams creates a CEL rule using built-in mappings with parameter substitution
func (s *PluginServer) createDefaultCELRuleWithParams(ruleSet extensions.RuleSet, check extensions.Check, paramCtx *ParameterContext) (celscanner.CelRule, error) {
	expression := s.mapCheckToExpression(check.ID)
	if expression == "" {
		return nil, nil // No mapping found
	}

	// Apply parameter substitution to the expression
	parameterizedExpression, err := paramCtx.ProcessParameterizedExpression(expression)
	if err != nil {
		hclog.Default().Warn("Failed to apply parameter substitution to default expression", "check_id", check.ID, "error", err)
		// Fall back to original expression if substitution fails
		parameterizedExpression = expression
	}

	hclog.Default().Debug("Applied parameter substitution to default rule",
		"check_id", check.ID,
		"original_expression", expression,
		"parameterized_expression", parameterizedExpression)

	builder := celscanner.NewRuleBuilder(check.ID).
		SetExpression(parameterizedExpression).
		WithName(check.ID).
		WithDescription(check.Description)

	// Add metadata
	builder.WithExtension("oscal_rule_id", ruleSet.Rule.ID)
	builder.WithExtension("check_id", check.ID)

	// Add default inputs based on check type (with parameter context for potential future enhancement)
	if err := s.addDefaultInputsWithParams(builder, check.ID, paramCtx); err != nil {
		return nil, err
	}

	return builder.Build()
}

// addDefaultInputs adds default inputs based on check ID patterns (deprecated, use addDefaultInputsWithParams)
func (s *PluginServer) addDefaultInputs(builder *celscanner.RuleBuilder, checkID string) error {
	// Create a dummy parameter context for backward compatibility
	return s.addDefaultInputsWithParams(builder, checkID, &ParameterContext{Parameters: make(map[string]string)})
}

// addDefaultInputsWithParams adds default inputs based on check ID patterns with parameter substitution
func (s *PluginServer) addDefaultInputsWithParams(builder *celscanner.RuleBuilder, checkID string, paramCtx *ParameterContext) error {
	if checkID == "pod-security-context" || checkID == "resource-limits" || checkID == "privileged-containers" {
		// Kubernetes inputs - could be parameterized with namespace
		namespace := paramCtx.GetParameterValue("namespace", "")
		builder.WithKubernetesInput("resource", "", "v1", "pods", namespace, "")
	} else if strings.Contains(checkID, "service") || strings.Contains(checkID, "sshd") ||
		strings.Contains(checkID, "firewalld") || strings.Contains(checkID, "selinux") {
		// System service checks - use system input for service status
		serviceName := extractServiceName(checkID)
		// Allow service name to be parameterized
		if parameterizedServiceName := paramCtx.GetParameterValue("service-name", ""); parameterizedServiceName != "" {
			serviceName = parameterizedServiceName
		}

		if strings.Contains(checkID, "enabled") {
			builder.WithSystemInput("service", "", "systemctl", []string{"is-enabled", serviceName})
		} else if strings.Contains(checkID, "running") || strings.Contains(checkID, "active") {
			builder.WithSystemInput("service", "", "systemctl", []string{"is-active", serviceName})
		} else if strings.Contains(checkID, "selinux") {
			builder.WithSystemInput("selinux", "", "getenforce", []string{})
		} else {
			builder.WithSystemInput("service", serviceName, "", []string{})
		}
	} else {
		// Default to file input for unknown checks - could be parameterized with path
		path := paramCtx.GetParameterValue("file-path", "*")
		workDir := paramCtx.GetParameterValue("work-dir", ".")
		builder.WithFileInput("resource", path, workDir, false, false)
	}
	return nil
}

// addRuleSetMetadata adds RuleSet metadata to a CEL rule
func (s *PluginServer) addRuleSetMetadata(rule celscanner.CelRule, ruleSet extensions.RuleSet) {
	// This is a bit tricky since CelRule is an interface
	// We might need to handle this differently based on the implementation
	// For now, we'll log this requirement
	hclog.Default().Debug("RuleSet metadata should be added to CEL rule",
		"cel_rule_id", rule.Identifier(),
		"oscal_rule_id", ruleSet.Rule.ID)
}

// loadMappingsFromFile loads CEL expression mappings from a YAML or JSON file
func (s *PluginServer) loadMappingsFromFile(mappingFile string) (map[string]string, error) {
	data, err := os.ReadFile(mappingFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read mapping file: %w", err)
	}

	// Try to parse as YAML first (which also handles JSON)
	var mappingData struct {
		Mappings map[string]struct {
			Expression  string                   `yaml:"expression" json:"expression"`
			Description string                   `yaml:"description" json:"description"`
			Inputs      []map[string]interface{} `yaml:"inputs" json:"inputs"`
		} `yaml:"mappings" json:"mappings"`
	}

	if err := yaml.Unmarshal(data, &mappingData); err != nil {
		return nil, fmt.Errorf("failed to parse mapping file: %w", err)
	}

	result := make(map[string]string)
	for checkName, mapping := range mappingData.Mappings {
		result[checkName] = mapping.Expression
	}

	return result, nil
}

// applyConfigDefaultsToParamCtx injects defaults from plugin configuration into the parameter context
// without overriding any values already provided by the assessment plan.
func (s *PluginServer) applyConfigDefaultsToParamCtx(paramCtx *ParameterContext) {
	if paramCtx == nil {
		return
	}

	setIfMissing := func(keys []string, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		// Check if any of the keys already has a non-empty value
		for _, k := range keys {
			if v, ok := paramCtx.Parameters[k]; ok && strings.TrimSpace(v) != "" {
				return
			}
		}
		// None set; set all variants for convenience in templates
		for _, k := range keys {
			paramCtx.Parameters[k] = value
		}
	}

	// AWS Region defaults (support common variants used in templates)
	setIfMissing([]string{"AwsRegion", "awsRegion", "aws_region"}, s.Config.AWS.Region)
	// AWS Profile defaults
	setIfMissing([]string{"AwsProfile", "awsProfile", "aws_profile"}, s.Config.AWS.Profile)
}

// Helper to extract a numeric days threshold from a CEL expression string
func extractDaysThreshold(expr string) string {
	// Try patterns like: daysOld > 365 or age_days > 365
	patterns := []string{
		`daysOld\s*>\s*(\d+)`,
		`age_days\s*>\s*(\d+)`,
	}
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		m := re.FindStringSubmatch(expr)
		if len(m) == 2 {
			return m[1]
		}
	}
	return ""
}

// resultToDecision maps policy.Result to a ProofWatch-friendly decision string
func resultToDecision(r policy.Result) string {
	switch r {
	case policy.ResultPass:
		return "pass"
	case policy.ResultFail:
		return "fail"
	case policy.ResultError:
		return "error"
	default:
		// Unknown/invalid -> fall back to needs review semantics
		return "warning"
	}
}
