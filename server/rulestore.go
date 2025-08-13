package server

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Vincent056/celscanner"
	"github.com/hashicorp/go-hclog"
	"gopkg.in/yaml.v3"
)

// RuleStore manages YAML-based storage of CEL rules
type RuleStore struct {
	mu       sync.RWMutex
	basePath string
	rules    map[string]*StoredRule
}

// StoredRule represents a rule with metadata stored in YAML
type StoredRule struct {
	ID          string                 `yaml:"id"`
	Name        string                 `yaml:"name"`
	Description string                 `yaml:"description"`
	Expression  string                 `yaml:"expression"`
	Inputs      []RuleInputConfig      `yaml:"inputs"`
	Tags        []string               `yaml:"tags"`
	Category    string                 `yaml:"category"`
	Severity    string                 `yaml:"severity"`
	Extensions  map[string]interface{} `yaml:"extensions,omitempty"`
	CreatedAt   time.Time              `yaml:"created_at"`
	UpdatedAt   time.Time              `yaml:"updated_at"`
	CreatedBy   string                 `yaml:"created_by"`
	CheckID     string                 `yaml:"check_id,omitempty"`
}

// RuleInputConfig represents input configuration in YAML
type RuleInputConfig struct {
	Name         string            `yaml:"name"`
	Type         string            `yaml:"type"`
	Resource     string            `yaml:"resource,omitempty"`
	Path         string            `yaml:"path,omitempty"`
	URL          string            `yaml:"url,omitempty"`
	Command      string            `yaml:"command,omitempty"`
	Args         []string          `yaml:"args,omitempty"`
	Service      string            `yaml:"service,omitempty"`
	Namespace    string            `yaml:"namespace,omitempty"`
	Region       string            `yaml:"region,omitempty"`
	Profile      string            `yaml:"profile,omitempty"`
	ResourceType string            `yaml:"resource_type,omitempty"`
	Filters      map[string]string `yaml:"filters,omitempty"`
	Metadata     map[string]string `yaml:"metadata,omitempty"`
}

// NewRuleStore creates a new YAML-based rule store
func NewRuleStore(basePath string) (*RuleStore, error) {
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create rule store directory: %w", err)
	}

	store := &RuleStore{
		basePath: basePath,
		rules:    make(map[string]*StoredRule),
	}

	// Load existing rules
	if err := store.loadRules(); err != nil {
		return nil, fmt.Errorf("failed to load existing rules: %w", err)
	}

	return store, nil
}

// loadRules loads all YAML rule files from the base directory
func (s *RuleStore) loadRules() error {
	files, err := ioutil.ReadDir(s.basePath)
	if err != nil {
		return err
	}

	hclog.Default().Info("Loading rules from YAML store", "path", s.basePath, "file_count", len(files))

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".yaml") || strings.HasSuffix(file.Name(), ".yml") {
			filePath := filepath.Join(s.basePath, file.Name())
			data, err := ioutil.ReadFile(filePath)
			if err != nil {
				hclog.Default().Error("Failed to read rule file", "file", filePath, "error", err)
				continue
			}

			var rule StoredRule
			if err := yaml.Unmarshal(data, &rule); err != nil {
				hclog.Default().Error("Failed to unmarshal rule", "file", filePath, "error", err)
				continue
			}

			s.rules[rule.ID] = &rule
			hclog.Default().Debug("Loaded rule", "id", rule.ID, "name", rule.Name)
		}
	}

	hclog.Default().Info("Loaded rules", "total", len(s.rules))
	return nil
}

// Save stores a rule to YAML file
func (s *RuleStore) Save(rule *StoredRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if rule.ID == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}

	rule.UpdatedAt = time.Now()
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = rule.UpdatedAt
	}

	// Marshal to YAML with nice formatting
	data, err := yaml.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to marshal rule: %w", err)
	}

	filename := filepath.Join(s.basePath, rule.ID+".yaml")
	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write rule file: %w", err)
	}

	s.rules[rule.ID] = rule
	hclog.Default().Info("Saved rule", "id", rule.ID, "file", filename)

	return nil
}

// Get retrieves a rule by ID
func (s *RuleStore) Get(id string) (*StoredRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rule, exists := s.rules[id]
	if !exists {
		return nil, fmt.Errorf("rule not found: %s", id)
	}

	return rule, nil
}

// List returns all rules with optional filtering
func (s *RuleStore) List(filter map[string]string) []*StoredRule {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*StoredRule

	for _, rule := range s.rules {
		if s.matchesFilter(rule, filter) {
			results = append(results, rule)
		}
	}

	return results
}

// matchesFilter checks if a rule matches the given filter criteria
func (s *RuleStore) matchesFilter(rule *StoredRule, filter map[string]string) bool {
	if len(filter) == 0 {
		return true
	}

	for key, value := range filter {
		switch key {
		case "category":
			if rule.Category != value {
				return false
			}
		case "severity":
			if rule.Severity != value {
				return false
			}
		case "check_id":
			if rule.CheckID != value {
				return false
			}
		case "tag":
			found := false
			for _, tag := range rule.Tags {
				if tag == value {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	return true
}

// Delete removes a rule from storage
func (s *RuleStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.rules[id]; !exists {
		return fmt.Errorf("rule not found: %s", id)
	}

	filename := filepath.Join(s.basePath, id+".yaml")
	if err := os.Remove(filename); err != nil {
		return fmt.Errorf("failed to delete rule file: %w", err)
	}

	delete(s.rules, id)
	hclog.Default().Info("Deleted rule", "id", id)

	return nil
}

// ConvertToCelRule converts a StoredRule to celscanner.CelRule (deprecated, use ConvertToCelRuleWithParams)
func (s *RuleStore) ConvertToCelRule(stored *StoredRule) (celscanner.CelRule, error) {
	// Create a dummy parameter context for backward compatibility
	paramCtx := &ParameterContext{Parameters: make(map[string]string)}
	return s.ConvertToCelRuleWithParams(stored, paramCtx)
}

// ConvertToCelRuleWithParams converts a StoredRule to celscanner.CelRule with parameter substitution
func (s *RuleStore) ConvertToCelRuleWithParams(stored *StoredRule, paramCtx *ParameterContext) (celscanner.CelRule, error) {
	// Apply parameter substitution to the expression
	parameterizedExpression, err := paramCtx.ProcessParameterizedExpression(stored.Expression)
	if err != nil {
		hclog.Default().Warn("Failed to apply parameter substitution to stored rule expression", "rule_id", stored.ID, "error", err)
		// Fall back to original expression if substitution fails
		parameterizedExpression = stored.Expression
	}

	// Apply parameter substitution to name and description
	parameterizedName, err := paramCtx.SubstituteString(stored.Name)
	if err != nil {
		hclog.Default().Warn("Failed to substitute rule name", "rule_id", stored.ID, "error", err)
		parameterizedName = stored.Name
	}

	parameterizedDescription, err := paramCtx.SubstituteString(stored.Description)
	if err != nil {
		hclog.Default().Warn("Failed to substitute rule description", "rule_id", stored.ID, "error", err)
		parameterizedDescription = stored.Description
	}

	hclog.Default().Debug("Applied parameter substitution to stored rule", 
		"rule_id", stored.ID,
		"original_expression", stored.Expression,
		"parameterized_expression", parameterizedExpression)

	builder := celscanner.NewRuleBuilder(stored.ID).
		WithName(parameterizedName).
		WithDescription(parameterizedDescription).
		SetExpression(parameterizedExpression)

	// Add tags as extension
	if len(stored.Tags) > 0 {
		builder.WithExtension("tags", stored.Tags)
	}

	// Add category and severity as extensions
	if stored.Category != "" {
		builder.WithExtension("category", stored.Category)
	}
	if stored.Severity != "" {
		builder.WithExtension("severity", stored.Severity)
	}

	// Add other extensions
	for key, value := range stored.Extensions {
		builder.WithExtension(key, value)
	}

	// Add inputs based on type (with parameter substitution)
	for _, input := range stored.Inputs {
		// Convert RuleInputConfig to InputDef for parameter substitution
		inputDef := InputDef{
			Name:         input.Name,
			Type:         input.Type,
			Resource:     input.Resource,
			Path:         input.Path,
			URL:          input.URL,
			Command:      input.Command,
			Args:         input.Args,
			Namespace:    input.Namespace,
			Region:       input.Region,
			Profile:      input.Profile,
			ResourceType: input.ResourceType,
			Filters:      input.Filters,
		}
		
		// Apply parameter substitution
		parameterizedInput, err := paramCtx.SubstituteInputDef(inputDef)
		if err != nil {
			hclog.Default().Warn("Failed to apply parameter substitution to input", "rule_id", stored.ID, "input_name", input.Name, "error", err)
			// Use original input if substitution fails
			parameterizedInput = inputDef
		}
		
		switch strings.ToLower(parameterizedInput.Type) {
		case "kubernetes":
			builder.WithKubernetesInput(parameterizedInput.Name, "", "v1", parameterizedInput.Resource, parameterizedInput.Namespace, "")
		case "file":
			workDir := parameterizedInput.Path
			if workDir == "" {
				workDir = "."
			}
			builder.WithFileInput(parameterizedInput.Name, parameterizedInput.Path, workDir, false, false)
		case "http":
			builder.WithHTTPInput(parameterizedInput.Name, parameterizedInput.URL, "GET", nil, nil)
		case "system":
			if input.Service != "" {
				// Service-based check (use original service field since it's not in InputDef)
				serviceName, _ := paramCtx.SubstituteString(input.Service)
				builder.WithSystemInput(parameterizedInput.Name, serviceName, "", []string{})
			} else if parameterizedInput.Command != "" {
				// Command-based check
				builder.WithSystemInput(parameterizedInput.Name, "", parameterizedInput.Command, parameterizedInput.Args)
			}
				case "aws":
			// Convert map[string]string filters to map[string][]string
			var filters map[string][]string
			if parameterizedInput.Filters != nil {
				filters = make(map[string][]string)
				for k, v := range parameterizedInput.Filters {
					filters[k] = []string{v}
				}
			}
			
			// Use resource type from input
			resourceType := parameterizedInput.ResourceType
			if resourceType == "" {
				resourceType = parameterizedInput.Resource // fallback to resource field
			}
			
			// Fallbacks for region/profile from plugin configuration if missing
			region := parameterizedInput.Region
			if strings.TrimSpace(region) == "" {
				region = s.getDefaultAWSRegion()
			}
			profile := parameterizedInput.Profile
			if strings.TrimSpace(profile) == "" {
				profile = s.getDefaultAWSProfile()
			}
			
			builder.WithAWSInput(parameterizedInput.Name, region, resourceType, filters, profile)
		}
	}

	return builder.Build()
}

// ExportRules exports rules to a single YAML file
func (s *RuleStore) ExportRules(ruleIDs []string, outputPath string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var rulesToExport []*StoredRule

	if len(ruleIDs) > 0 {
		// Export specific rules
		for _, id := range ruleIDs {
			if rule, exists := s.rules[id]; exists {
				rulesToExport = append(rulesToExport, rule)
			}
		}
	} else {
		// Export all rules
		for _, rule := range s.rules {
			rulesToExport = append(rulesToExport, rule)
		}
	}

	// Create export structure
	export := struct {
		Version  string        `yaml:"version"`
		Rules    []*StoredRule `yaml:"rules"`
		Exported time.Time     `yaml:"exported"`
	}{
		Version:  "1.0",
		Rules:    rulesToExport,
		Exported: time.Now(),
	}

	data, err := yaml.Marshal(export)
	if err != nil {
		return fmt.Errorf("failed to marshal rules for export: %w", err)
	}

	if err := ioutil.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write export file: %w", err)
	}

	hclog.Default().Info("Exported rules", "count", len(rulesToExport), "file", outputPath)
	return nil
}

// ImportRules imports rules from a YAML file
func (s *RuleStore) ImportRules(inputPath string, overwrite bool) error {
	data, err := ioutil.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read import file: %w", err)
	}

	// Try to unmarshal as export format first
	var export struct {
		Version string        `yaml:"version"`
		Rules   []*StoredRule `yaml:"rules"`
	}

	if err := yaml.Unmarshal(data, &export); err == nil && len(export.Rules) > 0 {
		// Import from export format
		for _, rule := range export.Rules {
			if !overwrite {
				if _, exists := s.rules[rule.ID]; exists {
					hclog.Default().Warn("Skipping existing rule", "id", rule.ID)
					continue
				}
			}
			if err := s.Save(rule); err != nil {
				hclog.Default().Error("Failed to import rule", "id", rule.ID, "error", err)
			}
		}
		return nil
	}

	// Try to unmarshal as array of rules
	var rules []*StoredRule
	if err := yaml.Unmarshal(data, &rules); err == nil {
		for _, rule := range rules {
			if !overwrite {
				if _, exists := s.rules[rule.ID]; exists {
					hclog.Default().Warn("Skipping existing rule", "id", rule.ID)
					continue
				}
			}
			if err := s.Save(rule); err != nil {
				hclog.Default().Error("Failed to import rule", "id", rule.ID, "error", err)
			}
		}
		return nil
	}

	// Try single rule
	var rule StoredRule
	if err := yaml.Unmarshal(data, &rule); err == nil {
		if !overwrite {
			if _, exists := s.rules[rule.ID]; exists {
				return fmt.Errorf("rule already exists: %s", rule.ID)
			}
		}
		return s.Save(&rule)
	}

	return fmt.Errorf("unable to parse import file format")
}

func (s *RuleStore) getDefaultAWSRegion() string {
	if v := os.Getenv("AWS_REGION"); strings.TrimSpace(v) != "" {
		return v
	}
	return "us-east-1"
}

func (s *RuleStore) getDefaultAWSProfile() string {
	if v := os.Getenv("AWS_PROFILE"); strings.TrimSpace(v) != "" {
		return v
	}
	return "default"
}
