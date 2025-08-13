// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"bytes"
	"github.com/oscal-compass/oscal-sdk-go/extensions"
	"github.com/hashicorp/go-hclog"
)

// ParameterContext holds parameter values for substitution
type ParameterContext struct {
	Parameters map[string]string
	RuleSet    extensions.RuleSet
}

// NewParameterContext creates a new parameter context from a RuleSet
func NewParameterContext(ruleSet extensions.RuleSet) *ParameterContext {
	params := make(map[string]string)
	
	// Extract parameters from the RuleSet
	for _, param := range ruleSet.Rule.Parameters {
		params[param.ID] = param.Value
		// Also add camelCase and snake_case variants for flexibility
		params[toCamelCase(param.ID)] = param.Value
		params[toSnakeCase(param.ID)] = param.Value
	}
	
	return &ParameterContext{
		Parameters: params,
		RuleSet:    ruleSet,
	}
}

// SubstituteString performs parameter substitution in a string using Go template syntax
func (pc *ParameterContext) SubstituteString(input string) (string, error) {
	if !strings.Contains(input, "{{") {
		return input, nil // No substitution needed
	}
	
	tmpl, err := template.New("param").Parse(input)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}
	
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, pc.Parameters)
	if err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}
	
	return buf.String(), nil
}

// SubstituteStringMap performs parameter substitution on all values in a string map
func (pc *ParameterContext) SubstituteStringMap(input map[string]string) (map[string]string, error) {
	if input == nil {
		return nil, nil
	}
	
	result := make(map[string]string)
	for k, v := range input {
		substituted, err := pc.SubstituteString(v)
		if err != nil {
			return nil, fmt.Errorf("failed to substitute value for key %s: %w", k, err)
		}
		result[k] = substituted
	}
	
	return result, nil
}

// SubstituteStringSlice performs parameter substitution on all strings in a slice
func (pc *ParameterContext) SubstituteStringSlice(input []string) ([]string, error) {
	if input == nil {
		return nil, nil
	}
	
	result := make([]string, len(input))
	for i, str := range input {
		substituted, err := pc.SubstituteString(str)
		if err != nil {
			return nil, fmt.Errorf("failed to substitute string at index %d: %w", i, err)
		}
		result[i] = substituted
	}
	
	return result, nil
}

// SubstituteInputDef performs parameter substitution on an InputDef
func (pc *ParameterContext) SubstituteInputDef(input InputDef) (InputDef, error) {
	result := input // Copy the struct
	
	var err error
	
	// Substitute string fields
	if result.Resource, err = pc.SubstituteString(result.Resource); err != nil {
		return result, fmt.Errorf("failed to substitute resource: %w", err)
	}
	if result.Path, err = pc.SubstituteString(result.Path); err != nil {
		return result, fmt.Errorf("failed to substitute path: %w", err)
	}
	if result.URL, err = pc.SubstituteString(result.URL); err != nil {
		return result, fmt.Errorf("failed to substitute URL: %w", err)
	}
	if result.Command, err = pc.SubstituteString(result.Command); err != nil {
		return result, fmt.Errorf("failed to substitute command: %w", err)
	}
	if result.Namespace, err = pc.SubstituteString(result.Namespace); err != nil {
		return result, fmt.Errorf("failed to substitute namespace: %w", err)
	}
	if result.Region, err = pc.SubstituteString(result.Region); err != nil {
		return result, fmt.Errorf("failed to substitute region: %w", err)
	}
	if result.Profile, err = pc.SubstituteString(result.Profile); err != nil {
		return result, fmt.Errorf("failed to substitute profile: %w", err)
	}
	if result.ResourceType, err = pc.SubstituteString(result.ResourceType); err != nil {
		return result, fmt.Errorf("failed to substitute resource_type: %w", err)
	}
	
	// Substitute slice fields
	if result.Args, err = pc.SubstituteStringSlice(result.Args); err != nil {
		return result, fmt.Errorf("failed to substitute args: %w", err)
	}
	
	// Substitute map fields
	if result.Filters, err = pc.SubstituteStringMap(result.Filters); err != nil {
		return result, fmt.Errorf("failed to substitute filters: %w", err)
	}
	
	return result, nil
}

// SubstituteInlineCELRule performs parameter substitution on an InlineCELRule
func (pc *ParameterContext) SubstituteInlineCELRule(rule InlineCELRule) (InlineCELRule, error) {
	result := rule // Copy the struct
	
	var err error
	
	// Substitute expression
	if result.Expression, err = pc.SubstituteString(result.Expression); err != nil {
		return result, fmt.Errorf("failed to substitute expression: %w", err)
	}
	
	// Substitute inputs
	for i, input := range result.Inputs {
		if result.Inputs[i], err = pc.SubstituteInputDef(input); err != nil {
			return result, fmt.Errorf("failed to substitute input %d: %w", i, err)
		}
	}
	
	return result, nil
}

// GetParameterValue gets a parameter value with optional default
func (pc *ParameterContext) GetParameterValue(paramID, defaultValue string) string {
	if value, exists := pc.Parameters[paramID]; exists && value != "" {
		return value
	}
	return defaultValue
}

// GetParameterValueAsInt gets a parameter value as an integer with optional default
func (pc *ParameterContext) GetParameterValueAsInt(paramID string, defaultValue int) (int, error) {
	if value, exists := pc.Parameters[paramID]; exists && value != "" {
		intVal, err := strconv.Atoi(value)
		if err != nil {
			return defaultValue, fmt.Errorf("parameter %s value %s is not a valid integer: %w", paramID, value, err)
		}
		return intVal, nil
	}
	return defaultValue, nil
}

// GetParameterValueAsBool gets a parameter value as a boolean with optional default
func (pc *ParameterContext) GetParameterValueAsBool(paramID string, defaultValue bool) (bool, error) {
	if value, exists := pc.Parameters[paramID]; exists && value != "" {
		boolVal, err := strconv.ParseBool(value)
		if err != nil {
			return defaultValue, fmt.Errorf("parameter %s value %s is not a valid boolean: %w", paramID, value, err)
		}
		return boolVal, nil
	}
	return defaultValue, nil
}

// LogParameters logs all available parameters for debugging
func (pc *ParameterContext) LogParameters() {
	if len(pc.Parameters) == 0 {
		hclog.Default().Debug("No parameters available for substitution")
		return
	}
	
	for k, v := range pc.Parameters {
		hclog.Default().Debug("Available parameter", "key", k, "value", v)
	}
}

// Helper functions for case conversion
func toCamelCase(s string) string {
	// Convert kebab-case or snake_case to camelCase
	re := regexp.MustCompile(`[-_]([a-zA-Z])`)
	return re.ReplaceAllStringFunc(s, func(match string) string {
		return strings.ToUpper(string(match[1]))
	})
}

func toSnakeCase(s string) string {
	// Convert camelCase or kebab-case to snake_case
	re := regexp.MustCompile(`([a-z])([A-Z])`)
	s = re.ReplaceAllString(s, "${1}_${2}")
	s = strings.ReplaceAll(s, "-", "_")
	return strings.ToLower(s)
}

// ProcessParameterizedExpression handles advanced CEL expression parameterization
func (pc *ParameterContext) ProcessParameterizedExpression(expression string) (string, error) {
	// First do basic template substitution
	result, err := pc.SubstituteString(expression)
	if err != nil {
		return "", err
	}
	
	// Handle special cases like port lists
	result = pc.processPortLists(result)
	
	return result, nil
}

// processPortLists handles the expansion of port lists in CEL expressions
func (pc *ParameterContext) processPortLists(expression string) string {
	// Look for patterns like: {{ expandPorts .AllowedPorts }}
	re := regexp.MustCompile(`{{\s*expandPorts\s+\.(\w+)\s*}}`)
	
	return re.ReplaceAllStringFunc(expression, func(match string) string {
		// Extract parameter name
		submatches := re.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}
		
		paramName := submatches[1]
		portsList, exists := pc.Parameters[paramName]
		if !exists {
			hclog.Default().Warn("Parameter not found for port expansion", "param", paramName)
			return match
		}
		
		// Split ports and create OR expression
		ports := strings.Split(portsList, ",")
		var conditions []string
		for _, port := range ports {
			port = strings.TrimSpace(port)
			if port != "" {
				conditions = append(conditions, fmt.Sprintf("rule.fromPort == %s", port))
			}
		}
		
		if len(conditions) == 0 {
			return "false" // No ports means never match
		}
		
		return "(" + strings.Join(conditions, " || ") + ")"
	})
} 