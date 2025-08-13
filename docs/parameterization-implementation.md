# Parameterization Implementation Summary

## Overview

We have successfully implemented **dynamic parameterization** capabilities in the `compliance-sdk-plugin`, allowing OSCAL Assessment Plan parameters to be passed to CEL rules for runtime customization. This implementation follows the same pattern used by ComplyCtl's OpenSCAP plugin.

## What Was Implemented

### 1. Parameter Context System (`server/parameters.go`)

**Core Components:**
- `ParameterContext` struct: Holds parameter values and provides substitution methods
- `NewParameterContext()`: Extracts parameters from OSCAL RuleSet objects
- Template processing with Go text/template syntax
- Advanced functions like `expandPorts` for port list expansion
- Automatic case conversion (kebab-case ↔ camelCase ↔ snake_case)

**Key Methods:**
- `SubstituteString()`: Basic Go template substitution
- `SubstituteInputDef()`: Parameterize input configurations
- `SubstituteInlineCELRule()`: Parameterize complete rule definitions
- `ProcessParameterizedExpression()`: Advanced CEL expression processing

### 2. Enhanced Rule Generation (`server/server.go`)

**Updated Methods:**
- `getCELRulesForRuleSet()`: Now creates parameter context and passes to all rule generation
- `processMappingDefinitionWithParams()`: Parameterized version of mapping processing
- `createCELRuleFromInlineWithParams()`: Parameterized inline rule creation
- `createDefaultCELRuleWithParams()`: Parameterized built-in rule generation
- `addDefaultInputsWithParams()`: Parameterized default input creation

**Backward Compatibility:**
- All original methods maintained for compatibility
- Deprecated methods delegate to new parameterized versions
- No breaking changes to existing API

### 3. Enhanced Rule Store (`server/rulestore.go`)

**Updated Components:**
- `ConvertToCelRuleWithParams()`: Parameterized stored rule conversion
- `RuleInputConfig` struct: Added `Namespace` field for Kubernetes support
- Full parameter substitution for stored rule expressions, names, descriptions, and inputs

### 4. Template Functions

**Built-in Functions:**
- `expandPorts`: Converts `"22,80,443"` → `(rule.fromPort == 22 || rule.fromPort == 80 || rule.fromPort == 443)`
- Standard Go template functions: `if`, `eq`, `range`, etc.
- Support for conditional expressions and complex logic

### 5. Example Configurations

**Updated Files:**
- `examples/mappings.yaml`: Comprehensive parameterized mapping examples
- `examples/rules/aws-security.yaml`: Parameterized stored rule examples
- `examples/parameterized-assessment-plan.json`: Example Assessment Plan with parameters
- `docs/parameterization.md`: Complete usage documentation

## Parameter Flow Implementation

### 1. OSCAL Assessment Plan → ComplyCtl
```json
{
  "activities": [
    {
      "title": "aws-security-groups-ssh-open",
      "props": [
        {
          "name": "ssh-port",
          "value": "2222",
          "class": "test-parameter"
        }
      ]
    }
  ]
}
```

### 2. ComplyCtl → Plugin (Generate RPC)
```go
// ComplyCtl extracts parameters and creates RuleSet with Parameter objects
ruleSet := extensions.RuleSet{
    Rule: extensions.Rule{
        ID: "aws-security-groups-ssh-open",
        Parameters: []extensions.Parameter{
            {ID: "ssh-port", Value: "2222"},
        },
    },
}
```

### 3. Plugin Parameter Processing
```go
// Create parameter context from RuleSet
paramCtx := NewParameterContext(ruleSet)
// paramCtx.Parameters = {"ssh-port": "2222", "sshPort": "2222", "ssh_port": "2222"}

// Apply to rule template
expression := "rule.fromPort == {{ .SshPort }}"
result := "rule.fromPort == 2222"
```

### 4. Generated CEL Rule
```go
celRule := celscanner.NewRuleBuilder("aws-security-groups-ssh-open").
    SetExpression("!securityGroups.securityGroups.exists(sg, sg.ipPermissions.exists(rule, rule.fromPort == 2222 && rule.ipRanges.exists(ip, ip.cidrIp == '0.0.0.0/0')))").
    WithAWSInput("securityGroups", "us-west-2", "security-groups", nil, "security-audit").
    Build()
```

## Advanced Features Implemented

### 1. Multi-Format Parameter Names
Automatic conversion between naming conventions:
```go
// Input parameter: "max-age-days"
paramCtx.Parameters = {
    "max-age-days": "90",  // Original
    "maxAgeDays": "90",    // camelCase
    "max_age_days": "90",  // snake_case
}
```

### 2. Port List Expansion
```yaml
# Template
expression: "{{ expandPorts .DatabasePorts }}"

# Input parameter: "database-ports" = "3306,5432,1433"
# Generated output: "(rule.fromPort == 3306 || rule.fromPort == 5432 || rule.fromPort == 1433)"
```

### 3. Conditional Logic
```yaml
expression: |
  {{ if eq .EnvironmentType "production" }}
    key.age_days <= {{ .ProductionMaxAge }}
  {{ else }}
    key.age_days <= {{ .DevMaxAge }}
  {{ end }}
```

### 4. Input Configuration Parameterization
```yaml
inputs:
  - name: "securityGroups"
    type: "aws"
    region: "{{ .AwsRegion }}"        # us-west-2
    profile: "{{ .AwsProfile }}"      # security-audit
    resource_type: "security-groups"
    filters:
      user: "{{ .IamUser }}"          # service-account
```

## Integration Points

### 1. ComplyCtl Generate Phase
```bash
complyctl generate -f assessment-plan.json
```
- Loads Assessment Plan with parameterized activities
- Calls plugin's `Generate(policy.Policy)` method
- Plugin creates parameterized CEL rules and saves to `cel-rules.yaml`

### 2. ComplyCtl Scan Phase
```bash
complyctl scan -f assessment-plan.json
```
- Loads generated parameterized CEL rules
- Executes celscanner with customized rules
- Returns results through plugin's `GetResults()` method

### 3. Plugin Manifest Integration
```json
{
  "metadata": {
    "id": "compliance-sdk-plugin"
  },
  "configuration": [
    {
      "name": "enable_aws",
      "default": "true"
    }
  ]
}
```

## Testing and Validation

### 1. Unit Tests
- All existing tests pass with new parameterization features
- Backward compatibility maintained for all deprecated methods
- New parameter context functionality tested

### 2. Example Scenarios
- AWS Security Groups with custom ports
- IAM Access Key policies with environment-specific age limits
- Multi-region AWS resource scanning
- Kubernetes namespace-specific checks
- Conditional compliance rules

### 3. Error Handling
- Graceful fallback for template parsing errors
- Warning logs for parameter substitution failures
- Robust handling of missing or invalid parameters

## Benefits Achieved

### 1. **Flexibility**
- Single rule definitions work across multiple environments
- Organization-specific policy customization
- Runtime parameter adjustment without code changes

### 2. **Reusability**
- Parameterized rules can be shared across teams
- Common rule templates with environment-specific values
- Reduced maintenance overhead

### 3. **Compliance Integration**
- Full integration with OSCAL standard
- Compatible with ComplyCtl framework
- Follows established patterns from OpenSCAP plugin

### 4. **Extensibility**
- Easy to add new template functions
- Support for complex conditional logic
- Framework for future enhancements

## Usage Example

**Assessment Plan**:
```json
{
  "activities": [
    {
      "title": "aws-security-groups-ssh-open",
      "props": [
        {"name": "ssh-port", "value": "2222", "class": "test-parameter"},
        {"name": "aws-region", "value": "us-west-2", "class": "test-parameter"}
      ]
    }
  ]
}
```

**Rule Template**:
```yaml
expression: "!securityGroups.securityGroups.exists(sg, sg.ipPermissions.exists(rule, rule.fromPort == {{ .SshPort }} && rule.ipRanges.exists(ip, ip.cidrIp == '0.0.0.0/0')))"
inputs:
  - name: "securityGroups"
    type: "aws"
    region: "{{ .AwsRegion }}"
    resource_type: "security-groups"
```

**Generated CEL Rule**:
```yaml
expression: "!securityGroups.securityGroups.exists(sg, sg.ipPermissions.exists(rule, rule.fromPort == 2222 && rule.ipRanges.exists(ip, ip.cidrIp == '0.0.0.0/0')))"
inputs:
  - name: "securityGroups"
    type: "aws"
    region: "us-west-2"
    resource_type: "security-groups"
```

This implementation provides a powerful, flexible parameterization system that enables the `compliance-sdk-plugin` to support dynamic customization of CEL rules through OSCAL Assessment Plans, matching the capabilities demonstrated by ComplyCtl's OpenSCAP plugin. 