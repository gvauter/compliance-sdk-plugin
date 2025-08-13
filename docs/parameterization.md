# CEL Scanner Plugin Parameterization Guide

## Overview

The `compliance-sdk-plugin` now supports **dynamic parameterization** of CEL rules through OSCAL Assessment Plans. This allows you to customize compliance checks at runtime based on organization-specific policies, environments, and requirements without modifying the underlying rule definitions.

## How Parameterization Works

### 1. Parameter Flow

```
OSCAL Assessment Plan → ComplyCtl → Plugin → CEL Rules
       ↓                    ↓         ↓         ↓
   Activities with      Extracts    Applies   Generates
   test-parameter      parameters   to        parameterized
   properties                      templates  CEL expressions
```

### 2. Parameter Sources

Parameters come from **Assessment Activities** in OSCAL Assessment Plans:

```json
{
  "activities": [
    {
      "title": "aws-security-groups-ssh-open",
      "props": [
        {
          "name": "ssh-port",
          "value": "22",
          "class": "test-parameter"
        }
      ]
    }
  ]
}
```

**Key Requirements:**
- Property `class` must be `"test-parameter"`
- Activity `title` must match the rule ID
- Property `name` becomes the parameter key
- Property `value` becomes the parameter value

## Template Syntax

### Basic Parameter Substitution

Use Go template syntax in CEL expressions and input configurations:

```yaml
expression: "rule.fromPort == {{ .SshPort }}"
inputs:
  - name: "securityGroups"
    region: "{{ .AwsRegion }}"
    resource_type: "{{ .ResourceType }}"
```

### Advanced Functions

#### Port List Expansion

For dynamic port checking, use the `expandPorts` function:

```yaml
expression: "!sg.ipPermissions.exists(rule, {{ expandPorts .DatabasePorts }} && rule.ipRanges.exists(ip, ip.cidrIp == '0.0.0.0/0'))"
```

**Input**: `DatabasePorts: "3306,5432,1433"`
**Output**: `(rule.fromPort == 3306 || rule.fromPort == 5432 || rule.fromPort == 1433)`

#### Conditional Logic

Use Go template conditionals for environment-specific rules:

```yaml
expression: "{{ if eq .EnvironmentType \"production\" }}key.age_days <= {{ .ProductionMaxAge }}{{ else }}key.age_days <= {{ .DevMaxAge }}{{ end }}"
```

## Parameter Name Variations

The plugin automatically creates multiple parameter name formats for flexibility:

| Original | camelCase | snake_case |
|----------|-----------|------------|
| `ssh-port` | `sshPort` | `ssh_port` |
| `max-age-days` | `maxAgeDays` | `max_age_days` |
| `aws-region` | `awsRegion` | `aws_region` |

## Example Use Cases

### 1. AWS Security Groups with Custom Ports

**Assessment Plan**:
```json
{
  "title": "aws-security-groups-ssh-open",
  "props": [
    {
      "name": "allowed-ports",
      "value": "443,22,8080",
      "class": "test-parameter"
    }
  ]
}
```

**Rule Template**:
```yaml
expression: "!sg.exists(sg, sg.ipPermissions.exists(rule, {{ expandPorts .AllowedPorts }} && rule.ipRanges.exists(ip, ip.cidrIp == '0.0.0.0/0')))"
```

### 2. Environment-Specific IAM Key Policies

**Assessment Plan**:
```json
{
  "title": "aws-iam-access-keys-old",
  "props": [
    {
      "name": "max-age-days",
      "value": "30",
      "class": "test-parameter"
    },
    {
      "name": "environment",
      "value": "production",
      "class": "test-parameter"
    }
  ]
}
```

**Rule Template**:
```yaml
expression: "!iamKeys.keys.exists(key, key.age_days > {{ .MaxAgeDays }})"
```

### 3. Multi-Region AWS Checks

**Assessment Plan**:
```json
{
  "title": "aws-multi-region-check",
  "props": [
    {
      "name": "aws-region",
      "value": "us-west-2",
      "class": "test-parameter"
    },
    {
      "name": "aws-profile", 
      "value": "security-audit",
      "class": "test-parameter"
    }
  ]
}
```

**Rule Template**:
```yaml
inputs:
  - name: "resources"
    type: "aws"
    region: "{{ .AwsRegion }}"
    profile: "{{ .AwsProfile }}"
```

### 4. Kubernetes Namespace-Specific Checks

**Assessment Plan**:
```json
{
  "title": "pod-security-context",
  "props": [
    {
      "name": "namespace",
      "value": "production",
      "class": "test-parameter"
    }
  ]
}
```

**Rule Template**:
```yaml
inputs:
  - name: "pods"
    type: "kubernetes"
    resource: "pods"
    namespace: "{{ .Namespace }}"
```

## Configuration Examples

### Mapping Configuration (mappings.yaml)

```yaml
mappings:
  aws-security:
    type: "inline"
    rules:
      - id: "aws-security-groups-ssh"
        expression: "!securityGroups.securityGroups.exists(sg, sg.ipPermissions.exists(rule, {{ expandPorts .AllowedPorts }} && rule.ipRanges.exists(ip, ip.cidrIp == '0.0.0.0/0')))"
        inputs:
          - name: "securityGroups"
            type: "aws"
            region: "{{ .AwsRegion }}"
            profile: "{{ .AwsProfile }}"
            resource_type: "security-groups"

# Default parameter values
default_parameters:
  AllowedPorts: "443,22"
  AwsRegion: "us-east-1"
  AwsProfile: "default"
```

### Stored Rules (aws-security.yaml)

```yaml
- id: "aws-security-groups-ssh-open"
  name: "SSH Access Control Check"
  description: "Checks that security groups do not allow SSH (port {{ .SshPort }}) access from 0.0.0.0/0"
  expression: "!securityGroups.securityGroups.exists(sg, sg.ipPermissions.exists(rule, rule.fromPort == {{ .SshPort }} && rule.ipRanges.exists(ip, ip.cidrIp == '0.0.0.0/0')))"
  inputs:
    - name: "securityGroups"
      type: "aws"
      region: "{{ .AwsRegion }}"
      profile: "{{ .AwsProfile }}"
      resource_type: "security-groups"
```

## Integration with ComplyCtl

### 1. Create Assessment Plan

Create an assessment plan with parameterized activities:

```bash
# assessment-plan.json
{
  "assessment-plan": {
    "local-definitions": {
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
    },
    "assessment-assets": {
      "components": [
        {
          "type": "validation",
          "title": "compliance-sdk-plugin",
          "props": [
            {
              "name": "provider-id",
              "value": "compliance-sdk-plugin"
            }
          ]
        }
      ]
    }
  }
}
```

### 2. Run ComplyCtl Commands

```bash
# Generate parameterized policies
complyctl generate -f assessment-plan.json

# Execute parameterized scans  
complyctl scan -f assessment-plan.json
```

### 3. Plugin Configuration

Configure the plugin in your manifest:

```yaml
# c2p-compliance-sdk-plugin-manifest.json
{
  "metadata": {
    "id": "compliance-sdk-plugin"
  },
  "configuration": [
    {
      "name": "workspace",
      "required": true
    },
    {
      "name": "enable_aws",
      "default": "true"
    }
  ]
}
```

## Best Practices

### 1. Parameter Naming

- Use **kebab-case** in Assessment Plans: `max-age-days`
- Template references work with any case: `{{ .MaxAgeDays }}`, `{{ .max_age_days }}`
- Be consistent within your organization

### 2. Default Values

Always provide sensible defaults in mapping configurations:

```yaml
default_parameters:
  MaxAgeDays: "90"      # Reasonable IAM key rotation policy
  SshPort: "22"         # Standard SSH port
  AwsRegion: "us-east-1" # Default AWS region
```

### 3. Validation

Parameters are validated during template execution:
- Invalid template syntax causes rule generation to fail
- Missing parameters fall back to empty strings
- Type mismatches are logged as warnings

### 4. Security Considerations

- **Never** put sensitive values directly in Assessment Plans
- Use AWS profiles and IAM roles for credentials
- Parameterize regions and accounts, not secrets
- Validate parameter values in production environments

### 5. Testing

Test your parameterized rules with different parameter values:

```bash
# Test with development parameters
complyctl generate -f assessment-plan-dev.json

# Test with production parameters  
complyctl generate -f assessment-plan-prod.json

# Compare generated rules
diff workspace/plugins/policy/cel-rules.yaml.dev workspace/plugins/policy/cel-rules.yaml.prod
```

## Troubleshooting

### Common Issues

1. **Parameters not substituted**
   - Check `class: "test-parameter"` is set
   - Verify activity title matches rule ID
   - Enable debug logging: `--debug`

2. **Template syntax errors**
   - Validate Go template syntax
   - Check parameter names match exactly
   - Use debug logs to see applied parameters

3. **Missing parameter values**
   - Parameters default to empty strings if missing
   - Check Assessment Plan property names
   - Verify rule ID matches activity title

### Debug Logging

Enable debug logging to see parameter substitution:

```bash
complyctl generate -f assessment-plan.json --debug
```

Look for log messages like:
```
Applied parameter substitution to inline rule rule_id=aws-security-groups-ssh original_expression=... parameterized_expression=...
```

## Advanced Features

### Custom Template Functions

The plugin provides these template functions:

- `expandPorts`: Expands comma-separated ports into CEL OR expressions
- Standard Go template functions: `if`, `eq`, `range`, etc.

### Conditional Rules

Create rules that behave differently based on parameters:

```yaml
expression: |
  {{ if .StrictMode }}
    // Strict compliance check
    resources.all(r, r.compliant == true)
  {{ else }}
    // Lenient check
    resources.exists(r, r.compliant == true)
  {{ end }}
```

### Dynamic Input Configuration

Parameterize not just expressions but also input sources:

```yaml
inputs:
  - name: "{{ .InputName }}"
    type: "{{ .InputType }}"
    region: "{{ .Region }}"
    filters:
      environment: "{{ .Environment }}"
```

This powerful parameterization system enables you to create flexible, reusable compliance rules that adapt to your organization's specific requirements while maintaining consistency across different environments and use cases. 