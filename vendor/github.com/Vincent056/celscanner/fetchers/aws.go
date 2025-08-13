/*
Copyright © 2024 Red Hat Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package fetchers

import (
	"context"
	"fmt"
	"time"

	"github.com/Vincent056/celscanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// AWSInputType represents AWS resource inputs
const AWSInputType celscanner.InputType = "aws"

// AWSSecurityGroupsInputType represents AWS Security Groups specifically
const AWSSecurityGroupsInputType celscanner.InputType = "aws-security-groups"

// AWSInputSpec specifies an AWS resource input
type AWSInputSpec interface {
	celscanner.InputSpec
	
	// Region returns the AWS region to query
	Region() string
	
	// ResourceType returns the AWS resource type (e.g., "security-groups", "iam-users")
	ResourceType() string
	
	// Filters returns AWS-specific filters
	Filters() map[string][]string
	
	// Profile returns the AWS profile to use (optional)
	Profile() string
}

// AWSInput provides a concrete implementation of AWSInputSpec
type AWSInput struct {
	AWSRegion      string              `json:"region"`
	AWSResourceType string             `json:"resourceType"`
	AWSFilters     map[string][]string `json:"filters,omitempty"`
	AWSProfile     string              `json:"profile,omitempty"`
}

func (a *AWSInput) Region() string                 { return a.AWSRegion }
func (a *AWSInput) ResourceType() string           { return a.AWSResourceType }
func (a *AWSInput) Filters() map[string][]string   { return a.AWSFilters }
func (a *AWSInput) Profile() string                { return a.AWSProfile }
func (a *AWSInput) Validate() error {
	if a.AWSRegion == "" {
		return fmt.Errorf("AWS region is required")
	}
	if a.AWSResourceType == "" {
		return fmt.Errorf("AWS resource type is required")
	}
	return nil
}

// AWSResourceHandler defines the interface for handling different AWS resource types
type AWSResourceHandler interface {
	// CanHandle returns true if this handler supports the resource type
	CanHandle(resourceType string) bool
	
	// FetchResource retrieves the resource using the appropriate AWS service
	FetchResource(ctx context.Context, spec AWSInputSpec, clientFactory *AWSClientFactory) (interface{}, error)
	
	// GetResourceType returns the resource type this handler manages
	GetResourceType() string
}

// AWSClientFactory manages AWS service clients for different regions and profiles
type AWSClientFactory struct {
	ec2Clients map[string]*ec2.Client
	iamClients map[string]*iam.Client
}

// NewAWSClientFactory creates a new AWS client factory
func NewAWSClientFactory() *AWSClientFactory {
	return &AWSClientFactory{
		ec2Clients: make(map[string]*ec2.Client),
		iamClients: make(map[string]*iam.Client),
	}
}

// GetEC2Client gets or creates an EC2 client for the specified region and profile
func (f *AWSClientFactory) GetEC2Client(region, profile string) (*ec2.Client, error) {
	key := fmt.Sprintf("%s-%s", region, profile)
	
	if client, exists := f.ec2Clients[key]; exists {
		return client, nil
	}
	
	cfg, err := f.loadAWSConfig(region, profile)
	if err != nil {
		return nil, err
	}
	
	client := ec2.NewFromConfig(cfg)
	f.ec2Clients[key] = client
	
	return client, nil
}

// GetIAMClient gets or creates an IAM client for the specified region and profile
func (f *AWSClientFactory) GetIAMClient(region, profile string) (*iam.Client, error) {
	key := fmt.Sprintf("%s-%s", region, profile)
	
	if client, exists := f.iamClients[key]; exists {
		return client, nil
	}
	
	cfg, err := f.loadAWSConfig(region, profile)
	if err != nil {
		return nil, err
	}
	
	client := iam.NewFromConfig(cfg)
	f.iamClients[key] = client
	
	return client, nil
}

// loadAWSConfig loads AWS configuration for the specified region and profile
func (f *AWSClientFactory) loadAWSConfig(region, profile string) (aws.Config, error) {
	var cfg aws.Config
	var err error
	
	if profile != "" {
		cfg, err = config.LoadDefaultConfig(context.TODO(),
			config.WithRegion(region),
			config.WithSharedConfigProfile(profile),
		)
	} else {
		cfg, err = config.LoadDefaultConfig(context.TODO(),
			config.WithRegion(region),
		)
	}
	
	if err != nil {
		return cfg, fmt.Errorf("failed to load AWS config: %w", err)
	}
	
	return cfg, nil
}

// AWSFetcher implements InputFetcher for AWS resources using a handler pattern
type AWSFetcher struct {
	// Default region if not specified in input
	defaultRegion string
	// Default profile if not specified in input
	defaultProfile string
	// Timeout for AWS API calls
	timeout time.Duration
	// Client factory for AWS services
	clientFactory *AWSClientFactory
	// Resource handlers by resource type
	handlers map[string]AWSResourceHandler
}

// NewAWSFetcher creates a new AWS input fetcher with resource handlers
func NewAWSFetcher(defaultRegion, defaultProfile string, timeout time.Duration) *AWSFetcher {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	
	clientFactory := NewAWSClientFactory()
	
	fetcher := &AWSFetcher{
		defaultRegion:  defaultRegion,
		defaultProfile: defaultProfile,
		timeout:        timeout,
		clientFactory:  clientFactory,
		handlers:       make(map[string]AWSResourceHandler),
	}
	
	// Register resource handlers
	fetcher.RegisterHandler(&SecurityGroupsHandler{})
	fetcher.RegisterHandler(&IAMUsersHandler{})
	fetcher.RegisterHandler(&IAMAccessKeysHandler{})
	
	return fetcher
}

// RegisterHandler registers a resource handler for a specific AWS resource type
func (a *AWSFetcher) RegisterHandler(handler AWSResourceHandler) {
	a.handlers[handler.GetResourceType()] = handler
}

// FetchInputs retrieves AWS resources for the specified inputs
func (a *AWSFetcher) FetchInputs(inputs []celscanner.Input, variables []celscanner.CelVariable) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	
	for _, input := range inputs {
		if !a.SupportsInputType(input.Type()) {
			continue
		}
		
		awsSpec, ok := input.Spec().(AWSInputSpec)
		if !ok {
			// Try to cast as the concrete implementation from interfaces.go (to avoid circular dependency)
			if concreteSpec, ok := input.Spec().(*celscanner.AWSInputImpl); ok {
				awsSpec = concreteSpec
			} else {
				return nil, fmt.Errorf("invalid AWS input spec for input %s", input.Name())
			}
		}
		
		data, err := a.fetchAWSResource(awsSpec)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch AWS resource for input %s: %w", input.Name(), err)
		}
		
		result[input.Name()] = data
	}
	
	return result, nil
}

// SupportsInputType returns true for AWS input types
func (a *AWSFetcher) SupportsInputType(inputType celscanner.InputType) bool {
	return inputType == AWSInputType || inputType == AWSSecurityGroupsInputType
}

// fetchAWSResource retrieves a specific AWS resource using the appropriate handler
func (a *AWSFetcher) fetchAWSResource(spec AWSInputSpec) (interface{}, error) {
	region := spec.Region()
	if region == "" {
		region = a.defaultRegion
	}
	
	if region == "" {
		return nil, fmt.Errorf("AWS region must be specified")
	}
	
	resourceType := spec.ResourceType()
	handler, exists := a.handlers[resourceType]
	if !exists {
		return nil, fmt.Errorf("no handler found for AWS resource type: %s", resourceType)
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	
	return handler.FetchResource(ctx, spec, a.clientFactory)
}

// ===== SECURITY GROUPS HANDLER =====

// SecurityGroupsHandler handles AWS security groups
type SecurityGroupsHandler struct{}

func (h *SecurityGroupsHandler) CanHandle(resourceType string) bool {
	return resourceType == "security-groups"
}

func (h *SecurityGroupsHandler) GetResourceType() string {
	return "security-groups"
}

func (h *SecurityGroupsHandler) FetchResource(ctx context.Context, spec AWSInputSpec, clientFactory *AWSClientFactory) (interface{}, error) {
	client, err := clientFactory.GetEC2Client(spec.Region(), spec.Profile())
	if err != nil {
		return nil, fmt.Errorf("failed to create EC2 client: %w", err)
	}
	
	sgResult, err := h.fetchSecurityGroups(ctx, client, spec.Region(), spec.Filters())
	if err != nil {
		return nil, err
	}
	
	return h.convertSecurityGroupResultToMap(sgResult), nil
}

// SecurityGroupResult represents security group data structured for CEL
type SecurityGroupResult struct {
	SecurityGroups []SecurityGroup `json:"securityGroups"`
	Region         string          `json:"region"`
	Timestamp      time.Time       `json:"timestamp"`
	Count          int             `json:"count"`
}

// SecurityGroup represents a security group for CEL evaluation
type SecurityGroup struct {
	GroupId               string              `json:"groupId"`
	GroupName             string              `json:"groupName"`
	Description           string              `json:"description"`
	VpcId                 string              `json:"vpcId"`
	OwnerId               string              `json:"ownerId"`
	Tags                  map[string]string   `json:"tags"`
	IngressRules          []SecurityGroupRule `json:"ingressRules"`
	EgressRules           []SecurityGroupRule `json:"egressRules"`
	IsDefaultGroup        bool                `json:"isDefaultGroup"`
	ReferencedByGroups    []string            `json:"referencedByGroups"`
}

// SecurityGroupRule represents an ingress or egress rule
type SecurityGroupRule struct {
	Protocol               string            `json:"protocol"`
	FromPort               int32             `json:"fromPort"`
	ToPort                 int32             `json:"toPort"`
	CidrBlocks            []string          `json:"cidrBlocks"`
	SourceSecurityGroups  []string          `json:"sourceSecurityGroups"`
	DestSecurityGroups    []string          `json:"destSecurityGroups"`
	Description           string            `json:"description"`
	Tags                  map[string]string `json:"tags"`
	IsEgress              bool              `json:"isEgress"`
	PrefixListIds         []string          `json:"prefixListIds"`
}

// fetchSecurityGroups retrieves security groups from AWS
func (h *SecurityGroupsHandler) fetchSecurityGroups(ctx context.Context, client *ec2.Client, region string, filters map[string][]string) (*SecurityGroupResult, error) {
	// Convert filters to AWS format
	var awsFilters []types.Filter
	for name, values := range filters {
		awsFilters = append(awsFilters, types.Filter{
			Name:   aws.String(name),
			Values: values,
		})
	}
	
	// Describe security groups
	input := &ec2.DescribeSecurityGroupsInput{}
	if len(awsFilters) > 0 {
		input.Filters = awsFilters
	}
	
	resp, err := client.DescribeSecurityGroups(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe security groups: %w", err)
	}
	
	// Convert to our structure
	securityGroups := make([]SecurityGroup, 0, len(resp.SecurityGroups))
	
	for _, sg := range resp.SecurityGroups {
		converted := h.convertSecurityGroup(sg)
		securityGroups = append(securityGroups, converted)
	}
	
	return &SecurityGroupResult{
		SecurityGroups: securityGroups,
		Region:         region,
		Timestamp:      time.Now(),
		Count:          len(securityGroups),
	}, nil
}

// convertSecurityGroup converts AWS SecurityGroup to our structure
func (h *SecurityGroupsHandler) convertSecurityGroup(sg types.SecurityGroup) SecurityGroup {
	// Convert tags
	tags := make(map[string]string)
	for _, tag := range sg.Tags {
		if tag.Key != nil && tag.Value != nil {
			tags[*tag.Key] = *tag.Value
		}
	}
	
	// Convert ingress rules
	ingressRules := make([]SecurityGroupRule, 0, len(sg.IpPermissions))
	for _, perm := range sg.IpPermissions {
		rules := h.convertIPPermissions(perm, false)
		ingressRules = append(ingressRules, rules...)
	}
	
	// Convert egress rules
	egressRules := make([]SecurityGroupRule, 0, len(sg.IpPermissionsEgress))
	for _, perm := range sg.IpPermissionsEgress {
		rules := h.convertIPPermissions(perm, true)
		egressRules = append(egressRules, rules...)
	}
	
	// Check if this is a default security group
	isDefault := sg.GroupName != nil && *sg.GroupName == "default"
	
	result := SecurityGroup{
		GroupId:        aws.ToString(sg.GroupId),
		GroupName:      aws.ToString(sg.GroupName),
		Description:    aws.ToString(sg.Description),
		VpcId:          aws.ToString(sg.VpcId),
		OwnerId:        aws.ToString(sg.OwnerId),
		Tags:           tags,
		IngressRules:   ingressRules,
		EgressRules:    egressRules,
		IsDefaultGroup: isDefault,
	}
	
	return result
}

// convertIPPermissions converts AWS IP permissions to our rule structure
func (h *SecurityGroupsHandler) convertIPPermissions(perm types.IpPermission, isEgress bool) []SecurityGroupRule {
	var rules []SecurityGroupRule
	
	protocol := aws.ToString(perm.IpProtocol)
	fromPort := aws.ToInt32(perm.FromPort)
	toPort := aws.ToInt32(perm.ToPort)
	
	// Handle CIDR blocks
	for _, ipRange := range perm.IpRanges {
		rule := SecurityGroupRule{
			Protocol:    protocol,
			FromPort:    fromPort,
			ToPort:      toPort,
			CidrBlocks:  []string{aws.ToString(ipRange.CidrIp)},
			Description: aws.ToString(ipRange.Description),
			IsEgress:    isEgress,
		}
		rules = append(rules, rule)
	}
	
	// Handle IPv6 CIDR blocks
	for _, ipv6Range := range perm.Ipv6Ranges {
		rule := SecurityGroupRule{
			Protocol:    protocol,
			FromPort:    fromPort,
			ToPort:      toPort,
			CidrBlocks:  []string{aws.ToString(ipv6Range.CidrIpv6)},
			Description: aws.ToString(ipv6Range.Description),
			IsEgress:    isEgress,
		}
		rules = append(rules, rule)
	}
	
	// Handle security group references
	for _, userIdGroupPair := range perm.UserIdGroupPairs {
		rule := SecurityGroupRule{
			Protocol:    protocol,
			FromPort:    fromPort,
			ToPort:      toPort,
			Description: aws.ToString(userIdGroupPair.Description),
			IsEgress:    isEgress,
		}
		
		if userIdGroupPair.GroupId != nil {
			if isEgress {
				rule.DestSecurityGroups = []string{*userIdGroupPair.GroupId}
			} else {
				rule.SourceSecurityGroups = []string{*userIdGroupPair.GroupId}
			}
		}
		
		rules = append(rules, rule)
	}
	
	// Handle prefix lists
	for _, prefixList := range perm.PrefixListIds {
		rule := SecurityGroupRule{
			Protocol:      protocol,
			FromPort:      fromPort,
			ToPort:        toPort,
			PrefixListIds: []string{aws.ToString(prefixList.PrefixListId)},
			Description:   aws.ToString(prefixList.Description),
			IsEgress:      isEgress,
		}
		rules = append(rules, rule)
	}
	
	// If no specific ranges/groups were found, create a basic rule
	if len(rules) == 0 {
		rule := SecurityGroupRule{
			Protocol: protocol,
			FromPort: fromPort,
			ToPort:   toPort,
			IsEgress: isEgress,
		}
		rules = append(rules, rule)
	}
	
	return rules
}

// convertSecurityGroupResultToMap converts SecurityGroupResult to map[string]interface{} for CEL compatibility
func (h *SecurityGroupsHandler) convertSecurityGroupResultToMap(result *SecurityGroupResult) map[string]interface{} {
	// Convert SecurityGroup structs to maps
	securityGroups := make([]map[string]interface{}, 0, len(result.SecurityGroups))
	
	for _, sg := range result.SecurityGroups {
		sgMap := map[string]interface{}{
			"groupId":        sg.GroupId,
			"groupName":      sg.GroupName,
			"description":    sg.Description,
			"vpcId":          sg.VpcId,
			"ownerId":        sg.OwnerId,
			"tags":           sg.Tags,
			"isDefaultGroup": sg.IsDefaultGroup,
		}
		
		// Convert ingress rules
		ingressRules := make([]map[string]interface{}, 0, len(sg.IngressRules))
		for _, rule := range sg.IngressRules {
			ruleMap := map[string]interface{}{
				"protocol":              rule.Protocol,
				"fromPort":              rule.FromPort,
				"toPort":                rule.ToPort,
				"cidrBlocks":            rule.CidrBlocks,
				"sourceSecurityGroups":  rule.SourceSecurityGroups,
				"destSecurityGroups":    rule.DestSecurityGroups,
				"prefixListIds":         rule.PrefixListIds,
				"description":           rule.Description,
				"tags":                  rule.Tags,
				"isEgress":              rule.IsEgress,
			}
			ingressRules = append(ingressRules, ruleMap)
		}
		sgMap["ingressRules"] = ingressRules
		
		// Convert egress rules
		egressRules := make([]map[string]interface{}, 0, len(sg.EgressRules))
		for _, rule := range sg.EgressRules {
			ruleMap := map[string]interface{}{
				"protocol":              rule.Protocol,
				"fromPort":              rule.FromPort,
				"toPort":                rule.ToPort,
				"cidrBlocks":            rule.CidrBlocks,
				"sourceSecurityGroups":  rule.SourceSecurityGroups,
				"destSecurityGroups":    rule.DestSecurityGroups,
				"prefixListIds":         rule.PrefixListIds,
				"description":           rule.Description,
				"tags":                  rule.Tags,
				"isEgress":              rule.IsEgress,
			}
			egressRules = append(egressRules, ruleMap)
		}
		sgMap["egressRules"] = egressRules
		
		securityGroups = append(securityGroups, sgMap)
	}
	
	// Return the final map structure
	return map[string]interface{}{
		"securityGroups": securityGroups,
		"region":         result.Region,
		"timestamp":      result.Timestamp,
		"count":          result.Count,
	}
}

// ===== IAM USERS HANDLER =====

// IAMUsersHandler handles AWS IAM users
type IAMUsersHandler struct{}

func (h *IAMUsersHandler) CanHandle(resourceType string) bool {
	return resourceType == "iam-users"
}

func (h *IAMUsersHandler) GetResourceType() string {
	return "iam-users"
}

func (h *IAMUsersHandler) FetchResource(ctx context.Context, spec AWSInputSpec, clientFactory *AWSClientFactory) (interface{}, error) {
	client, err := clientFactory.GetIAMClient(spec.Region(), spec.Profile())
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM client: %w", err)
	}
	
	usersResult, err := h.fetchIAMUsers(ctx, client, spec.Filters())
	if err != nil {
		return nil, err
	}
	
	return h.convertIAMUsersResultToMap(usersResult), nil
}

// IAMUsersResult represents IAM users data structured for CEL
type IAMUsersResult struct {
	Users     []IAMUser `json:"users"`
	Timestamp time.Time `json:"timestamp"`
	Count     int       `json:"count"`
}

// IAMUser represents an IAM user for CEL evaluation
type IAMUser struct {
	UserName             string            `json:"userName"`
	UserId               string            `json:"userId"`
	Arn                  string            `json:"arn"`
	Path                 string            `json:"path"`
	CreateDate           time.Time         `json:"createDate"`
	PasswordLastUsed     *time.Time        `json:"passwordLastUsed"`
	PermissionsBoundary  string            `json:"permissionsBoundary"`
	Tags                 map[string]string `json:"tags"`
}

// fetchIAMUsers retrieves IAM users from AWS
func (h *IAMUsersHandler) fetchIAMUsers(ctx context.Context, client *iam.Client, filters map[string][]string) (*IAMUsersResult, error) {
	// Build input with optional path prefix filter
	input := &iam.ListUsersInput{}
	
	if filters != nil {
		if pathPrefixes, ok := filters["path-prefix"]; ok && len(pathPrefixes) > 0 {
			input.PathPrefix = aws.String(pathPrefixes[0])
		}
	}
	
	// List users
	resp, err := client.ListUsers(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to list IAM users: %w", err)
	}
	
	// Convert to our structure
	users := make([]IAMUser, 0, len(resp.Users))
	
	for _, user := range resp.Users {
		converted := h.convertIAMUser(user)
		users = append(users, converted)
	}
	
	return &IAMUsersResult{
		Users:     users,
		Timestamp: time.Now(),
		Count:     len(users),
	}, nil
}

// convertIAMUser converts AWS IAM User to our structure
func (h *IAMUsersHandler) convertIAMUser(user iamtypes.User) IAMUser {
	// Convert tags
	tags := make(map[string]string)
	for _, tag := range user.Tags {
		if tag.Key != nil && tag.Value != nil {
			tags[*tag.Key] = *tag.Value
		}
	}
	
	// Handle permissions boundary
	permissionsBoundary := ""
	if user.PermissionsBoundary != nil && user.PermissionsBoundary.PermissionsBoundaryArn != nil {
		permissionsBoundary = *user.PermissionsBoundary.PermissionsBoundaryArn
	}
	
	result := IAMUser{
		UserName:             aws.ToString(user.UserName),
		UserId:               aws.ToString(user.UserId),
		Arn:                  aws.ToString(user.Arn),
		Path:                 aws.ToString(user.Path),
		CreateDate:           aws.ToTime(user.CreateDate),
		PasswordLastUsed:     user.PasswordLastUsed,
		PermissionsBoundary:  permissionsBoundary,
		Tags:                 tags,
	}
	
	return result
}

// convertIAMUsersResultToMap converts IAMUsersResult to map[string]interface{} for CEL compatibility
func (h *IAMUsersHandler) convertIAMUsersResultToMap(result *IAMUsersResult) map[string]interface{} {
	// Convert IAMUser structs to maps
	users := make([]map[string]interface{}, 0, len(result.Users))
	
	for _, user := range result.Users {
		userMap := map[string]interface{}{
			"userName":            user.UserName,
			"userId":              user.UserId,
			"arn":                 user.Arn,
			"path":                user.Path,
			"createDate":          user.CreateDate,
			"permissionsBoundary": user.PermissionsBoundary,
			"tags":                user.Tags,
		}
		
		// Handle optional password last used
		if user.PasswordLastUsed != nil {
			userMap["passwordLastUsed"] = *user.PasswordLastUsed
		} else {
			userMap["passwordLastUsed"] = nil
		}
		
		users = append(users, userMap)
	}
	
	// Return the final map structure
	return map[string]interface{}{
		"users":     users,
		"timestamp": result.Timestamp,
		"count":     result.Count,
	}
}

// ===== IAM ACCESS KEYS HANDLER =====

// IAMAccessKeysHandler handles AWS IAM user access keys
type IAMAccessKeysHandler struct{}

func (h *IAMAccessKeysHandler) CanHandle(resourceType string) bool {
	return resourceType == "iam-access-keys"
}

func (h *IAMAccessKeysHandler) GetResourceType() string {
	return "iam-access-keys"
}

func (h *IAMAccessKeysHandler) FetchResource(ctx context.Context, spec AWSInputSpec, clientFactory *AWSClientFactory) (interface{}, error) {
	client, err := clientFactory.GetIAMClient(spec.Region(), spec.Profile())
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM client: %w", err)
	}
	
	accessKeysResult, err := h.fetchIAMAccessKeys(ctx, client, spec.Filters())
	if err != nil {
		return nil, err
	}
	
	return h.convertIAMAccessKeysResultToMap(accessKeysResult), nil
}

// IAMAccessKeysResult represents IAM access keys data structured for CEL
type IAMAccessKeysResult struct {
	AccessKeys []IAMAccessKey `json:"accessKeys"`
	Timestamp  time.Time      `json:"timestamp"`
	Count      int            `json:"count"`
}

// IAMAccessKey represents an IAM access key for CEL evaluation
type IAMAccessKey struct {
	AccessKeyId     string     `json:"accessKeyId"`
	UserName        string     `json:"userName"`
	Status          string     `json:"status"`
	CreateDate      time.Time  `json:"createDate"`
	LastUsedDate    *time.Time `json:"lastUsedDate"`
	LastUsedRegion  string     `json:"lastUsedRegion"`
	LastUsedService string     `json:"lastUsedService"`
	DaysOld         int        `json:"daysOld"`
}

// fetchIAMAccessKeys retrieves IAM access keys from AWS
func (h *IAMAccessKeysHandler) fetchIAMAccessKeys(ctx context.Context, client *iam.Client, filters map[string][]string) (*IAMAccessKeysResult, error) {
	var allAccessKeys []IAMAccessKey
	
	// First, get all users (or specific user if filtered)
	var userNames []string
	if filters != nil {
		if userFilters, ok := filters["user-name"]; ok && len(userFilters) > 0 {
			userNames = userFilters
		}
	}
	
	// If no specific users specified, get all users
	if len(userNames) == 0 {
		listUsersInput := &iam.ListUsersInput{}
		resp, err := client.ListUsers(ctx, listUsersInput)
		if err != nil {
			return nil, fmt.Errorf("failed to list users: %w", err)
		}
		
		for _, user := range resp.Users {
			if user.UserName != nil {
				userNames = append(userNames, *user.UserName)
			}
		}
	}
	
	// For each user, get their access keys
	for _, userName := range userNames {
		accessKeys, err := h.fetchAccessKeysForUser(ctx, client, userName)
		if err != nil {
			// Log error but continue with other users
			continue
		}
		allAccessKeys = append(allAccessKeys, accessKeys...)
	}
	
	return &IAMAccessKeysResult{
		AccessKeys: allAccessKeys,
		Timestamp:  time.Now(),
		Count:      len(allAccessKeys),
	}, nil
}

// fetchAccessKeysForUser retrieves access keys for a specific user
func (h *IAMAccessKeysHandler) fetchAccessKeysForUser(ctx context.Context, client *iam.Client, userName string) ([]IAMAccessKey, error) {
	// List access keys for the user
	listKeysInput := &iam.ListAccessKeysInput{
		UserName: aws.String(userName),
	}
	
	resp, err := client.ListAccessKeys(ctx, listKeysInput)
	if err != nil {
		return nil, fmt.Errorf("failed to list access keys for user %s: %w", userName, err)
	}
	
	var accessKeys []IAMAccessKey
	
	for _, key := range resp.AccessKeyMetadata {
		accessKey := h.convertAccessKey(key)
		
		// Get last used information for the access key
		if key.AccessKeyId != nil {
			lastUsed, err := h.getAccessKeyLastUsed(ctx, client, *key.AccessKeyId)
			if err == nil && lastUsed != nil {
				accessKey.LastUsedDate = lastUsed.LastUsedDate
				accessKey.LastUsedRegion = aws.ToString(lastUsed.Region)
				accessKey.LastUsedService = aws.ToString(lastUsed.ServiceName)
			}
		}
		
		accessKeys = append(accessKeys, accessKey)
	}
	
	return accessKeys, nil
}

// getAccessKeyLastUsed retrieves last used information for an access key
func (h *IAMAccessKeysHandler) getAccessKeyLastUsed(ctx context.Context, client *iam.Client, accessKeyId string) (*iamtypes.AccessKeyLastUsed, error) {
	input := &iam.GetAccessKeyLastUsedInput{
		AccessKeyId: aws.String(accessKeyId),
	}
	
	resp, err := client.GetAccessKeyLastUsed(ctx, input)
	if err != nil {
		return nil, err
	}
	
	return resp.AccessKeyLastUsed, nil
}

// convertAccessKey converts AWS AccessKeyMetadata to our structure
func (h *IAMAccessKeysHandler) convertAccessKey(key iamtypes.AccessKeyMetadata) IAMAccessKey {
	createDate := aws.ToTime(key.CreateDate)
	daysOld := int(time.Since(createDate).Hours() / 24)
	
	result := IAMAccessKey{
		AccessKeyId: aws.ToString(key.AccessKeyId),
		UserName:    aws.ToString(key.UserName),
		Status:      string(key.Status),
		CreateDate:  createDate,
		DaysOld:     daysOld,
	}
	
	return result
}

// convertIAMAccessKeysResultToMap converts IAMAccessKeysResult to map[string]interface{} for CEL compatibility
func (h *IAMAccessKeysHandler) convertIAMAccessKeysResultToMap(result *IAMAccessKeysResult) map[string]interface{} {
	// Convert IAMAccessKey structs to maps
	accessKeys := make([]map[string]interface{}, 0, len(result.AccessKeys))
	
	for _, key := range result.AccessKeys {
		keyMap := map[string]interface{}{
			"accessKeyId":     key.AccessKeyId,
			"userName":        key.UserName,
			"status":          key.Status,
			"createDate":      key.CreateDate,
			"lastUsedRegion":  key.LastUsedRegion,
			"lastUsedService": key.LastUsedService,
			"daysOld":         key.DaysOld,
		}
		
		// Handle optional last used date
		if key.LastUsedDate != nil {
			keyMap["lastUsedDate"] = *key.LastUsedDate
		} else {
			keyMap["lastUsedDate"] = nil
		}
		
		accessKeys = append(accessKeys, keyMap)
	}
	
	// Return the final map structure
	return map[string]interface{}{
		"accessKeys": accessKeys,
		"timestamp":  result.Timestamp,
		"count":      result.Count,
	}
}

// ===== CONVENIENCE CONSTRUCTORS =====

// NewAWSInput creates an AWS resource input
func NewAWSInput(name, region, resourceType string, filters map[string][]string, profile string) celscanner.Input {
	return &celscanner.InputImpl{
		InputName: name,
		InputType: AWSInputType,
		InputSpec: &AWSInput{
			AWSRegion:       region,
			AWSResourceType: resourceType,
			AWSFilters:      filters,
			AWSProfile:      profile,
		},
	}
}

// NewAWSSecurityGroupsInput creates an AWS Security Groups input (convenience function)
func NewAWSSecurityGroupsInput(name, region string, filters map[string][]string, profile string) celscanner.Input {
	return &celscanner.InputImpl{
		InputName: name,
		InputType: AWSSecurityGroupsInputType,
		InputSpec: &AWSInput{
			AWSRegion:       region,
			AWSResourceType: "security-groups",
			AWSFilters:      filters,
			AWSProfile:      profile,
		},
	}
}

// NewAWSIAMUsersInput creates an AWS IAM Users input (convenience function)
func NewAWSIAMUsersInput(name, region string, filters map[string][]string, profile string) celscanner.Input {
	return &celscanner.InputImpl{
		InputName: name,
		InputType: celscanner.InputTypeAWS,
		InputSpec: &AWSInput{
			AWSRegion:       region,
			AWSResourceType: "iam-users",
			AWSFilters:      filters,
			AWSProfile:      profile,
		},
	}
}

// NewAWSIAMAccessKeysInput creates an AWS IAM Access Keys input (convenience function)
func NewAWSIAMAccessKeysInput(name, region string, filters map[string][]string, profile string) celscanner.Input {
	return &celscanner.InputImpl{
		InputName: name,
		InputType: celscanner.InputTypeAWS,
		InputSpec: &AWSInput{
			AWSRegion:       region,
			AWSResourceType: "iam-access-keys",
			AWSFilters:      filters,
			AWSProfile:      profile,
		},
	}
} 