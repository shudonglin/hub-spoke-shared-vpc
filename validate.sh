#!/bin/bash

# Hub-Spoke VPC Terraform Validation Script
# This script validates the Terraform configuration

set -e

echo "🔍 Hub-Spoke VPC Terraform Validation Script"
echo "=============================================="

# Check if Terraform is installed
if ! command -v terraform &> /dev/null; then
    echo "❌ Terraform is not installed. Please install Terraform first."
    exit 1
fi

echo "✅ Terraform is installed"

# Check Terraform version
TERRAFORM_VERSION=$(terraform version -json | jq -r '.terraform_version')
echo "📋 Terraform Version: $TERRAFORM_VERSION"

# Validate Terraform version (should be >= 1.12.0)
REQUIRED_VERSION="1.12.0"
if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$TERRAFORM_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ Terraform version $TERRAFORM_VERSION is below required version $REQUIRED_VERSION"
    exit 1
fi

echo "✅ Terraform version meets requirements"

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "⚠️  AWS CLI is not installed. Please install AWS CLI for better experience."
else
    echo "✅ AWS CLI is installed"
    
    # Check AWS credentials
    if aws sts get-caller-identity &> /dev/null; then
        echo "✅ AWS credentials are configured"
        ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
        echo "📋 AWS Account ID: $ACCOUNT_ID"
    else
        echo "⚠️  AWS credentials are not configured or invalid"
    fi
fi

# Initialize Terraform (if not already initialized)
if [ ! -d ".terraform" ]; then
    echo "🚀 Initializing Terraform..."
    terraform init
else
    echo "✅ Terraform already initialized"
fi

# Validate Terraform configuration
echo "🔍 Validating Terraform configuration..."
if terraform validate; then
    echo "✅ Terraform configuration is valid"
else
    echo "❌ Terraform configuration validation failed"
    exit 1
fi

# Format check
echo "🔍 Checking Terraform formatting..."
if terraform fmt -check -recursive; then
    echo "✅ Terraform files are properly formatted"
else
    echo "⚠️  Terraform files need formatting. Run 'terraform fmt -recursive' to fix."
fi

# Plan (if terraform.tfvars exists)
if [ -f "terraform.tfvars" ]; then
    echo "🔍 Running Terraform plan..."
    if terraform plan -out=tfplan -detailed-exitcode; then
        EXIT_CODE=$?
        if [ $EXIT_CODE -eq 0 ]; then
            echo "✅ No changes needed"
        elif [ $EXIT_CODE -eq 2 ]; then
            echo "✅ Plan completed successfully with changes"
        fi
    else
        echo "❌ Terraform plan failed"
        exit 1
    fi
else
    echo "⚠️  terraform.tfvars not found. Copy terraform.tfvars.example to terraform.tfvars and customize it."
fi

echo ""
echo "🎉 Validation completed successfully!"
echo ""
echo "Next steps:"
echo "1. Copy terraform.tfvars.example to terraform.tfvars"
echo "2. Customize terraform.tfvars with your desired values"
echo "3. Run 'terraform plan' to see what will be created"
echo "4. Run 'terraform apply' to create the infrastructure" 