#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=========================================="
echo "Mantissa Log Destruction Script"
echo "=========================================="
echo ""
echo "WARNING: This will destroy all Mantissa Log infrastructure"
echo "         and optionally delete all log data."
echo ""

confirm_destruction() {
    echo "This action will:"
    echo "  - Destroy all Lambda functions"
    echo "  - Delete Glue database and tables"
    echo "  - Remove EventBridge rules"
    echo "  - Delete Cognito user pool"
    echo "  - Remove API Gateway"
    echo "  - Delete DynamoDB tables"
    echo ""

    read -p "Are you absolutely sure you want to destroy everything? (yes/no): " CONFIRM

    if [ "$CONFIRM" != "yes" ]; then
        echo "Destruction cancelled"
        exit 0
    fi

    echo ""
    read -p "Delete S3 buckets and ALL log data? (yes/no): " DELETE_S3

    echo ""
    read -p "Final confirmation - type 'DELETE' to proceed: " FINAL_CONFIRM

    if [ "$FINAL_CONFIRM" != "DELETE" ]; then
        echo "Destruction cancelled"
        exit 0
    fi
}

get_bucket_names() {
    if [ -f "$PROJECT_ROOT/terraform-outputs.json" ]; then
        LOGS_BUCKET=$(grep -o '"logs_bucket[^:]*:[^"]*"[^"]*"' "$PROJECT_ROOT/terraform-outputs.json" | cut -d'"' -f4 || echo "")
        ATHENA_BUCKET=$(grep -o '"athena_results_bucket[^:]*:[^"]*"[^"]*"' "$PROJECT_ROOT/terraform-outputs.json" | cut -d'"' -f4 || echo "")
        RULES_BUCKET=$(grep -o '"rules_bucket[^:]*:[^"]*"[^"]*"' "$PROJECT_ROOT/terraform-outputs.json" | cut -d'"' -f4 || echo "")
    fi
}

empty_s3_buckets() {
    echo "Emptying S3 buckets..."

    if [ -n "$LOGS_BUCKET" ]; then
        echo "  Emptying logs bucket: $LOGS_BUCKET"
        aws s3 rm "s3://$LOGS_BUCKET" --recursive || echo "  Warning: Could not empty logs bucket"
    fi

    if [ -n "$ATHENA_BUCKET" ]; then
        echo "  Emptying Athena results bucket: $ATHENA_BUCKET"
        aws s3 rm "s3://$ATHENA_BUCKET" --recursive || echo "  Warning: Could not empty Athena bucket"
    fi

    if [ -n "$RULES_BUCKET" ]; then
        echo "  Emptying rules bucket: $RULES_BUCKET"
        aws s3 rm "s3://$RULES_BUCKET" --recursive || echo "  Warning: Could not empty rules bucket"
    fi

    echo ""
}

destroy_infrastructure() {
    echo "Destroying infrastructure with Terraform..."

    cd "$PROJECT_ROOT/infrastructure/aws/terraform"

    if [ ! -f "terraform.tfstate" ] && [ ! -f "backend.tf" ]; then
        echo "  No Terraform state found. Nothing to destroy."
        return
    fi

    if [ ! -d ".terraform" ]; then
        echo "  Initializing Terraform..."
        terraform init
    fi

    echo ""
    echo "  Running terraform destroy..."
    terraform destroy -auto-approve

    echo "  Infrastructure destroyed"
    echo ""
}

delete_s3_buckets() {
    if [ "$DELETE_S3" != "yes" ]; then
        echo "Skipping S3 bucket deletion"
        return
    fi

    echo "Deleting S3 buckets..."

    if [ -n "$LOGS_BUCKET" ]; then
        echo "  Deleting logs bucket: $LOGS_BUCKET"
        aws s3 rb "s3://$LOGS_BUCKET" --force || echo "  Warning: Could not delete logs bucket"
    fi

    if [ -n "$ATHENA_BUCKET" ]; then
        echo "  Deleting Athena results bucket: $ATHENA_BUCKET"
        aws s3 rb "s3://$ATHENA_BUCKET" --force || echo "  Warning: Could not delete Athena bucket"
    fi

    if [ -n "$RULES_BUCKET" ]; then
        echo "  Deleting rules bucket: $RULES_BUCKET"
        aws s3 rb "s3://$RULES_BUCKET" --force || echo "  Warning: Could not delete rules bucket"
    fi

    echo ""
}

cleanup_state_bucket() {
    if [ "$DELETE_S3" != "yes" ]; then
        echo "Skipping state bucket cleanup"
        return
    fi

    read -p "Delete Terraform state bucket? (yes/no): " DELETE_STATE

    if [ "$DELETE_STATE" == "yes" ]; then
        if [ -f "$PROJECT_ROOT/infrastructure/aws/terraform/backend.tf" ]; then
            STATE_BUCKET=$(grep 'bucket' "$PROJECT_ROOT/infrastructure/aws/terraform/backend.tf" | cut -d'"' -f2)

            if [ -n "$STATE_BUCKET" ]; then
                echo "  Emptying state bucket: $STATE_BUCKET"
                aws s3 rm "s3://$STATE_BUCKET" --recursive || true

                echo "  Deleting state bucket: $STATE_BUCKET"
                aws s3 rb "s3://$STATE_BUCKET" || true
            fi
        fi
    fi

    echo ""
}

cleanup_local_files() {
    echo "Cleaning up local files..."

    rm -f "$PROJECT_ROOT/terraform-outputs.json"
    rm -f "$PROJECT_ROOT/infrastructure/aws/terraform/backend.tf"
    rm -f "$PROJECT_ROOT/infrastructure/aws/terraform/tfplan"
    rm -f "$PROJECT_ROOT/infrastructure/aws/terraform/.terraform.lock.hcl"
    rm -rf "$PROJECT_ROOT/infrastructure/aws/terraform/.terraform"
    rm -rf "$PROJECT_ROOT/build"

    echo "  Local files cleaned"
    echo ""
}

print_summary() {
    echo "=========================================="
    echo "Destruction Complete"
    echo "=========================================="
    echo ""
    echo "All Mantissa Log infrastructure has been destroyed."
    echo ""

    if [ "$DELETE_S3" == "yes" ]; then
        echo "All S3 buckets and log data have been deleted."
    else
        echo "S3 buckets were preserved. You can manually delete them if needed:"
        [ -n "$LOGS_BUCKET" ] && echo "  - $LOGS_BUCKET"
        [ -n "$ATHENA_BUCKET" ] && echo "  - $ATHENA_BUCKET"
        [ -n "$RULES_BUCKET" ] && echo "  - $RULES_BUCKET"
    fi

    echo ""
}

main() {
    confirm_destruction
    get_bucket_names
    empty_s3_buckets
    destroy_infrastructure
    delete_s3_buckets
    cleanup_state_bucket
    cleanup_local_files
    print_summary
}

main
