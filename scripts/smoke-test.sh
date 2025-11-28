#!/bin/bash

set -e

TERRAFORM_OUTPUTS=$1

if [ -z "$TERRAFORM_OUTPUTS" ] || [ ! -f "$TERRAFORM_OUTPUTS" ]; then
    echo "ERROR: Terraform outputs file not provided or not found"
    echo "Usage: $0 <terraform-outputs.json>"
    exit 1
fi

echo "Running smoke tests..."
echo ""

TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local TEST_NAME=$1
    local TEST_COMMAND=$2

    echo -n "  Testing $TEST_NAME... "

    if eval "$TEST_COMMAND" > /dev/null 2>&1; then
        echo "PASS"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo "FAIL"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

get_output() {
    local KEY=$1
    grep -o "\"$KEY[^:]*:[^\"]*\"[^\"]*\"" "$TERRAFORM_OUTPUTS" | cut -d'"' -f4
}

test_s3_buckets() {
    echo "S3 Buckets:"

    LOGS_BUCKET=$(get_output "logs_bucket")
    if [ -n "$LOGS_BUCKET" ]; then
        run_test "Logs bucket exists" "aws s3 ls s3://$LOGS_BUCKET"
        run_test "Logs bucket encryption enabled" "aws s3api get-bucket-encryption --bucket $LOGS_BUCKET"
        run_test "Logs bucket public access blocked" "aws s3api get-public-access-block --bucket $LOGS_BUCKET"
    else
        echo "  WARNING: Logs bucket output not found"
    fi

    ATHENA_BUCKET=$(get_output "athena_results_bucket")
    if [ -n "$ATHENA_BUCKET" ]; then
        run_test "Athena results bucket exists" "aws s3 ls s3://$ATHENA_BUCKET"
    fi

    echo ""
}

test_glue_catalog() {
    echo "Glue Data Catalog:"

    DATABASE_NAME=$(get_output "database_name")
    if [ -n "$DATABASE_NAME" ]; then
        run_test "Glue database exists" "aws glue get-database --name $DATABASE_NAME"

        TABLES=$(aws glue get-tables --database-name "$DATABASE_NAME" --query 'TableList[].Name' --output text 2>/dev/null)
        if [ -n "$TABLES" ]; then
            echo "  Found tables: $TABLES"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo "  WARNING: No tables found in database"
        fi
    else
        echo "  WARNING: Database name output not found"
    fi

    echo ""
}

test_lambda_functions() {
    echo "Lambda Functions:"

    DETECTION_ENGINE=$(get_output "detection_engine_function_name")
    if [ -n "$DETECTION_ENGINE" ]; then
        run_test "Detection engine function exists" "aws lambda get-function --function-name $DETECTION_ENGINE"
        run_test "Detection engine has execution role" "aws lambda get-function-configuration --function-name $DETECTION_ENGINE --query 'Role'"
    fi

    LLM_QUERY=$(get_output "llm_query_function_name")
    if [ -n "$LLM_QUERY" ]; then
        run_test "LLM query function exists" "aws lambda get-function --function-name $LLM_QUERY"
    fi

    ALERT_ROUTER=$(get_output "alert_router_function_name")
    if [ -n "$ALERT_ROUTER" ]; then
        run_test "Alert router function exists" "aws lambda get-function --function-name $ALERT_ROUTER"
    fi

    echo ""
}

test_dynamodb_tables() {
    echo "DynamoDB Tables:"

    STATE_TABLE=$(get_output "state_table_name")
    if [ -n "$STATE_TABLE" ]; then
        run_test "State table exists" "aws dynamodb describe-table --table-name $STATE_TABLE"
        run_test "State table has TTL enabled" "aws dynamodb describe-time-to-live --table-name $STATE_TABLE --query 'TimeToLiveDescription.TimeToLiveStatus' --output text | grep -q ENABLED"
    fi

    echo ""
}

test_eventbridge_rules() {
    echo "EventBridge Rules:"

    DETECTION_RULE=$(get_output "detection_schedule_rule_name")
    if [ -n "$DETECTION_RULE" ]; then
        run_test "Detection schedule rule exists" "aws events describe-rule --name $DETECTION_RULE"
        run_test "Detection schedule rule is enabled" "aws events describe-rule --name $DETECTION_RULE --query 'State' --output text | grep -q ENABLED"
    fi

    echo ""
}

test_cognito() {
    echo "Cognito:"

    USER_POOL=$(get_output "user_pool_id")
    if [ -n "$USER_POOL" ]; then
        run_test "User pool exists" "aws cognito-idp describe-user-pool --user-pool-id $USER_POOL"
    fi

    USER_POOL_CLIENT=$(get_output "user_pool_client_id")
    if [ -n "$USER_POOL_CLIENT" ] && [ -n "$USER_POOL" ]; then
        run_test "User pool client exists" "aws cognito-idp describe-user-pool-client --user-pool-id $USER_POOL --client-id $USER_POOL_CLIENT"
    fi

    echo ""
}

test_api_gateway() {
    echo "API Gateway:"

    API_ENDPOINT=$(get_output "api_endpoint")
    if [ -n "$API_ENDPOINT" ]; then
        echo "  API Endpoint: $API_ENDPOINT"

        run_test "API endpoint is accessible" "curl -sf -o /dev/null -w '%{http_code}' $API_ENDPOINT/health | grep -q '200\\|401\\|403'"
    else
        echo "  WARNING: API endpoint output not found"
    fi

    echo ""
}

test_athena_workgroup() {
    echo "Athena:"

    WORKGROUP=$(get_output "athena_workgroup_name")
    if [ -n "$WORKGROUP" ]; then
        run_test "Athena workgroup exists" "aws athena get-work-group --work-group $WORKGROUP"
    fi

    echo ""
}

test_simple_query() {
    echo "Query Execution Test:"

    DATABASE_NAME=$(get_output "database_name")
    WORKGROUP=$(get_output "athena_workgroup_name")
    ATHENA_BUCKET=$(get_output "athena_results_bucket")

    if [ -n "$DATABASE_NAME" ] && [ -n "$WORKGROUP" ] && [ -n "$ATHENA_BUCKET" ]; then
        echo -n "  Testing Athena query execution... "

        QUERY_ID=$(aws athena start-query-execution \
            --query-string "SELECT 1" \
            --query-execution-context Database="$DATABASE_NAME" \
            --work-group "$WORKGROUP" \
            --result-configuration OutputLocation="s3://$ATHENA_BUCKET/smoke-test/" \
            --query 'QueryExecutionId' \
            --output text 2>/dev/null)

        if [ -n "$QUERY_ID" ]; then
            sleep 2

            STATUS=$(aws athena get-query-execution \
                --query-execution-id "$QUERY_ID" \
                --query 'QueryExecution.Status.State' \
                --output text 2>/dev/null)

            if [ "$STATUS" == "SUCCEEDED" ] || [ "$STATUS" == "RUNNING" ]; then
                echo "PASS"
                TESTS_PASSED=$((TESTS_PASSED + 1))
            else
                echo "FAIL (Status: $STATUS)"
                TESTS_FAILED=$((TESTS_FAILED + 1))
            fi
        else
            echo "FAIL (Could not start query)"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    else
        echo "  SKIP (Missing required outputs)"
    fi

    echo ""
}

print_summary() {
    echo "=========================================="
    echo "Smoke Test Summary"
    echo "=========================================="
    echo ""
    echo "Tests Passed: $TESTS_PASSED"
    echo "Tests Failed: $TESTS_FAILED"
    echo ""

    if [ $TESTS_FAILED -eq 0 ]; then
        echo "All smoke tests passed!"
        echo ""
        return 0
    else
        echo "Some tests failed. Please review the output above."
        echo ""
        return 1
    fi
}

main() {
    test_s3_buckets
    test_glue_catalog
    test_lambda_functions
    test_dynamodb_tables
    test_eventbridge_rules
    test_cognito
    test_api_gateway
    test_athena_workgroup
    test_simple_query

    print_summary
}

main
