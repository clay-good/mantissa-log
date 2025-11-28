resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true

  finding_publishing_frequency = var.guardduty_finding_frequency

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = var.enable_guardduty_kubernetes
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = var.enable_guardduty_malware_protection
        }
      }
    }
  }
}

resource "aws_guardduty_publishing_destination" "s3" {
  count           = var.enable_guardduty ? 1 : 0
  detector_id     = aws_guardduty_detector.main[0].id
  destination_arn = var.logs_bucket_arn
  kms_key_arn     = var.kms_key_arn != "" ? var.kms_key_arn : null

  destination_type = "S3"

  depends_on = [aws_guardduty_detector.main]
}

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  count       = var.enable_guardduty_realtime ? 1 : 0
  name        = "${var.name_prefix}-guardduty-findings"
  description = "Capture GuardDuty findings for real-time alerting"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = var.guardduty_severity_filter
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_lambda" {
  count = var.enable_guardduty_realtime ? 1 : 0
  rule  = aws_cloudwatch_event_rule.guardduty_findings[0].name
  arn   = var.alert_router_lambda_arn
}

resource "aws_lambda_permission" "guardduty_invoke" {
  count         = var.enable_guardduty_realtime ? 1 : 0
  statement_id  = "AllowExecutionFromGuardDuty"
  action        = "lambda:InvokeFunction"
  function_name = var.alert_router_lambda_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings[0].arn
}
