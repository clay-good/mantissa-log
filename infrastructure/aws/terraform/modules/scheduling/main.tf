resource "aws_cloudwatch_event_rule" "detection_engine" {
  name                = "${var.name_prefix}-detection-schedule"
  description         = "Trigger detection engine on schedule"
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "detection_engine" {
  rule      = aws_cloudwatch_event_rule.detection_engine.name
  target_id = "DetectionEngineLambda"
  arn       = var.detection_engine_arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = var.detection_engine_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detection_engine.arn
}
