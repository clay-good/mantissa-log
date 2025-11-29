resource "aws_cloudwatch_event_rule" "detection_tuner" {
  name                = "${var.name_prefix}-detection-tuner"
  description         = "Trigger detection tuner weekly"
  schedule_expression = var.detection_tuner_schedule
}

resource "aws_cloudwatch_event_target" "detection_tuner" {
  rule      = aws_cloudwatch_event_rule.detection_tuner.name
  target_id = "DetectionTunerLambda"
  arn       = var.detection_tuner_arn
}

resource "aws_lambda_permission" "allow_eventbridge_detection_tuner" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = var.detection_tuner_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detection_tuner.arn
}
