resource "aws_athena_named_query" "normalized_auth_events" {
  name      = "create_normalized_auth_events_view"
  database  = aws_glue_catalog_database.main.name
  workgroup = aws_athena_workgroup.main.name
  query     = <<-SQL
    CREATE OR REPLACE VIEW normalized_auth_events AS
    SELECT
      eventtime AS timestamp,
      useridentity.username AS user,
      sourceipaddress AS source_ip,
      eventname AS action,
      CASE
        WHEN errorcode IS NULL THEN 'success'
        ELSE 'failure'
      END AS result,
      eventsource AS service,
      errorcode,
      errormessage,
      awsregion AS region,
      CAST(ROW(
        eventversion,
        eventtime,
        eventsource,
        eventname,
        awsregion,
        sourceipaddress,
        useragent,
        useridentity,
        requestparameters,
        responseelements,
        errorcode,
        errormessage
      ) AS JSON) AS raw_event
    FROM cloudtrail_logs
    WHERE eventname IN (
      'ConsoleLogin',
      'AssumeRole',
      'GetSessionToken',
      'CreateAccessKey',
      'UpdateAccessKey',
      'DeleteAccessKey',
      'ChangePassword',
      'CreateUser',
      'DeleteUser',
      'AttachUserPolicy',
      'DetachUserPolicy',
      'PutUserPolicy',
      'DeleteUserPolicy'
    )
  SQL
}

resource "aws_athena_named_query" "normalized_network_events" {
  name      = "create_normalized_network_events_view"
  database  = aws_glue_catalog_database.main.name
  workgroup = aws_athena_workgroup.main.name
  query     = <<-SQL
    CREATE OR REPLACE VIEW normalized_network_events AS
    SELECT
      from_unixtime(start) AS timestamp,
      srcaddr AS source_ip,
      dstaddr AS dest_ip,
      srcport AS source_port,
      dstport AS dest_port,
      CASE protocol
        WHEN 6 THEN 'TCP'
        WHEN 17 THEN 'UDP'
        WHEN 1 THEN 'ICMP'
        ELSE CAST(protocol AS VARCHAR)
      END AS protocol,
      bytes,
      action,
      log_status,
      interface_id,
      account_id
    FROM vpc_flow_logs
    WHERE log_status = 'OK'
  SQL
}
