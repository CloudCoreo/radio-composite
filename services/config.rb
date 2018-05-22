coreo_aws_rule "ec2-ip-address-whitelisted" do
    action :define
    service :ec2
    link "http://kb.cloudcoreo.com/mydoc_ec2-ip-address-whitelisted.html"
    display_name "Security Group contains IP address"
    description "Security Group contains IP address"
    category "Security"
    suggested_action "Review Security Group to ensure that the host ip address added is to allowed access."
    level "Low"
    objectives ["security_groups"]
    audit_objects ["object.security_groups.ip_permissions.ip_ranges.cidr_ip"]
    operators ["=~"]
    raise_when [/\/32/]
    id_map "object.security_groups.group_id"
    meta_rule_query <<~QUERY
    {
      ranges as var(func: %<ip_permission_filter>s) {
        range as ip_ranges
      }
      query(func: %<security_group_filter>s) @cascade {
        %<default_predicates>s
        group_id
        relates_to @filter(uid(ranges) AND eq(val(range), "[{:cidr_ip=>\\\"1.0.0.0/32\\\"}]")) {
          %<default_predicates>s
        }
      }
    }
    QUERY
    meta_rule_node_triggers ({'security_group' => [], 'ip_permission' => ['ip_ranges']})
end

coreo_aws_rule_runner "advise-ec2" do
  service :ec2
  action :run
  rules (${AUDIT_AWS_EC2_ALERT_LIST})
  regions ${AUDIT_AWS_EC2_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_aws_rule "s3-allusers-read" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-allusers-read.html"
  display_name "All users can list the affected bucket"
  description "Bucket has permissions (ACL) which let anyone list the bucket contents."
  category "Security"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to list the bucket."
  level "High"
  meta_nist_171_id "3.1.3"
  objectives     ["buckets", "bucket_acl", "bucket_acl"]
  call_modifiers [{}, {:bucket => "buckets.name"}, {}]
  audit_objects ["", "object.grants.grantee.uri", "object.grants.permission"]
  operators     ["", "=~", "=~"]
  raise_when    ["", /AllUsers/i, /\bread\b/i]
  id_map "modifiers.bucket"
  meta_rule_query <<~QUERY
  {
    b as var(func: %<bucket_filter>s) @cascade {
      ba as relates_to @filter(%<bucket_acl_filter>s) {
        bag as relates_to @filter(%<bucket_acl_grant_filter>s) {
          p as permission
          g as relates_to @filter(%<grantee_filter>s) {
            u as uri
          }
        }
      }
    }
    query(func: uid(b)) @cascade {
      %<default_predicates>s
      relates_to @filter(uid(ba)) {
        %<default_predicates>s
        relates_to @filter(uid(bag) AND eq(val(p), "READ")) {
          %<default_predicates>s
          permission
          relates_to @filter(uid(g) AND eq(val(u), "http://acs.amazonaws.com/groups/global/AllUsers")) {
            %<default_predicates>s
            uri
          }
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                            'bucket' => [],
                            'bucket_acl' => [],
                            'bucket_acl_grant' => ['permission'],
                            'grantee' => ['uri']
                          })
end


coreo_aws_rule_runner "advise-s3" do
  service :s3
  action :run
  regions ${AUDIT_AWS_EC2_REGIONS}
  rules (${AUDIT_AWS_S3_ALERT_LIST})
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_aws_rule "rds-short-backup-retention-period" do
  action :define
  service :rds
  link "http://kb.cloudcoreo.com/mydoc_rds-short-backup-retention-period.html"
  display_name "RDS short backup retention period"
  description "The affected RDS database has a short backup retention period (less than 30 days)."
  category "Dataloss"
  suggested_action "Modify the backup retention period to increase it to greater than 30 days."
  level "Low"
  meta_nist_171_id "3.8.9"
  objectives ["db_instances"]
  audit_objects ["object.db_instances.backup_retention_period"]
  operators ["<"]
  raise_when [30]
  id_map "object.db_instances.db_instance_identifier"
  meta_rule_query <<~QUERY
  {
    dbs as var(func: %<db_instance_filter>s) {
      brp as backup_retention_period
      r1 as relates_to @filter(NOT has(db_snapshot)) {
        r2 as relates_to @filter(NOT has(db_instance))
      }
    }
    query(func: uid(dbs)) @filter(lt(val(brp), 30)) {
      %<default_predicates>s
      db_instance_identifier
      relates_to @filter(uid(r1)) {
        %<default_predicates>s
        relates_to @filter(uid(r2)) {
          %<default_predicates>s
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'db_instance' => ['backup_retention_period']
  })
end

coreo_aws_rule "rds-no-auto-minor-version-upgrade" do
  action :define
  service :rds
  link "http://kb.cloudcoreo.com/mydoc_rds-no-auto-minor-version-upgrade.html"
  display_name "RDS not set to automatically upgrade"
  description "RDS is not set to automatically upgrade minor versions on your database instance."
  category "Reliability"
  suggested_action "Consider whether you would like AWS to automatically upgrade minor versions on your database instance. Modify your settings to allow minor version upgrades if possible."
  level "High"
  objectives ["db_instances"]
  audit_objects ["object.db_instances.auto_minor_version_upgrade"]
  operators ["=="]
  raise_when [false]
  id_map "object.db_instances.db_instance_identifier"
  meta_rule_query <<~QUERY
  {
    dbs as var(func: %<db_instance_filter>s) {
      amvu as auto_minor_version_upgrade
      r1 as relates_to @filter(NOT has(db_snapshot)) {
        r2 as relates_to @filter(NOT has(db_instance))
      }
    }
    query(func: uid(dbs)) @filter(eq(val(amvu), false)) {
      %<default_predicates>s
      db_instance_identifier
      relates_to @filter(uid(r1)) {
        %<default_predicates>s
        relates_to @filter(uid(r2)) {
          %<default_predicates>s
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'db_instance' => ['auto_minor_version_upgrade']
  })
end

coreo_aws_rule "rds-db-instance-unencrypted" do
  action :define
  service :rds
  link "http://kb.cloudcoreo.com/mydoc_rds-db-snapshot-unencrypted.html"
  display_name "RDS DB instances are not encrypted"
  description "The affected RDS DB instance is not encrypted."
  category "Security"
  suggested_action "Consider whether the affected RDS DB instance should be encrypted. If not, modify the option which encrypts your RDS DB instance"
  level "High"
  meta_nist_171_id "3.13.2"
  objectives ["db_instances"]
  audit_objects ["object.db_instances.storage_encrypted"]
  operators ["=="]
  raise_when [false]
  id_map "object.db_instances.db_instance_identifier"
  meta_rule_query <<~QUERY
  {
    dbs as var(func: %<db_instance_filter>s) {
      se as storage_encrypted
      r1 as relates_to @filter(NOT has(db_snapshot)) {
        r2 as relates_to @filter(NOT has(db_instance))
      }
    }
    query(func: uid(dbs)) @filter(eq(val(se), false)) {
      %<default_predicates>s
      db_instance_identifier
      relates_to @filter(uid(r1)) {
        %<default_predicates>s
        relates_to @filter(uid(r2)) {
          %<default_predicates>s
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'db_instance' => ['storage_encrypted']
  })
end

coreo_aws_rule "rds-db-snapshot-unencrypted" do
  action :define
  service :rds
  link "http://kb.cloudcoreo.com/mydoc_rds-db-snapshot-unencrypted.html"
  display_name "RDS snapshots are not encrypted"
  description "The affected RDS snaphsot is not encrypted."
  category "Security"
  suggested_action "Consider whether the affected RDS snapshot should be encrypted. If not, modify the option which encrypts your RDS snapshot"
  level "High"
  meta_nist_171_id "3.13.2"
  objectives ["db_snapshots"]
  audit_objects ["object.db_snapshots.encrypted"]
  operators ["=="]
  raise_when [false]
  id_map "object.db_snapshots.db_snapshot_identifier"
  meta_rule_query <<~QUERY
  {
    s as var(func: %<db_snapshot_filter>s) {
      e as encrypted
      r1 as relates_to {
        r2 as relates_to @filter(NOT has(db_snapshot))
      }
    }
    query(func: uid(s)) @filter(eq(val(e), false)) {
      %<default_predicates>s
      db_snapshot_identifier
      relates_to @filter(uid(r1)) {
        %<default_predicates>s
        relates_to @filter(uid(r2)) {
          %<default_predicates>s
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'db_snapshot' => ['encrypted']
  })
end

coreo_aws_rule "rds-db-publicly-accessible" do
  action :define
  service :rds
  link "http://kb.cloudcoreo.com/mydoc_rds-db-publicly-accessible.html"
  display_name "RDS is publicly accessible to the world"
  description "The affected RDS database is publicly accessible to the world."
  category "Security"
  suggested_action "Consider whether the affected RDS database should be publicly accessible to the world. If not, modify the option which enables your RDS database to become publicly accessible."
  level "High"
  meta_nist_171_id "3.1.22, 3.13.2"
  objectives ["db_instances"]
  audit_objects ["object.db_instances.publicly_accessible"]
  operators ["=="]
  raise_when [true]
  id_map "object.db_instances.db_instance_identifier"
  meta_rule_query <<~QUERY
  {
    dbs as var(func: %<db_instance_filter>s) {
      pa as publicly_accessible
      r1 as relates_to @filter(NOT has(db_snapshot)) {
        r2 as relates_to @filter(NOT has(db_instance))
      }
    }
    query(func: uid(dbs)) @filter(eq(val(pa), true)) {
      %<default_predicates>s
      db_instance_identifier
      relates_to @filter(uid(r1)) {
        %<default_predicates>s
        relates_to @filter(uid(r2)) {
          %<default_predicates>s
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'db_instance' => ['publicly_accessible']
  })
end

coreo_aws_rule_runner "advise-rds" do
  rules ${AUDIT_AWS_RDS_ALERT_LIST}
  service :rds
  action :run
  regions ${AUDIT_AWS_RDS_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end
