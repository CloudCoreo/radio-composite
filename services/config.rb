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
      s as var(func: has(security_group)) @cascade {
        i as relates_to @filter(has(ip_permission)) {
            range as ip_ranges
        }
      }
      sg as var(func: uid(s)) @cascade {
        ip as relates_to @filter((uid(i) AND eq(val(range), "[{:cidr_ip=>\\\"1.0.0.0/32\\\"}]")))
      }
      query(func: uid(sg)) {
        %<default_predicates>s
        group_id
        relates_to @filter(uid(ip) OR NOT has(ip_permission)) {
          %<default_predicates>s
          ip_ranges
        }
      }
    }
    QUERY
    meta_rule_node_triggers ({
                              'security_group' => [], 
                              'ip_permission' => ['ip_ranges']
                            })
end

coreo_aws_rule "ec2-unrestricted-traffic" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-unrestricted-traffic.html"
  display_name "Security group allows unrestricted traffic"
  description "All IP addresses are allowed to access resources in a specific security group."
  category "Security"
  suggested_action "Restrict access to the minimum specific set of IP address or ports necessary."
  level "Low"
  meta_nist_171_id "3.4.7, 3.4.8"
  objectives ["security_groups"]
  audit_objects ["object.security_groups.ip_permissions.ip_ranges.cidr_ip"]
  operators ["=="]
  raise_when ["0.0.0.0/0"]
  id_map "object.security_groups.group_id"
  meta_rule_query <<~QUERY
  {
    s as var(func: has(security_group)) @cascade {
      i as relates_to @filter(has(ip_permission)) {
          range as ip_ranges
      }
    }
    sg as var(func: uid(s)) @cascade {
      ip as relates_to @filter((uid(i) AND eq(val(range), "[{:cidr_ip=>\\\"0.0.0.0/0\\\"}]")))
    }
    query(func: uid(sg)) {
      %<default_predicates>s
      group_id
      relates_to @filter(uid(ip) OR NOT has(ip_permission)) {
        %<default_predicates>s
        ip_ranges
      }
    }
  }
  QUERY
  meta_rule_node_triggers ({
                             'security_group' => [],
                             'ip_permission' => ['ip_ranges']
                           })
end

coreo_aws_rule "ec2-vpc-flow-logs" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_ec2-vpc-flow-logs.html"
  display_name "Ensure VPC flow logging is enabled in all VPCs (Scored)"
  suggested_action "VPC Flow Logs be enabled for packet 'Rejects' for VPCs."
  description "VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs."
  level "Low"
  meta_cis_id "4.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.13.1, 3.13.6"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  {
    vpcs as var(func: %<vpc_filter>s) @cascade {
      fl as relates_to @filter(%<flow_log_filter>s) {
        fls as flow_log_status
      }
    }
    v as var(func: uid(vpcs)) @cascade {
      relates_to @filter(uid(fl) AND eq(val(fls), "ACTIVE"))
    }
    query(func: has(vpc)) @filter(NOT uid(v)) {
      %<default_predicates>s
      relates_to @filter(NOT has(flow_log)) {
        %<default_predicates>s
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                            'vpc' => [],
                            'flow_log' => ['flow_log_status']
                          })
end

coreo_aws_rule_runner "advise-ec2" do
  service :ec2
  action :run
  rules (${AUDIT_AWS_EC2_ALERT_LIST})
  regions ${AUDIT_AWS_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_aws_rule "s3-allusers-full-control" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-allusers-full-control.html"
  display_name "All users can do anything with the affected bucket"
  description "Bucket has permissions (ACL) which let all users do anything with the bucket and/or it's contents."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to have full control."
  level "High"
  meta_nist_171_id "3.1.22, 3.1.3"
  objectives     ["buckets", "bucket_acl", "bucket_acl"]
  call_modifiers [{}, {:bucket => "buckets.name"}, {}]
  audit_objects ["", "object.grants.grantee.uri", "object.grants.permission"]
  operators     ["", "=~", "=~"]
  raise_when    ["", /AllUsers/i, /\bfull_control\b/i]
  id_map "modifiers.bucket"
  meta_rule_query <<~QUERY
  {
    b as var(func: %<bucket_filter>s)  @cascade {
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
        relates_to @filter(uid(bag) AND eq(val(p), "FULL_CONTROL")) {
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

coreo_aws_rule "s3-allusers-write" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-allusers-write.html"
  display_name "All users can write to the affected bucket"
  description "Bucket has permissions (ACL) which let all users write to the bucket."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to write."
  level "High"
  meta_nist_171_id "3.1.3"
  objectives     ["buckets", "bucket_acl", "bucket_acl"]
  call_modifiers [{}, {:bucket => "buckets.name"}, {}]
  audit_objects ["", "object.grants.grantee.uri", "object.grants.permission"]
  operators     ["", "=~", "=~"]
  raise_when    ["", /AllUsers/i, /\bwrite\b/i]
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
        relates_to @filter(uid(bag) AND eq(val(p), "WRITE")) {
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

coreo_aws_rule "s3-allusers-write-acp" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-allusers-write-acp.html"
  display_name "All users can write the bucket ACP / ACL"
  description "Bucket has permissions (ACP / ACL) which let all users modify the permissions."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows everyone to edit permissions."
  level "High"
  meta_nist_171_id "3.1.3"
  objectives     ["buckets", "bucket_acl", "bucket_acl"]
  call_modifiers [{}, {:bucket => "buckets.name"}, {}]
  audit_objects ["", "object.grants.grantee.uri", "object.grants.permission"]
  operators     ["", "=~", "=~"]
  raise_when    ["", /AllUsers/i, /\bwrite_acp\b/i]
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
        relates_to @filter(uid(bag) AND eq(val(p), "WRITE_ACP")) {
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

coreo_aws_rule "s3-authenticatedusers-write" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-authenticatedusers-write.html"
  display_name "All authenticated AWS users can write to the affected bucket"
  description "Bucket has permissions (ACL) which let any AWS users write to the bucket."
  category "Dataloss"
  suggested_action "Remove the entry from the bucket permissions that allows 'Any Authenticated AWS User' to write."
  level "High"
  meta_nist_171_id "3.1.3"
  objectives     ["buckets", "bucket_acl", "bucket_acl"]
  call_modifiers [{}, {:bucket => "buckets.name"}, {}]
  audit_objects ["", "object.grants.grantee.uri", "object.grants.permission"]
  operators     ["", "=~", "=~"]
  raise_when    ["", /AuthenticatedUsers/i, /\bwrite\b/i]
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
        relates_to @filter(uid(bag) AND eq(val(p), "WRITE")) {
          %<default_predicates>s
          permission
          relates_to @filter(uid(g) AND eq(val(u), "http://acs.amazonaws.com/groups/global/AuthenticatedUsers")) {
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

coreo_aws_rule "s3-authenticatedusers-write-acp" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-authenticatedusers-write-acp.html"
  display_name "All authenticated AWS users can change bucket permissions"
  description "Bucket has permissions ( ACP / ACL) which let any AWS user modify the permissions."
  category "Dataloss"
  suggested_action "Remove the bucket permissions (ACP / ACL) that allows 'Any Authenticated AWS User' to edit permissions."
  level "High"
  meta_nist_171_id "3.1.3"
  objectives     ["buckets", "bucket_acl", "bucket_acl"]
  call_modifiers [{}, {:bucket => "buckets.name"}, {}]
  audit_objects ["", "object.grants.grantee.uri", "object.grants.permission"]
  operators     ["", "=~", "=~"]
  raise_when    ["", /AuthenticatedUsers/i, /\bwrite_acp\b/i]
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
        relates_to @filter(uid(bag) AND eq(val(p), "WRITE_ACP")) {
          %<default_predicates>s
          permission
          relates_to @filter(uid(g) AND eq(val(u), "http://acs.amazonaws.com/groups/global/AuthenticatedUsers")) {
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

coreo_aws_rule "s3-logging-disabled" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-logging-disabled.html"
  display_name "S3 bucket logging not enabled"
  description "S3 bucket logging has not been enabled for the affected resource."
  category "Audit"
  suggested_action "Enable logging on your S3 buckets."
  level "Low"
  meta_nist_171_id "3.1.2"
  objectives     ["buckets", "bucket_logging"]
  call_modifiers [{}, {:bucket => "buckets.name"}]
  audit_objects ["", ""]
  operators     ["", "=="]
  raise_when    ["", nil]
  id_map "modifiers.bucket"
  meta_rule_query <<~QUERY
  {
    b as var(func: has(bucket)) @cascade {
      relates_to @filter(has(bucket_logging))
    }
    query(func: %<bucket_filter>s) @filter(NOT uid(b)) {
      %<default_predicates>s
      relates_to @filter(NOT has(bucket_policy)) {
        %<default_predicates>s
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                              'bucket' => [],
                              'bucket_logging' => []
                          })
end

coreo_aws_rule "s3-authenticatedusers-read" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_s3-authenticatedusers-read.html"
  display_name "All authenticated AWS users can read the affected bucket"
  description "Bucket has permissions (ACL) which let any AWS user list the bucket contents."
  category "Security"
  suggested_action "Remove the entry from the bucket permissions that allows 'Any Authenticated AWS User' to list the bucket."
  level "High"
  meta_nist_171_id "3.1.3"
  objectives     ["buckets", "bucket_acl", "bucket_acl"]
  call_modifiers [{}, {:bucket => "buckets.name"}, {}]
  audit_objects ["", "object.grants.grantee.uri", "object.grants.permission"]
  operators     ["", "=~", "=~"]
  raise_when    ["", /AuthenticatedUsers/i, /\bread\b/i]
  id_map "modifiers.bucket"
  meta_rule_query <<~QUERY
  {
    b as var(func: %<bucket_filter>s)  {
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
          relates_to @filter(uid(g) AND eq(val(u), "http://acs.amazonaws.com/groups/global/AuthenticatedUsers")) {
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
  regions ["PLAN::region"]
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
  regions ${AUDIT_AWS_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_aws_rule "iam-inventory-users" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM User Inventory"
  description "This rule performs an inventory on all IAM Users in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["users"]
  audit_objects ["object.users.user_name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.users.user_name"
end

coreo_aws_rule "iam-inventory-roles" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Role Inventory"
  description "This rule performs an inventory on all IAM Roles in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["roles"]
  audit_objects ["object.roles.role_name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.roles.role_name"
end

coreo_aws_rule "iam-inventory-policies" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Policy Inventory"
  description "This rule performs an inventory on all IAM Policies in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["policies"]
  audit_objects ["object.policies.policy_name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.policies.policy_name"
end

coreo_aws_rule "iam-inventory-groups" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "IAM Group Inventory"
  description "This rule performs an inventory on all IAM User Groups in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["groups"]
  audit_objects ["object.groups.group_name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.groups.group_name"
end

coreo_aws_rule "iam-inventory-ec2-roles" do
  action :define
  service :ec2
  include_violations_in_count false
  display_name "IAM Inventory EC2 Instance Roles"
  description "This rule performs an inventory on all IAM roles for instances."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["instances"]
  audit_objects ["object.reservations.instances.iam_instance_profile.arn"]
  operators ["=~"]
  raise_when [//]
  id_map "object.reservations.instances.iam_instance_profile.arn"
end

coreo_aws_rule "iam-unusediamgroup" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-unusediamgroup.html"
  display_name "Unused or empty IAM group"
  description "There is an IAM group defined without any users in it and therefore unused."
  category "Access"
  suggested_action "Ensure that groups defined within IAM have active users in them. If the groups don't have active users or are not being used, delete the unused IAM group."
  level "Low"
  objectives ["groups", "group"]
  call_modifiers [{}, {:group_name => "objective[0].groups.group_name"}]
  formulas ["", "count"]
  audit_objects ["", "object.users"]
  operators ["", "=="]
  raise_when ["", 0]
  id_map "object.group.group_name"
  meta_rule_query <<~QUERY
  {
    query(func: %<group_filter>s) @cascade { 
      %<default_predicates>s
      relates_to @filter(%<user_filter>s AND NOT has(user)) 
    }
  }
  QUERY
  meta_rule_node_triggers({
                              'group' => [],
                              'user' => []
                          })
end

coreo_aws_rule "iam-multiple-keys" do
  action :define
  service :iam
  # link "http://kb.cloudcoreo.com/mydoc_iam-unusediamgroup.html"
  display_name "IAM User with multiple keys"
  description "There is an IAM User with multiple access keys"
  category "Access"
  suggested_action "Remove excess access keys"
  level "Low"
  objectives ["credential_report", "credential_report"]
  audit_objects ["object.content.access_key_1_active", "object.content.access_key_2_active"]
  operators ["=~", "=~" ]
  raise_when [/true/i, /true/i]
  id_map "object.content.user"
end

coreo_aws_rule "iam-root-multiple-keys" do
  action :define
  service :iam
  # link "http://kb.cloudcoreo.com/mydoc_iam-unusediamgroup.html"
  display_name "IAM Root user with multiple keys"
  description "There is are multiple access keys for root user"
  category "Access"
  suggested_action "Remove at least one set of access keys"
  level "Warning"
  meta_nist_171_id "3.1.5"
  id_map "object.content.user"
  objectives ["credential_report", "credential_report", "credential_report"]
  audit_objects ["object.content.user", "object.content.access_key_1_active", "object.content.access_key_2_active"]
  operators ["==", "=~", "=~" ]
  raise_when ["<root_account>", /true/i, /true/i]
end

coreo_aws_rule "iam-inactive-key-no-rotation" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-inactive-key-no-rotation.html"
  display_name "User Has Access Keys Inactive and Un-rotated"
  description "User has inactive keys that have not been rotated in the last 90 days."
  category "Access"
  suggested_action "If you regularly use the AWS access keys, we recommend that you also regularly rotate or delete them."
  level "Medium"
  meta_nist_171_id "3.5.9"
  id_map "modifiers.user_name"
  objectives ["users", "access_keys", "access_keys"]
  audit_objects ["", "object.access_key_metadata.status", "object.access_key_metadata.create_date"]
  call_modifiers [{}, {:user_name => "objective[0].users.user_name"}, {:user_name => "objective[0].users.user_name"}]
  operators ["", "==", "<"]
  raise_when ["", "Inactive", "90.days.ago"]
end

coreo_aws_rule "iam-active-key-no-rotation" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-active-key-no-rotation.html"
  display_name "User Has Access Keys Active and Un-rotated"
  description "User has active keys that have not been rotated in the last 90 days"
  category "Access"
  suggested_action "If you regularly use the AWS access keys, we recommend that you also regularly rotate or delete them."
  level "Medium"
  meta_cis_id "1.4"
  meta_cis_scored "true"
  meta_cis_level "1"
  id_map "modifiers.user_name"
  objectives ["users", "access_keys", "access_keys"]
  audit_objects ["", "object.access_key_metadata.status", "object.access_key_metadata.create_date"]
  call_modifiers [{}, {:user_name => "objective[0].users.user_name"}, {:user_name => "objective[0].users.user_name"}]
  operators ["", "==", "<"]
  raise_when ["", "Active", "90.days.ago"]
end

coreo_aws_rule "iam-missing-password-policy" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-missing-password-policy.html"
  display_name "Password policy doesn't exist"
  description "There currently isn't a password policy to require a certain password length, password expiration, prevent password reuse, and more."
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  level "High"
  meta_nist_171_id "3.5.7"
  objectives ["account_password_policy"]
  audit_objects ["object"]
  operators ["=="]
  raise_when [nil]
  id_map "static.password_policy"
end

coreo_aws_rule "iam-passwordreuseprevention" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-passwordreuseprevention.html"
  display_name "Users can reuse old passwords"
  description "The current password policy doesn't prevent users from reusing their old passwords."
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  meta_cis_id "1.10"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.5.8"
  level "High"
  objectives ["account_password_policy"]
  audit_objects ["object.password_policy"]
  formulas ["include?(password_reuse_prevention)"]
  operators ["!="]
  raise_when [true]
  id_map "static.password_policy"
  meta_rule_query <<~QUERY
  { 
    pp as var(func: has(password_policy)) @filter(NOT has(password_reuse_prevention)) { 
    }
  
    np as var(func: has(password_policy)) @filter( has(password_reuse_prevention)) { 
       prp as password_reuse_prevention
    } 
      
    ap as var(func: uid(np)) @filter(eq(val(prp), false)) {
    }
        
    query(func: uid(ap, pp)){
      %<default_predicates>s
    }
      
  }
  QUERY
  meta_rule_node_triggers ({
      'password_policy' => ['password_reuse_prevention']
  })
end

coreo_aws_rule "iam-expirepasswords" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-expirepasswords.html"
  display_name "Passwords not set to expire"
  description "The current password policy doesn't require users to regularly change their passwords. User passwords are set to never expire."
  category "Access"
  suggested_action "Configure a strong password policy for your users so that passwords expire such that users must change their passwords periodically."
  meta_cis_id "1.11"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "High"
  objectives ["account_password_policy"]
  audit_objects ["object.password_policy.expire_passwords"]
  operators ["=="]
  raise_when ["false"]
  id_map "static.password_policy"
  meta_rule_query <<~QUERY
  {
    pp as var(func: %<password_policy_filter>s ) {
      is_expired as expire_passwords
    }
    query(func: uid(pp)) @filter(eq(val(is_expired), false)) {
      %<default_predicates>s
    }
  }
  QUERY
  meta_rule_node_triggers ({
      'password_policy' => ['expire_passwords']
  })
end

coreo_aws_rule "iam-no-mfa" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-no-mfa.html"
  display_name "Multi-Factor Authentication not enabled"
  description "Cloud user does not have Multi-Factor Authentication enabled on their cloud account."
  category "Security"
  suggested_action "Enable Multi-Factor Authentication for every cloud user."
  level "High"
  meta_nist_171_id "3.5.3, 3.7.5"
  id_map "object.content.user"
  objectives ["credential_report", "credential_report"]
  audit_objects ["object.content.password_enabled", "object.content.mfa_active"]
  operators ["=~", "=~" ]
  raise_when [/true/i, /false/i]
end

coreo_aws_rule "iam-root-active-password" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-root-active-password.html"
  display_name "Root user has active password"
  description "The root user has been logging in using a password."
  category "Security"
  suggested_action "Re-set your root account password, don't log in to your root account, and secure root account password in a safe place."
  level "High"
  meta_nist_171_id "3.1.6"
  id_map "object.content.user"
  objectives ["credential_report", "credential_report"]
  audit_objects ["object.content.user", "object.content.password_last_used"]
  operators ["==", ">"]
  raise_when ["<root_account>", "15.days.ago"]
end

coreo_aws_rule "iam-user-attached-policies" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-user-attached-policies.html"
  display_name "Account using inline policies"
  description "User account is using custom inline policies versus using IAM group managed policies."
  category "Access"
  suggested_action "Switch all inline policies to apply to IAM groups and assign users IAMs roles."
  meta_cis_id "1.16"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "Low"
  id_map "modifiers.user_name"
  objectives ["users", "user_policies"]
  formulas ["", "count"]
  call_modifiers [{}, {:user_name => "objective[0].users.user_name"}]
  audit_objects ["", "object.policy_names"]
  operators ["", ">"]
  raise_when ["", 0]
end

coreo_aws_rule "iam-password-policy-uppercase" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-password-policy-uppercase.html"
  display_name "Password policy doesn't require an uppercase letter"
  description "The password policy must require an uppercase letter to meet CIS standards"
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  meta_cis_id "1.5"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.5.7"
  level "Medium"
  objectives ["account_password_policy"]
  id_map "static.password_policy"
  audit_objects ["object.password_policy.require_uppercase_characters"]
  operators ["=="]
  raise_when [false]
  meta_rule_query <<~QUERY
  {
    pp as var(func: %<password_policy_filter>s ) {
      is_uppercase as require_uppercase_characters
    }
    query(func: uid(pp)) @filter(eq(val(is_uppercase), false)) {
      %<default_predicates>s
    }
  }
  QUERY
  meta_rule_node_triggers ({
      'password_policy' => ['require_uppercase_characters']
  })
end

coreo_aws_rule "iam-password-policy-lowercase" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-password-policy-lowercase.html"
  display_name "Password policy doesn't require an lowercase letter"
  description "The password policy must require an lowercase letter to meet CIS standards"
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  meta_cis_id "1.6"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "Medium"
  meta_nist_171_id "3.5.7"
  objectives ["account_password_policy"]
  id_map "static.password_policy"
  audit_objects ["object.password_policy.require_lowercase_characters"]
  operators ["=="]
  raise_when [false]
  meta_rule_query <<~QUERY
  {
    pp as var(func: %<password_policy_filter>s ) {
      is_lowercase as require_lowercase_characters
    }
    query(func: uid(pp)) @filter(eq(val(is_lowercase), false)) {
      %<default_predicates>s
    }
  }
  QUERY
  meta_rule_node_triggers ({
      'password_policy' => ['require_lowercase_characters']
  })
end

coreo_aws_rule "iam-password-policy-symbol" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-password-policy-symbol.html"
  display_name "Password policy doesn't require a symbol"
  description "The password policy must require a symbol to meet CIS standards"
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  meta_cis_id "1.7"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "Medium"
  meta_nist_171_id "3.5.7"
  objectives ["account_password_policy"]
  id_map "static.password_policy"
  audit_objects ["object.password_policy.require_symbols"]
  operators ["=="]
  raise_when [false]
  meta_rule_query <<~QUERY
  {
    pp as var(func: %<password_policy_filter>s ) {
      is_symbol as require_symbols
    }
    query(func: uid(pp)) @filter(eq(val(is_symbol), false)) {
      %<default_predicates>s
    }
  }
  QUERY
  meta_rule_node_triggers ({
      'password_policy' => ['require_symbols']
  })
end

coreo_aws_rule "iam-password-policy-number" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-password-policy-number.html"
  display_name "Password policy doesn't require a number"
  description "The password policy must require a number to meet CIS standards"
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  meta_cis_id "1.8"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "Medium"
  meta_nist_171_id "3.5.7"
  objectives ["account_password_policy"]
  id_map "static.password_policy"
  audit_objects ["object.password_policy.require_numbers"]
  operators ["=="]
  raise_when [false]
  meta_rule_query <<~QUERY
  {
    pp as var(func: %<password_policy_filter>s ) {
      is_number as require_numbers
    }
    query(func: uid(pp)) @filter(eq(val(is_number), false)) {
      %<default_predicates>s
    }
  }
  QUERY
  meta_rule_node_triggers ({
      'password_policy' => ['require_numbers']
  })
end

coreo_aws_rule "iam-password-policy-min-length" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-password-policy-min-length.html"
  display_name "Password policy doesn't require a minimum length of 14 characters"
  description "The password policy must require a minimum length of 14 characters to meet CIS standards"
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  meta_cis_id "1.9"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "Medium"
  meta_nist_171_id "3.5.7"
  objectives ["account_password_policy"]
  id_map "static.password_policy"
  audit_objects ["object.password_policy.minimum_password_length"]
  operators ["<"]
  raise_when [14]
  meta_rule_query <<~QUERY
  {
    pp as var(func: %<password_policy_filter>s ) {
      is_min_length as minimum_password_length
    }
    query(func: uid(pp)) @filter( lt(val(is_min_length), 14) ) {
      %<default_predicates>s
    }
  }
  QUERY
  meta_rule_node_triggers ({
      'password_policy' => ['minimum_password_length']
  })
end

coreo_aws_rule "iam-cloudbleed-passwords-not-rotated" do
  action :define
  service :iam
  display_name "User may have been exposed to the CloudBleed issue"
  description "Cloudbleed is the latest internet bug that puts users private information in jeopardy. News of the bug broke late on Feb 24, 2017,"
  link "http://kb.cloudcoreo.com/mydoc_iam-cloudbleed-password-not-rotated.html"
  category "Security"
  suggested_action "Users should be asked to rotate their passwords after February 25, 2017"
  level "High"
  id_map "object.content.user"
  objectives ["credential_report", "credential_report", "credential_report"]
  audit_objects ["object.content.password_last_changed", "object.content.password_last_changed", "object.content.password_last_changed"]
  operators ["!=", "!=", "<"]
  raise_when ["not_supported", "N/A", "2017-02-21 16:00:00 -0800"]
end

coreo_aws_rule "iam-support-role" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-support-role.html"
  display_name "IAM Support Role"
  description "Ensure a support role exists to manage incidents"
  category "Security"
  suggested_action "Create a support role"
  meta_cis_id "1.22"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "Low"
  meta_nist_171_id "3.4.6"
  objectives ["", "policies"]
  audit_objects ["object.policies.policy_name", "object.policies.attachment_count"]
  operators ["==", ">"]
  raise_when ["AWSSupportAccess", 0]
  id_map "object.policies.policy_name"
  meta_rule_query <<~QUERY
  {
    pf as var(func: %<policy_filter>s ) {
      pfa as attachment_count
      pfn as policy_name
    }
    query(func: uid(pf)) @filter( gt( val(pfa), 0) AND eq(val(pfn), AWSSupportAccess") ) {
      %<default_predicates>s
    }
  }
  QUERY
  meta_rule_node_triggers ({
      'policy' => ['attachment_count','policy_name']
  })
end

coreo_aws_rule "iam-user-password-not-used" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-user-password-not-used.html"
  include_violations_in_count false
  display_name "IAM User Password Not Used Recently"
  description "Lists all IAM users whose password has not used in ${AUDIT_AWS_IAM_DAYS_PASSWORD_UNUSED} days"
  category "Security"
  suggested_action "Consider deleting unused or unnecessary IAM users"
  level "Informational"
  objectives ["users"]
  audit_objects ["object.users.password_last_used"]
  operators ["<"]
  raise_when ['${AUDIT_AWS_IAM_DAYS_PASSWORD_UNUSED}.days.ago']
  id_map "object.users.user_name"
end

coreo_aws_rule "iam-unused-access" do
  action :define
  service :user
  include_violations_in_count false
  link "http://kb.cloudcoreo.com/mydoc_iam-unused-access.html"
  display_name "IAM inactive credentials"
  description "This rule checks for credentials that have been unused for 90 days"
  category "Security"
  suggested_action "User credentials that have not been used in 90 days should be removed or deactivated"
  level "Low"
  meta_nist_171_id "3.1.1, 3.1.16"
  meta_cis_id "1.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule "iam-user-is-admin" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_iam-unused-access.html"
  display_name "IAM user has privileges that allow administrator access"
  description "This rule checks for any users that have administrator level access, no matter how the access is/was granted."
  category "Security"
  suggested_action "User access should be granted only to those who need it."
  level "Medium"
  meta_nist_171_id "3.1.1, 3.1.5, 3.1.6, 3.1.7"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule "iam-instance-role-is-admin" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_iam-unused-access.html"
  display_name "EC2 Instance has Administrator Access"
  description "This rule checks for any ec2 instances that have administrator level access. This would indicate that any compromised system would grant the attacker admin access."
  category "Security"
  suggested_action "Instance roles should be granted only what is necessary."
  level "High"
  meta_nist_171_id "3.13.3"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule "iam-no-hardware-mfa-root" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-no-hardware-mfa-root.html"
  display_name "IAM has no root MFA hardware devices"
  description "Triggers if there is no hardware MFA Device for root"
  category "Security"
  suggested_action "Establish a hardware MFA device for root"
  meta_cis_id "1.14"
  meta_cis_scored "true"
  meta_cis_level "2"
  meta_nist_171_id "3.5.3, 3.7.5"
  level "High"
  objectives ["virtual_mfa_devices"]
  audit_objects ["object.virtual_mfa_devices.serial_number"]
  operators ["=="]
  raise_when ["arn:aws:iam::${AUDIT_AWS_IAM_ACCOUNT_NUMBER}:mfa/root-account-mfa-device"]
  id_map "static.root_user"
end

coreo_aws_rule "iam-active-root-user" do
  action :define
  service :iam
  include_violations_in_count false
  link "http://kb.cloudcoreo.com/mydoc_iam-active-root-user.html"
  display_name "IAM Root User Activity"
  description "This rule performs an audit on root user activity"
  category "Security"
  suggested_action "Root user should not be active, when possible. Additionally, ensure that CIS rule 3.3 is passing for this rule to pass"
  level "Low"
  meta_cis_id "1.1"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.1.6"
  id_map "object.content.user"
  objectives ["credential_report"]
  audit_objects ["object.content.user"]
  operators ["=="]
  raise_when ["<root_account>"]
end

coreo_aws_rule "iam-mfa-password-holders" do
  action :define
  service :iam
  include_violations_in_count false
  link "http://kb.cloudcoreo.com/mydoc_iam-mfa-password-holders.html"
  display_name "MFA for IAM Password Holders"
  description "This rule checks that all IAM users with a password have MFA enabled"
  category "Security"
  suggested_action "Activate MFA for all users with a console password"
  level "Medium"
  meta_cis_id "1.2"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.5.3, 3.7.5"
  objectives ["credential_report","credential_report"]
  audit_objects ["object.content.password_enabled", "object.content.mfa_active"]
  operators ["==", "=="]
  raise_when [true, false]
  id_map "object.content.user"
end

coreo_aws_rule "manual-maintenance-records" do
  action :define
  service :user
  link ""
  display_name "Ensure System Components Maintained to Best Practices"
  description "Ensure that all system components are repaired and those repairs documented and reviewed in line with organization/vendor/manufacturer specifications"
  category "Security"
  suggested_action "Put policies in place to make sure systematic best practices are in place for system component repairs and recording/reviewing of those repairs"
  level "Manual"
  meta_always_show_card "true"
  meta_nist_171_id "3.7.1, 3.7.2, 3.7.3"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end

coreo_aws_rule "manual-approved-monitored-maintenance" do
  action :define
  service :user
  link ""
  display_name "Ensure that all maintenance activities are approved and monitored"
  description "All maintenance activities should be both approved and monitored whether or on or off site"
  category "Security"
  suggested_action "Implement a policy to ensure that all maintenance efforts are systematically both approved and monitored, on and off site"
  level "Manual"
  meta_always_show_card "true"
  meta_nist_171_id "3.7.1, 3.7.2, 3.7.3"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end

coreo_aws_rule "manual-component-removal-approval" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_manual-ensure-security-questions.html"
  display_name "Ensure Explicit Approval pre Component Removal"
  description "Ensure that the removal of any system or component from premsis for maintenance requires the explicit approval of a specified person/department"
  category "Security"
  suggested_action "Implement a policy to ensure that the removal of any system or component from premsis for maintenance requires the explicit approval of a specified person/department"
  level "Manual"
  meta_always_show_card "true"
  meta_nist_171_id "3.7.1, 3.7.2, 3.7.3"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end

coreo_aws_rule "manual-ensure-security-questions" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_manual-ensure-security-questions.html"
  display_name "Ensure Account Security Questions"
  description "Security Questions improve account security"
  category "Security"
  suggested_action "Ensure that the AWS account has security questions registered"
  level "Manual"
  meta_always_show_card "true"
  meta_cis_id "1.15"
  meta_cis_scored "false"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end

coreo_aws_rule "manual-obscure-auth-info" do
  action :define
  service :user
  link ""
  display_name "Ensure Authorization Information is Obscured"
  description "Obscuring authorization information during authorization process improves security"
  category "Security"
  suggested_action "Make password characters be obscured by, for example, the * symbol during sign-in process"
  level "Manual"
  meta_always_show_card "true"
  meta_nist_171_id "3.5.11"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end

coreo_aws_rule "manual-detailed-billing" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_manual-detailed-billing.html"
  display_name "Enable Detailed Billing"
  description "Detailed billing can help to bring attention to anomalous use of AWS resources"
  category "Security"
  suggested_action "Ensure that Detailed Billing has been enabled"
  level "Manual"
  meta_always_show_card "true"
  meta_cis_id "1.17"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule "iam-root-key-access" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_iam-root-key-access.html"
  display_name "IAM Root Access Key"
  description "This rule checks for root access keys. Root account should not have access keys enabled"
  category "Security"
  suggested_action "Deactivate root access keys"
  level "High"
  meta_cis_id "1.12"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.1.6"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule "iam-root-no-mfa" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_iam-root-no-mfa-cis.html"
  display_name "Multi-Factor Authentication not enabled for root account"
  description "Root cloud user does not have Multi-Factor Authentication enabled on their cloud account"
  category "Security"
  suggested_action "Enable Multi-Factor Authentication for the root cloud user."
  level "High"
  meta_cis_id "1.13"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.5.3"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule "manual-strategic-iam-roles" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_manual-strategic-iam-roles.html"
  display_name "Ensure Strategic IAM Roles"
  description "Use IAM Master and Manager Roles to optimize security"
  category "Security"
  suggested_action "Implement IAM roles as set out in the CIS document"
  level "Manual"
  meta_always_show_card "true"
  meta_cis_id "1.18"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule "iam-initialization-access-key" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_iam-initialization-access-key.html"
  display_name "IAM Initialization Access"
  description "This rule checks for access keys that were activated during initialization"
  category "Security"
  suggested_action "Do not establish access keys during initialization of user"
  level "Low"
  meta_cis_id "1.23"
  meta_cis_scored "false"
  meta_cis_level "1"
  meta_nist_171_id "3.5.9"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule "iam-omnipotent-policy" do
  action :define
  service :user
  link ""
  display_name "Full Privilege Policy"
  description "IAM policies should be written to have the minimum necessary permissions. Full permissions are considered to be suboptimal for security"
  category "Access"
  suggested_action "Write IAM policies as to give the minimal necessary permissions"
  level "High"
  meta_cis_id "1.24"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.1.2, 3.4.5, 3.4.6"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
{
  gateways as var(func: %<internet_gateway_filter>s)  @cascade {
      relates_to @filter(%<route_filter>s) {
        relates_to @filter(%<route_table_filter>s) {
          relates_to @filter(%<route_table_association_filter>s) {
            relates_to @filter(has(subnet)) {
              relates_to @filter(%<instance_filter>s AND has(public_ip_address)) {
                evil_instance_state as state
                relates_to @filter(has(key_pair)){
                  exposed_keys as uid
                  relates_to @filter(%<instance_filter>s){
                    innocent_instance_state as state
                    relates_to @filter(%<iam_instance_profile_filter>s){
                      relates_to @filter(%<role_filter>s){
                        relates_to @filter(has(policy) AND has(is_admin_policy)){
                          exposed_policies as uid
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      
    }
  }
  violations(func: uid(gateways)) @cascade {
    relates_to @filter(has(route)) {
      name:label
      relates_to @filter(has(route_table)) {
        name:label
        relates_to @filter(has(route_table_association)) {
          name:label
          relates_to @filter(has(subnet)) {
            name:label
            relates_to @filter(has(instance) and eq(val(evil_instance_state),"{:code=>16, :name=>\\\"running\\\"}")) {
              name:instance_id
              state
              createdAt
              objectId
              relates_to @filter(uid(exposed_keys)){
                name:key_name
                teamId
                relates_to @filter(has(instance) and eq(val(innocent_instance_state),"{:code=>16, :name=>\\\"running\\\"}")){
                  name:instance_id
                  state
                  createdAt
                  objectId
                  relates_to @filter(has(iam_instance_profile)){
                    name:arn
                    relates_to @filter(has(role)){
                      name:label
                      relates_to @filter(uid(exposed_policies)){
                        arn
                        name:policy_name
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
  QUERY
  meta_rule_node_triggers ({'internet_gateway' => ['relates_to'], 'route' => [], 'route_table' => [], 'route_table_association' => [], 'instance' => [], 'iam_instance_profile' => [], 'role' => [] })

end

coreo_aws_rule "manual-contact-details" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_manual-contact-details.html"
  display_name "Maintain Contact Details"
  description "Contact details associated with the AWS account may be used by AWS staff to contact the account owner"
  category "Security"
  suggested_action "Ensure that contact details associated with AWS account are current"
  level "Manual"
  meta_always_show_card "true"
  meta_cis_id "1.19"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end

coreo_aws_rule "manual-security-contact" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_manual-security-contact.html"
  display_name "Security Contact Details"
  description "Contact details may be provided to the AWS account for your security team, allowing AWS staff to contact them when required"
  category "Security"
  suggested_action "Ensure that security contact information is provided in your AWS account"
  level "Manual"
  meta_always_show_card "true"
  meta_cis_id "1.20"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end

coreo_aws_rule "manual-resource-instance-access" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_manual-resource-instance-access.html"
  display_name "IAM Instance Roles"
  description "Proper usage of IAM roles reduces the risk of active, unrotated keys"
  category "Security"
  suggested_action "Ensure IAM instance roles are used for AWS resource access from instances"
  level "Manual"
  meta_always_show_card "true"
  meta_cis_id "1.21"
  meta_cis_scored "false"
  meta_cis_level "2"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end

coreo_aws_rule "manual-appropriate-sns-subscribers" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_manual-appropriate-sns-subscribers.html"
  display_name "SNS Appropriate Subscribers"
  description "Unintended SNS subscribers may pose a security risk"
  category "Security"
  suggested_action "Regularly ensure that only appropriate subscribers exist in SNS"
  level "Manual"
  meta_always_show_card "true"
  meta_cis_id "3.15"
  meta_cis_scored "false"
  meta_cis_level "1"
  meta_nist_171_id "3.4.3, 3.14.6, 3.14.7"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end

coreo_aws_rule "manual-least-access-routing-tables" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_manual-least-access-routing-tables.html"
  display_name "Least Access Routing Tables"
  description "Being highly selective in peering routing tables minimizes impact of potential breach"
  category "Security"
  suggested_action "Review and minimize routing table access regularly"
  level "Manual"
  meta_always_show_card "true"
  meta_cis_id "4.5"
  meta_cis_scored "false"
  meta_cis_level "2"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end


# end of user-visible content. Remaining resources are system-defined

coreo_aws_rule "iam-internal" do
  action :define
  service :iam
  display_name "IAM Root Access Key"
  description "This rule checks for root access keys. Root account should not have access keys enabled"
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  id_map "object.content.user"
  objectives ["credential_report"]
  audit_objects ["object.content.user"]
  operators ["=~"]
  raise_when [//]
end

coreo_aws_rule "iam-policy-internal" do
  action :define
  service :iam
  link ""
  display_name "Policy inventory internal"
  description "Internal rule that checks all policies"
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives ["policies", "policy_version"]
  audit_objects ["", "object.policy_version.document"]
  call_modifiers [{}, {:policy_arn => "objective[0].policies.arn", :version_id => "objective[0].policies.default_version_id"}]
  operators ["", "=~"]
  raise_when ["", //]
  id_map "modifiers.policy_arn"
end

coreo_uni_util_variables "iam-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.results' => 'unset'},
                {'GLOBAL::number_violations' => '0'}
            ])
end

coreo_aws_rule_runner "advise-iam" do
  service :iam
  action :run
  regions ["PLAN::region"]
  rules ${AUDIT_AWS_IAM_ALERT_LIST}.push("iam-internal", "iam-policy-internal").uniq
  rules ${AUDIT_AWS_IAM_ALERT_LIST}.push("iam-internal", "iam-policy-internal").push("iam-inventory-users").uniq if ${AUDIT_AWS_IAM_ALERT_LIST}.include?('iam-user-is-admin')
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_aws_rule_runner "advise-iam-instance-roles" do
  service :ec2
  action (${AUDIT_AWS_IAM_ALERT_LIST}.include?('iam-instance-role-is-admin') ? :run : :nothing)
  regions ["PLAN::region"]
  rules ['iam-inventory-ec2-roles']
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_uni_util_variables "iam-update-planwide-1" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.results' => 'COMPOSITE::coreo_aws_rule_runner.advise-iam.report'},
                {'GLOBAL::number_violations' => 'COMPOSITE::coreo_aws_rule_runner.advise-iam.number_violations'},
                {'COMPOSITE::coreo_aws_rule_runner.advise-iam-instance-roles.report' => '{}'}
            ])
  variables([
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.results' => 'COMPOSITE::coreo_aws_rule_runner.advise-iam.report'},
                {'GLOBAL::number_violations' => 'COMPOSITE::coreo_aws_rule_runner.advise-iam.number_violations'},
                {'COMPOSITE::coreo_aws_rule_runner.advise-iam-instance-roles.report' => 'COMPOSITE::coreo_aws_rule_runner.advise-iam-instance-roles.report'}
            ]) if ${AUDIT_AWS_IAM_ALERT_LIST}.include?('iam-instance-role-is-admin')
end


coreo_uni_util_jsrunner "cis-iam-admin" do
  action ((${AUDIT_AWS_IAM_ALERT_LIST}.include?('iam-user-is-admin') || ${AUDIT_AWS_IAM_ALERT_LIST}.include?('iam-instance-role-is-admin')) ? :run : :nothing)
  data_type "json"
  provide_composite_access true
  json_input '{ "composite name":"PLAN::stack_name",
                "violations":COMPOSITE::coreo_aws_rule_runner.advise-iam.report,
                "violationsEc2": COMPOSITE::coreo_aws_rule_runner.advise-iam-instance-roles.report,
                "numberViolations": COMPOSITE::coreo_aws_rule_runner.advise-iam.number_violations
              }'
  packages([
               {
                   :name => "aws-sdk",
                   :version => "^2.110.0"
               },{
                   :name => "bluebird",
                   :version => "3.5.0"
               },{
                   :name => "merge-deep",
                   :version => "3.0.0"
               }
           ])
  function <<-RUBY
    var merge = require('merge-deep');
    // json_input.violations always exists
    var violations = json_input.violations;
    var violationsEc2 = {};
    if (runIamInstanceRoleIsAdmin) {
        violations = merge(json_input.violations, json_input.violationsEc2);
        violationsEc2 = json_input.violationsEc2;
    }
    json_input.violations = violations;
    var numberViolations = json_input.numberViolations;
    setRegion = Object.keys(violations)[0];
    const iamUsersArray = [];
    for (var region in violationsEc2) {
        for (var violator in violationsEc2[region]) {
            var violator_info = violationsEc2[region][violator]['violator_info'];
            if (violator_info['arn']) {
                var fakeUser = {type: 'ec2', user: violator, arn: violator_info['arn']};
                iamUsersArray.push(fakeUser);
            }
        }
    }
    for (var region in violations) {
        for (var violator in violations[region]) {
            var violator_info = violations[region][violator]['violator_info'];
            if (violator_info['user_name'] || violator_info['user']) {
                if (violator_info['user_name'] === '<root_account>' || violator_info['user'] === '<root_account>') {
                    continue;
                }
                violator_info.type = 'iam';
                iamUsersArray.push(violator_info);
            }
        }
    }
    const operations = [];
    iamUsersArray.forEach((user) => operations.push(checkIsFullAdmin(user)));
    return Promise.all(operations)
        .then((results) => {
            for (var i = 0; i < results.length; i++) {
                var obj = results[i];
                if (obj === undefined) {
                    continue;
                }
                var allRes = [].concat(obj);
                var userIsInViolation = true;
                var user;
                for (var policyToCheckCounter = 0; policyToCheckCounter < IAM_ADMIN_POLICY_SPECIFIER.length; policyToCheckCounter++) {
                    var policyToCheck = IAM_ADMIN_POLICY_SPECIFIER[policyToCheckCounter];
                    var explictDenyStated = false;
                    var policyIsAllowed = false; // assume implicit deny by default
                    for (var resCounter = 0; resCounter < allRes.length; resCounter++) {
                        var res = allRes[resCounter];
                        user = res.user;
                        var result = res.result;
                        var evaluationResults = result['EvaluationResults'];
                        for (var e = 0; e < evaluationResults.length; e++) {
                            if (evaluationResults[e].EvalActionName !== policyToCheck) {
                                continue;
                            }
                            // if a policy is only implicitly denied, it is denied
                            // if a policy is implicitly denied and allowed, it is allowed
                            // if a policy is EVER explicitly denied, it is totally denied
                            if (evaluationResults[e]['EvalDecision'] === 'allowed') {
                                policyIsAllowed = true;
                            }
                            if (evaluationResults[e]['EvalDecision'] === 'explicitDeny') {
                                policyIsAllowed = false;
                                explictDenyStated = true;
                                break;
                            }
                        }
                        // don't break here unless explicitly denied - we still might have a policy that explicitly denies
                        if (explictDenyStated) {
                            break;
                        }
                    }
                    ;
                    if (policyIsAllowed) {
                        break;
                    }
                }
                ;
                if (policyIsAllowed) {
                    fullAdmin.push(user);
                }
            }
            for (var i = 0; i < fullAdmin.length; i++) {
                var user = fullAdmin[i];
                var userName = user.user;
                if (userName && userName.arn) {
                    user = fullAdmin[i].user;
                    userName = user.arn;
                }
                if (json_input['violations'][setRegion][userName].hasOwnProperty('violator_info')) {
                    if (!json_input['violations'][setRegion][userName]) {
                        json_input['violations'][setRegion][userName] = {}
                    }
                    if (!json_input['violations'][setRegion][userName]['violations']) {
                        json_input['violations'][setRegion][userName]['violations'] = {}
                    }
                    if (user.type === 'iam' && runIamUserIsAdmin) {
                        json_input['violations'][setRegion][userName]['violations']['iam-user-is-admin'] = Object.assign(ruleMeta[IAM_ADMIN_RULE]);
                    } else if (user.type === 'ec2' && runIamInstanceRoleIsAdmin) {
                        json_input['violations'][setRegion][userName]['violations']['iam-instance-role-is-admin'] = Object.assign(ruleMeta[EC2_ADMIN_RULE]);
                    }
                    numberViolations += 1;
                }
            }
            const violations = json_input['violations'];
            const report = JSON.stringify(violations)
            coreoExport('JSONReport', JSON.stringify(json_input));
            coreoExport('numberViolations', numberViolations);
            coreoExport('report', report);
            return callback(violations);
        });
}
var setRegion = '';
const fullAdmin = [];
const AWS = require('aws-sdk');
const Promise = require('bluebird');
const iam = Promise.promisifyAll(new AWS.IAM({maxRetries: 1000, apiVersion: '2010-05-08', retryDelayOptions: {base: 1000}}));
const IAM_ADMIN_POLICY_SPECIFIER = ${AUDIT_AWS_CIS_IAM_ADMIN_GROUP_PERMISSIONS};
const ruleInputsToKeep = ['service', 'category', 'link', 'display_name', 'suggested_action', 'description', 'level', 'meta_cis_id', 'meta_cis_scored', 'meta_cis_level', 'include_violations_in_count', 'meta_nist_171_id'];
const IAM_ADMIN_RULE = 'iam-user-is-admin';
const EC2_ADMIN_RULE = 'iam-instance-role-is-admin';
const runIamUserIsAdmin = ${AUDIT_AWS_IAM_ALERT_LIST}.indexOf(IAM_ADMIN_RULE) > -1;
const runIamInstanceRoleIsAdmin = ${AUDIT_AWS_IAM_ALERT_LIST}.indexOf(EC2_ADMIN_RULE) > -1;
const ruleMetaJSON = {
     'iam-user-is-admin': COMPOSITE::coreo_aws_rule.iam-user-is-admin.inputs,
     'iam-instance-role-is-admin': COMPOSITE::coreo_aws_rule.iam-instance-role-is-admin.inputs
 };
const ruleMeta = {};
Object.keys(ruleMetaJSON).forEach(rule => {
    const flattenedRule = {};
    ruleMetaJSON[rule].forEach(input => {
        if (ruleInputsToKeep.includes(input.name))
            flattenedRule[input.name] = input.value;
    })
    flattenedRule["service"] = "iam";
    ruleMeta[rule] = flattenedRule;
});
function checkIsFullAdmin(user) {
    if (user.type === 'ec2') {
        var params = {
            ActionNames: IAM_ADMIN_POLICY_SPECIFIER,
            PolicySourceArn: user.arn
        };
        var profileName = user.arn.split('/')[user.arn.split('/').length - 1];
        return iam.getInstanceProfileAsync({InstanceProfileName: profileName}).then((ip) => {
            var roles = [];
            ip.InstanceProfile.Roles.forEach((role) => {
                role.arn = role.Arn;
                role.user = user;
                roles.push(checkIsFullAdmin(role))
            });
            return Promise.all(roles);
        }).catch((err) => {
            if (err.code === 'NoSuchEntity') {
                console.log(`Got NoSuchEntity for profileName: ${profileName}`);
                return Promise.resolve();
            }
            console.log(`Error with iam.getInstanceProfile: ${err}`);
            return Promise.reject(err);
        });
    } else {
        var params = {
            ActionNames: IAM_ADMIN_POLICY_SPECIFIER,
            PolicySourceArn: user.arn
        };
        return iam.simulatePrincipalPolicyAsync(params)
            .then((result) => {
                return {user: user, result: result};
            })
            .catch((err) => {
                if (err.code === 'NoSuchEntity') {
                    return Promise.resolve();
                }
                console.log(`Error with iam.simulatePrincipalPolicy: ${err}`);
                return Promise.reject(err);
            });
    }
RUBY
end
coreo_uni_util_variables "iam-update-user-is-admin" do
  action (${AUDIT_AWS_IAM_ALERT_LIST}.include?('iam-user-is-admin') ? :set : :nothing)
  variables([
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.cis-iam-admin.JSONReport'},
                {'COMPOSITE::coreo_aws_rule_runner.advise-iam.report' => 'COMPOSITE::coreo_uni_util_jsrunner.cis-iam-admin.report'},
                {'GLOBAL::number_violations' => 'COMPOSITE::coreo_aws_rule_runner.advise-iam.number_violations'},
            ])
end
coreo_uni_util_jsrunner "cis-iam" do
  action :run
  data_type "json"
  provide_composite_access true
  json_input '{ "composite name":"PLAN::stack_name",
                "violations":COMPOSITE::coreo_aws_rule_runner.advise-iam.report}'
  function <<-EOH
  const ruleMetaJSON = {
       'iam-unused-access': COMPOSITE::coreo_aws_rule.iam-unused-access.inputs,
       'iam-root-key-access': COMPOSITE::coreo_aws_rule.iam-root-key-access.inputs,
       'iam-root-no-mfa': COMPOSITE::coreo_aws_rule.iam-root-no-mfa.inputs,
       'iam-initialization-access-key': COMPOSITE::coreo_aws_rule.iam-initialization-access-key.inputs,
       'iam-omnipotent-policy': COMPOSITE::coreo_aws_rule.iam-omnipotent-policy.inputs
   };
   const ruleInputsToKeep = ['service', 'category', 'link', 'display_name', 'suggested_action', 'description', 'level', 'meta_cis_id', 'meta_cis_scored', 'meta_cis_level', 'include_violations_in_count', 'meta_nist_171_id'];
   const ruleMeta = {};
   Object.keys(ruleMetaJSON).forEach(rule => {
       const flattenedRule = {};
       ruleMetaJSON[rule].forEach(input => {
           if (ruleInputsToKeep.includes(input.name))
               flattenedRule[input.name] = input.value;
       })
       flattenedRule["service"] = "iam";
       ruleMeta[rule] = flattenedRule;
   })
   const UNUSED_ACCESS_RULE = 'iam-unused-access'
   const ROOT_ACCESS_RULE = 'iam-root-key-access'
   const ROOT_MFA_RULE = 'iam-root-no-mfa'
   const INIT_ACCESS_RULE = 'iam-initialization-access-key'
   const OMNIPOTENT_POLICY_RULE = 'iam-omnipotent-policy'
let alertListToJSON = "${AUDIT_AWS_IAM_ALERT_LIST}";
let alertListArray = alertListToJSON.replace(/'/g, '"');
const viols = json_input['violations']['PLAN::region'];
function setValueForNewJSONInput(json_input) {
  const users = []
  var policies = []
  const polRegex = new RegExp(':policy/')
  for (var item in viols) {
      if (polRegex.test(item)) {
          policies.push(item)
      } else {
          users.push(item)
      }
  }
    //if cis 1.3 wanted, the below will run
    if  (alertListArray.indexOf('iam-unused-access') > -1) {
        for (var user in users) {
          var userName = users[user]
          if (json_input['violations']['PLAN::region'][userName].hasOwnProperty('violator_info')) {
            var keyOneDate = new Date(json_input['violations']['PLAN::region'][userName]['violator_info']['access_key_1_last_used_date']);
            var keyTwoDate = new Date(json_input['violations']['PLAN::region'][userName]['violator_info']['access_key_2_last_used_date']);
            var passwordUsedDate = new Date(json_input['violations']['PLAN::region'][userName]['violator_info']['password_last_used']);
            const ninetyDaysAgo = (new Date()) - 1000 * 60 * 60 * 24 * 90
            const keyOneUnused = keyOneDate < ninetyDaysAgo
            const keyOneEnabled = json_input['violations']['PLAN::region'][userName]['violator_info']['access_key_1_active'] == "true"
            const keyTwoUnused = keyTwoDate < ninetyDaysAgo
            const keyTwoEnabled = json_input['violations']['PLAN::region'][userName]['violator_info']['access_key_2_active'] == "true"
            const passwordUnused = passwordUsedDate < ninetyDaysAgo
            const passwordEnabled = json_input['violations']['PLAN::region'][userName]['violator_info']['password_enabled'] == "true"
            if ((keyOneUnused && keyOneEnabled) || (keyTwoEnabled && keyTwoUnused) || (passwordEnabled && passwordUnused)) {
                if (!json_input['violations']['PLAN::region'][userName]) {
                    json_input['violations']['PLAN::region'][userName] = {}
                }
                if (!json_input['violations']['PLAN::region'][userName]['violations']) {
                    json_input['violations']['PLAN::region'][userName]['violations'] = {}
                }
                json_input['violations']['PLAN::region'][userName]['violations']['iam-unused-access'] = Object.assign(ruleMeta[UNUSED_ACCESS_RULE]);
            }
          }
        }
    }
    //if cis 1.12 wanted, the below will run
    if  (alertListArray.indexOf('iam-root-key-access') > -1 && users && users["<root_account>"]) {
        const keyOneEnabled = users["<root_account>"]['violator_info']['access_key_1_active'] == "true"
        const keyTwoEnabled = users["<root_account>"]['violator_info']['access_key_2_active'] == "true"
        if ((keyOneEnabled || keyTwoEnabled)) {
            if (!json_input['violations']['PLAN::region']["<root_account>"]) {
                json_input['violations']['PLAN::region']["<root_account>"] = {}
            }
            if (!json_input['violations']['PLAN::region']["<root_account>"]['violations']) {
                json_input['violations']['PLAN::region']["<root_account>"]['violations'] = {}
            }
            json_input['violations']['PLAN::region']["<root_account>"]['violations']['iam-root-key-access'] = Object.assign(ruleMeta[ROOT_ACCESS_RULE]);
        }
    }
    //if cis 1.13 wanted, the below will run
    if  (alertListArray.indexOf('iam-root-no-mfa') > -1 && users && users["<root_account>"]) {
        if (users["<root_account>"]['violator_info']['mfa_active'] == "false"){
            if (!json_input['violations']['PLAN::region']["<root_account>"]) {
                json_input['violations']['PLAN::region']["<root_account>"] = {}
            }
            if (!json_input['violations']['PLAN::region']["<root_account>"]['violations']) {
                json_input['violations']['PLAN::region']["<root_account>"]['violations'] = {}
            }
            json_input['violations']['PLAN::region']["<root_account>"]['violations']['iam-root-no-mfa'] = Object.assign(ruleMeta[ROOT_MFA_RULE]);
        }
    }
    //if cis 1.23 wanted, the below will run
    if  (alertListArray.indexOf('iam-initialization-access-key') > -1) {
        for (var user in users) {
          var userName = users[user]
          if (json_input['violations']['PLAN::region'][userName].hasOwnProperty('violator_info')) {
            var keyOneDate = json_input['violations']['PLAN::region'][userName]['violator_info']['access_key_1_last_used_date'] == "N/A";
            var keyTwoDate = json_input['violations']['PLAN::region'][userName]['violator_info']['access_key_2_last_used_date'] == "N/A";
            var keyOneEnabled = json_input['violations']['PLAN::region'][userName]['violator_info']['access_key_1_active'] == "true";
            var keyTwoEnabled = json_input['violations']['PLAN::region'][userName]['violator_info']['access_key_2_active'] == "true";
            if ((keyOneDate && keyOneEnabled) || (keyTwoDate && keyTwoEnabled)) {
                if (!json_input['violations']['PLAN::region'][userName]) {
                    json_input['violations']['PLAN::region'][userName] = {}
                }
                if (!json_input['violations']['PLAN::region'][userName]['violations']) {
                    json_input['violations']['PLAN::region'][userName]['violations'] = {}
                }
                json_input['violations']['PLAN::region'][userName]['violations']['iam-initialization-access-key'] = Object.assign(ruleMeta[INIT_ACCESS_RULE]);
            }
          }
        }
    }
    //if cis 1.24 wanted, the below will run
    if (alertListArray.indexOf('iam-omnipotent-policy') > -1) {
        for (var policy in policies) {
            var policyName = policies[policy]
            var document = json_input['violations']['PLAN::region'][policyName]['violations']['iam-policy-internal']['result_info'][0]['object']['document']
            var decodedDocument = decodeURIComponent(document).replace(/\\++/g, ' ');
            var jsonDocument = JSON.parse(decodedDocument);
            if (!(typeof jsonDocument['Statement'][0] == "undefined")) {
                var action = jsonDocument["Statement"][0]['Action'];
            }
            if (!(typeof jsonDocument['Statement'][0] == "undefined")) {
                var resource = jsonDocument["Statement"][0]['Resource'];
            }
            if (!(typeof jsonDocument['Statement'][0] == "undefined")) {
                var allowEffect = (jsonDocument["Statement"][0]['Effect'] == "Allow");
            }
            if (typeof action == "string") {
                var allAction = action == "*";
            } else if (!(typeof action == "undefined")){
                var allAction = action.indexOf('*') > -1;
            }
            var allResource = resource.indexOf('*') > -1;
            var awsManagedPolicy = policyName.split(':')[4] === 'aws';
            if (allowEffect && allAction && allResource && !awsManagedPolicy) {
                json_input['violations']['PLAN::region'][policyName]['violations']['iam-omnipotent-policy'] = Object.assign(ruleMeta[OMNIPOTENT_POLICY_RULE]);
            }
        }
    }
    //Strip internal violations
    for (var user in users) {
        var userName = users[user]
        var internal = json_input['violations']['PLAN::region'][userName]['violations'].hasOwnProperty('iam-internal');
        var single_violation = (Object.keys(json_input['violations']['PLAN::region'][userName]['violations']).length === 1);
        if (internal && single_violation) {
            delete json_input['violations']['PLAN::region'][userName];
        }
        else if (internal && !single_violation){
            delete json_input['violations']['PLAN::region'][userName]['violations']['iam-internal'];
        }
    }
    //Strip internal violations
    for (var policy in policies) {
        var policyName = policies[policy]
        var internal = json_input['violations']['PLAN::region'][policyName]['violations'].hasOwnProperty('iam-policy-internal');
        var single_violation = (Object.keys(json_input['violations']['PLAN::region'][policyName]['violations']).length === 1);
        if (internal && single_violation) {
            delete json_input['violations']['PLAN::region'][policyName];
        }
        else if (internal && !single_violation){
            delete json_input['violations']['PLAN::region'][policyName]['violations']['iam-policy-internal'];
        }
    }
}
setValueForNewJSONInput(json_input)
const violations = json_input['violations'];
const report = JSON.stringify(violations)
coreoExport('JSONReport', JSON.stringify(json_input));
coreoExport('report', report);
callback(violations);
  EOH
end
coreo_uni_util_variables "iam-update-planwide-4" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.cis-iam.JSONReport'},
                {'COMPOSITE::coreo_aws_rule_runner.advise-iam.report' => 'COMPOSITE::coreo_uni_util_jsrunner.cis-iam.report'},
            ])
end
coreo_aws_rule "kms-unused" do
  action(${AUDIT_AWS_KMS_ALERT_LIST}.include?("kms-unused") ? :define : :nothing)
  service :user
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "KMS is unused"
  description "This rule performs an inventory on all kms objects to determine if KMS is being used as a cryptographic management system. If not, it indicated a system may not be in use."
  category "Security"
  suggested_action "None."
  level "Low"
  meta_nist_171_id "3.13.10"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  { 
    query(func: %<key_filter>s) @filter(NOT has(relates_to)) {
        %<default_predicates>s
    }
  }
  QUERY
  meta_rule_node_triggers ({
          'key' => []
  })
end

coreo_aws_rule "kms-key-rotates" do
  action :define
  service :kms
  link "http://kb.cloudcoreo.com/mydoc_kms-key-rotates.html"
  include_violations_in_count true
  display_name "Verify rotation for customer created CMKs is enabled"
  description "AWS Key Management Service (KMS) allows customers to rotate the backing key which is key material stored within the KMS which is tied to the key ID of the Customer Created customer master key (CMK). It is the backing key that is used to perform cryptographic operations such as encryption and decryption. Automated key rotation currently retains all prior backing keys so that decryption of encrypted data can take place transparently."
  category "Audit"
  suggested_action "It is recommended that CMK key rotation be enabled."
  level "Medium"
  meta_cis_id "2.8"
  meta_cis_scored "true"
  meta_cis_level "2"
  objectives ["keys", "key_rotation_status"]
  call_modifiers [{}, {:key_id => "object.keys.key_id"}]
  audit_objects ["", "object.key_rotation_enabled"]
  operators ["", "=="]
  raise_when ["", false]
  id_map "modifiers.key_id"
  # TODO: wrong query, need to fix
  meta_rule_query <<~QUERY
  { 
    keys as var(func: %<key_filter>s) @cascade {         
      keys_rotation as relates_to @filter(has(key_rotation_status)) {
        kre as key_rotation_enabled
      }
    }
    query(func: uid(keys)) @cascade {
      %<default_predicates>s
      relates_to @filter(uid(keys_rotation) AND eq(val(kre), false) ) {
        %<default_predicates>s
      }
    }
  }
  QUERY
  meta_rule_node_triggers ({
          'key' => [],
          'key_rotation_status' => ['key_rotation_enabled']
  })
end

coreo_aws_rule_runner "advise-kms" do
  action :run
  rules ${AUDIT_AWS_KMS_ALERT_LIST}
  service :kms
  regions ${AUDIT_AWS_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_aws_rule "cloudtrail-logs-encrypted" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_cloudtrail-logs-encrypted.html"
  display_name "Verify CloudTrail logs are encrypted at rest using KMS CMKs"
  suggested_action "It is recommended that CloudTrail be configured to use SSE-KMS."
  description "AWS CloudTrail is a web service that records AWS API calls for an account and makes those logs available to users and resources in accordance with IAM policies. AWS Key Management Service (KMS) is a managed service that helps create and control the encryption keys used to encrypt account data, and uses Hardware Security Modules (HSMs) to protect the security of encryption keys. CloudTrail logs can be configured to leverage server side encryption (SSE) and KMS customer created master keys (CMK) to further protect CloudTrail logs."
  level "Medium"
  meta_cis_id "2.7"
  meta_cis_scored "true"
  meta_cis_level "2"
  meta_nist_171_id "3.3.1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  # TODO: followup, query likely broken
  meta_rule_query <<~QUERY
  {
    logged_trails as var(func: has(trail))  @cascade{
      relates_to @filter(has(kms_key)) { }
    }
    query(func: %<trail_filter>s) @filter( NOT uid(logged_trails) ) {
      %<default_predicates>s
    }
  }
  QUERY
  meta_rule_node_triggers({
                              'trail' => []
                          })
end
        
coreo_aws_rule "cloudtrail-log-file-validating" do
  action :define
  service :cloudtrail
  link "http://kb.cloudcoreo.com/mydoc_cloudtrail-log-file-validating.html"
  display_name "Cloudtrail Log File Validation Disabled"
  description "CloudTrail log file validation is disabled for this trail. It should be enabled"
  category "Audit"
  suggested_action "Enable CloudTrail log file validation for this trail."
  level "Low"
  meta_cis_id "2.2"
  meta_cis_scored "true"
  meta_cis_level "2"
  meta_nist_171_id "3.3.1"
  objectives ["trails"]
  audit_objects ["object.trail_list.log_file_validation_enabled"]
  operators ["=="]
  raise_when [false]
  id_map "stack.current_region"
  meta_rule_query <<~QUERY
  {
    trails as var(func: %<trail_filter>s) @cascade {
      is_log_validated as log_file_validation_enabled
    }
    query(func: uid(trails)) @filter(eq(val(is_log_validated), false)) {
      %<default_predicates>s
    }
  }
  QUERY
  meta_rule_node_triggers({
                              'trail' => ['log_file_validation_enabled']
                          })
end
      
coreo_aws_rule_runner "advise-cloudtrail" do
  action :run
  service :cloudtrail
  rules(${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST})
  regions ${AUDIT_AWS_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

