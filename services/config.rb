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
  regions ${AUDIT_AWS_REGIONS}
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
  regions ${AUDIT_AWS_REGIONS}
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

coreo_aws_rule_runner "advise-iam" do
  service :iam
  action :run
  regions ${AUDIT_AWS_REGIONS}
  rules (${AUDIT_AWS_IAM_ALERT_LIST})
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end
