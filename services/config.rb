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
        relates_to @filter(uid(ranges) AND eq(val(range), "[{:cidr_ip=>\"1.0.0.0/32\"}]")) {
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
