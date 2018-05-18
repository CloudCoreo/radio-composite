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
