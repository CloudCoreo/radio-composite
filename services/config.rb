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

coreo_aws_rule "administrative-policy-exposed-by-connected-ssh-credential" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/connected-threats-ssh-credentials"
  display_name "Publicly routable instance shares ssh-key with administrative instances"
  description "A publicly routable and addressable ec2 instance has the same ssh key as an instance with an administrative policy."
  category "Security"
  suggested_action "Generate distinct ssh keys per subnet or ec2 instance role."
  level "Medium"
  objectives [""]
  audit_objects [""]
  operators [""]
  meta_rule_query <<~QUERY
{
  gateways as var(func: has(internet_gateway))  @cascade {
      relates_to @filter(has(route)) {
        relates_to @filter(has(route_table)) {
          relates_to @filter(has(route_table_association)) {
            relates_to @filter(has(subnet)) {
              relates_to @filter(has(instance) AND has(public_ip_address)) {
                evil_instance_state as state
                relates_to @filter(has(key_pair)){
                  exposed_keys as uid
                  relates_to @filter(has(instance)){
                    innocent_instance_state as state
                    relates_to @filter(has(iam_instance_profile)){
                      relates_to @filter(has(role)){
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
            relates_to @filter(has(instance) and eq(val(evil_instance_state),"{:code=>16, :name=>\"running\"}")) {
              name:instance_id
              state
              createdAt
              objectId
              relates_to @filter(uid(exposed_keys)){
                name:key_name
                teamId
                relates_to @filter(has(instance) and eq(val(innocent_instance_state),"{:code=>16, :name=>\"running\"}")){
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
  meta_rule_node_triggers ('internet_gateway' => ['relates_to'], 'route_table' => [], 'route_table_association' => [], 'instance' => ['state', 'public_ip_address'], 'iam_instance_profile' => [], 'role' => [] })
end

coreo_aws_rule_runner "advise-ec2" do
  service :ec2
  action :run
  rules (${AUDIT_AWS_EC2_ALERT_LIST})
  regions ${AUDIT_AWS_EC2_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end
