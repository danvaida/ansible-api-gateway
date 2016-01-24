#!/usr/bin/python
# This module is a candidate for Ansible module extras.
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: api_gw_facts

'''

EXAMPLES = '''
---
- hosts: localhost
  gather_facts: no

  - name: display stuff
    debug: var=results
'''

API_CONFIG = dict(
    account=dict(required_params=[], optional_params=[]),
    api_key=dict(required_params=[], optional_params=[]), 
    api_keys=dict(required_params=[], optional_params=[]),
    base_path_mapping=dict(required_params=[], optional_params=[]), 
    base_path_mappings=dict(required_params=[], optional_params=[]),
    client_certificate=dict(required_params=[], optional_params=[]), 
    client_certificates=dict(required_params=[], optional_params=[]),
    deployment=dict(required_params=[], optional_params=[]), 
    deployments=dict(required_params=[], optional_params=[]),
    domain_name=dict(required_params=[], optional_params=[]), 
    domain_names=dict(required_params=[], optional_params=[]),
    integration=dict(required_params=[], optional_params=[]),
    integration_response=dict(required_params=[], optional_params=[]),
    method=dict(required_params=[], optional_params=[]),
    method_response=dict(required_params=[], optional_params=[]),
    model=dict(required_params=[], optional_params=[]),
    models=dict(required_params=[], optional_params=[]),
    model_template=dict(required_params=[], optional_params=[]),
    resource=dict(required_params=[], optional_params=[]), 
    resources=dict(required_params=['rest_api_id'], optional_params=['position', 'limit']),
    rest_api=dict(required_params=[], optional_params=[]), 
    rest_apis=dict(required_params=[], optional_params=['position', 'limit']),
    stage=dict(required_params=[], optional_params=[]), 
    stages=dict(required_params=['rest_api_id'], optional_params=['deployment_id']),
    sdk=dict(required_params=[], optional_params=[]),
    )


import datetime

try:
    import boto3
    from botocore.exceptions import ClientError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


# ----------------------------------
#          Helper functions
# ----------------------------------

def pc(key):
    """
    Changes python key into Pascale case equivalent. For example, 'this_function_name' becomes 'ThisFunctionName'.

    :param key:
    :return:
    """

    return "".join([token.capitalize() for token in key.split('_')])


def cc(key):
    """
    Changes python key into camel case equivalent. For example, 'this_function_name' becomes 'thisFunctionName'.

    :param key:
    :return:
    """
    token = pc(key)

    return "{}{}".format(token[0].lower(), token[1:])


def get_api_params(params, module, resource_type, required=False):
    """
    Check for presence of parameters, required or optional and change parameter case for API.

    :param params: AWS parameters needed for API
    :param module: Ansible module reference
    :param resource_type:
    :param required:
    :return:
    """

    api_params = dict()

    for param in params:
        value = module.params.get(param)
        if value:
            api_params[cc(param)] = value
        else:
            if required:
                module.fail_json(msg='Parameter {0} required for this action on resource type {1}'.format(param, resource_type))

    return api_params


def fix_return(node):
    """
    fixup returned dictionary
    
    :param node:
    :return:
    """

    if isinstance(node, datetime.datetime):
        node_value = str(node)

    elif isinstance(node, list):
        node_value = [fix_return(item) for item in node]

    elif isinstance(node, dict):
        node_value = dict([(item, fix_return(node[item])) for item in node.keys()])

    else:
        node_value = node

    return node_value


# ----------------------------------
#   Resource management function
# ----------------------------------

def get_facts(client, module):
    """
    Needs a little more work....

    :param client:
    :param module:
    :return:
    """
    resource_type = module.params['type']

    api_method = getattr(client, 'get_{}'.format(resource_type))
    api_params = get_api_params(API_CONFIG[resource_type]['required_params'], module, resource_type, required=True)
    api_params.update(get_api_params(API_CONFIG[resource_type]['optional_params'], module, resource_type, required=False))

    try:
        results = api_method(**api_params)
    except ClientError, e:
        module.fail_json(msg='Error gathering facts for type {0}: {1}'.format(module.params['type'], e))

    return fix_return(results)


# ----------------------------------
#           Main function
# ----------------------------------

def main():
    """
    Main entry point.

    :return dict: ansible facts

    """

    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        # state=dict(default='present', required=False, choices=['present', 'absent', 'updated']),
        name=dict(default=None, required=False),
        type=dict(required=False, choices=API_CONFIG.keys(), default='account'),
        rest_api_id=dict(default=None, required=False),
        limit=dict(type='int', default=None, required=False)
         )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        mutually_exclusive=[],
        required_together=[]
    )

    # validate dependencies
    if not HAS_BOTO3:
        module.fail_json(msg='boto3 is required for this module.')

    try:
        region, endpoint, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
        aws_connect_kwargs.update(dict(region=region,
                                       endpoint=endpoint,
                                       conn_type='client',
                                       resource='apigateway'
                                       ))
        client = boto3_conn(module, **aws_connect_kwargs)
    except ClientError, e:
        module.fail_json(msg="Can't authorize connection - {0}".format(e))
    except Exception, e:
        module.fail_json(msg="Connection Error - {0}".format(e))

    response = get_facts(client, module)

    results = dict(ansible_facts=dict(results=response), changed=False)

    module.exit_json(**results)


# ansible import module(s) kept at ~eof as recommended

from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
