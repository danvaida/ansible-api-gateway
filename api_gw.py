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
module: api_gw

'''

EXAMPLES = '''
---
- hosts: localhost
  gather_facts: no

  - name: display stuff
    debug: var=results
'''

API_CONFIG = dict(
    api_key=dict(
        create=dict(required=['name', 'description', 'enabled', 'stage_keys'], optional=[], method='create'),
        read=dict(required=['api_key'], optional=[], method='get'),
        update=dict(required=['api_key'], optional=[], method='update'),
        delete=dict(required=['api_key'], optional=[], method='delete'),
    ),
    base_path_mapping=dict(
        read=dict(required=['domain_name', 'base_path'], optional=[], method='get'),
    ),
    client_certificate=dict(
        create=dict(required=['description'], optional=[], method='generate'),
        read=dict(required=['client_certificate_id'], optional=[], method='get'),
        update=dict(required=['client_certificate_id'], optional=['patch_operations'], method='update'),
        delete=dict(required=['client_certificate_id'], optional=[], method='delete'),
    ),
    deployment=dict(
        read=dict(required=['rest_api_id', 'deployment_id'], optional=[], method='get'),
    ),
    domain_name=dict(
        read=dict(required=['domain_name'], optional=[], method='get'),
    ),
    integration=dict(
        read=dict(required=['rest_api_id', 'resource_id', 'http_method'], optional=[], method='get'),
    ),
    integration_response=dict(
        read=dict(required=['rest_api_id', 'resource_id', 'http_method', 'status_code'], optional=[], method='get'),
    ),
    method=dict(
        create=dict(required=['rest_api_id', 'resource_id', 'http_method', 'authorization_type'],
                     optional=['api_key_required', 'request_parameters', 'request_models'],
                     method='put'),
        read=dict(required=['rest_api_id', 'resource_id', 'http_method'], optional=[], method='get'),
        update=dict(required=['rest_api_id', 'resource_id', 'http_method', 'patch_operations'], optional=[], method='update'),
        delete=dict(required=['rest_api_id', 'resource_id', 'http_method'], optional=[], method='delete'),
    ),
    method_response=dict(
        read=dict(required=['rest_api_id', 'resource_id', 'http_method', 'status_code'], optional=[], method='get'),
    ),
    model=dict(
        read=dict(required=['rest_api_id', 'model_name'], optional=['flatten'], method='get'),
    ),
    model_template=dict(
        read=dict(required=['rest_api_id', 'model_name'], optional=[], method='get'),
    ),
    resource=dict(
        create=dict(required=['rest_api_id', 'parent_id', 'path_part'], optional=[], method='create'),
        read=dict(required=['rest_api_id', 'resource_id'], optional=[], method='get'),
        update=dict(required=['rest_api_id', 'resource_id', 'patch_operations'], optional=[], method='update'),
        delete=dict(required=['rest_api_id', 'resource_id'], optional=[], method='delete'),
    ),
    rest_api=dict(
        create=dict(required=['name'], optional=['description', 'clone_from'], method='create'),
        read=dict(required=['rest_api_id'], optional=[], method='get'),
        update=dict(required=['rest_api_id', 'patch_operations'], optional=[], method='update'),
        delete=dict(required=['rest_api_id'], optional=[], method='delete'),
    ),
    stage=dict(
        create=dict(required=['rest_api_id', 'stage_name', 'deployment_id'],
                    optional=['description', 'cache_cluster_enabled', 'cache_cluster_size', 'variables'],
                    method='create'),
        read=dict(required=['rest_api_id', 'stage_name'], optional=[], method='get'),
        update=dict(required=['rest_api_id', 'stage_name', 'patch_operations'], optional=[], method='update'),
        delete=dict(required=['rest_api_id'], optional=[], method='delete'),

    )
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
    results = dict()
    changed = False
    api_params = dict()
    current_state = None

    state = module.params.get('state')

    api_method = getattr(client, 'get_{}'.format(resource_type))
    if not api_method:
        module.fail_json(msg="Programming error: resource {} has no get method.".format(resource_type))

    method_params = API_CONFIG[resource_type]['read']
    api_params = get_api_params(method_params['required'], module, resource_type, required=True)
    api_params.update(get_api_params(method_params['optional'], module, resource_type, required=False))

    try:
        results = api_method(**api_params)
        current_state = 'present'
    except ClientError, e:
        if e.response['Error']['Code'] == 'NotFoundException':           #       'ResourceNotFoundException':
            current_state = 'absent'
        else:
            module.fail_json(msg='Error gathering facts for type {0}: {1}'.format(resource_type, e))

    if state == current_state:
        # nothing to do but exit
        changed = False
    else:
        if state == 'absent':
            method_params = API_CONFIG[resource_type]['delete']
            api_params = get_api_params(method_params['required'], module, resource_type, required=True)
            api_params.update(get_api_params(method_params['optional'], module, resource_type, required=False))
            api_method = getattr(client, '{}_{}'.format(method_params['method'], resource_type))

            try:
                if not module.check_mode:
                    results = api_method(**api_params)
                changed = True
            except ClientError, e:
                module.fail_json(msg='Error deleting type {0}: {1}'.format(resource_type, e))

        elif state == 'present':
            method_params = API_CONFIG[resource_type]['create']
            api_params = get_api_params(method_params['required'], module, resource_type, required=True)
            api_params.update(get_api_params(method_params['optional'], module, resource_type, required=False))
            api_method = getattr(client, '{}_{}'.format(method_params['method'], resource_type))

            try:
                if not module.check_mode:
                    results = api_method(**api_params)
                changed = True
            except ClientError, e:
                module.fail_json(msg='Error creating type {0}: {1}'.format(resource_type, e))
        else:
            method_params = API_CONFIG[resource_type]['update']
            api_params = get_api_params(method_params['required'], module, resource_type, required=True)
            api_params.update(get_api_params(method_params['optional'], module, resource_type, required=False))
            api_method = getattr(client, '{}_{}'.format(method_params['method'], resource_type))

            try:
                if not module.check_mode:
                    results = api_method(**api_params)
                changed = True
            except ClientError, e:
                module.fail_json(msg='Error updating type {0}: {1}'.format(resource_type, e))

    return dict(changed=changed, results=fix_return(results))


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
        state=dict(default='present', required=False, choices=['present', 'absent', 'updated']),
        type=dict(required=False, choices=API_CONFIG.keys(), default='account'),
        rest_api_id=dict(default=None, required=False),
        limit=dict(type='int', default=None, required=False),
        position=dict(default=None, required=False),
        resource_id=dict(default=None, required=False),
        stage_name=dict(default=None, required=False),
        sdk_type=dict(default=None, required=False),
        parameters=dict(type='dict', default=None, required=False),
        stage_keys=dict(type='list', default=None, required=False),
        patch_operations=dict(type='list', default=None, required=False),
        flatten=dict(type='bool', default=None, required=False),
        enabled=dict(type='bool', default=None, required=False),
        api_key_required=dict(type='bool', default=None, required=False),
        http_method=dict(default=None, required=False),
        authorization_type=dict(default=None, required=False),
        status_code=dict(default=None, required=False),
        deployment_id=dict(default=None, required=False),
        domain_name=dict(default=None, required=False),
        model_name=dict(default=None, required=False),
        base_path=dict(default=None, required=False),
        name=dict(default=None, required=False),
        parent_id=dict(default=None, required=False),
        path_part=dict(default=None, required=False),
        description=dict(default=None, required=False),
        client_certificate_id=dict(default=None, required=False),
        clone_from=dict(default=None, required=False),
        cache_cluster_enabled=dict(type='bool', default=None, required=False),
        cache_cluster_size=dict(default=None, required=False, choices=['0.5', '1.6', '13.5', '28.4', '58.2', '118', '237']),
        variables=dict(type='dict', default=None, required=False),
        request_parameters=dict(type='dict', default=None, required=False),
        request_models=dict(type='dict', default=None, required=False),
         )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
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

    results = dict(ansible_facts=response['results'], changed=response['changed'])

    module.exit_json(**results)


# ansible import module(s) kept at ~eof as recommended

from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
