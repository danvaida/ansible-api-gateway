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
short_description: Gathers AWS API Gateway details as Ansible facts
description:
  - Gathers various details related to REST APIs.
version_added: "2.1"
options:
  query:
    description:
      - Specifies the resource type for which to gather facts.  Leave blank to retrieve all facts.
    required: true
    choices: [ 'all', 'account', 'api_key', 'api_keys', 'base_path_mapping', 'base_path_mappings',
               'client_certificate', 'client_certificates', 'deployment', 'deployments', 'domain_name',
                'domain_names', 'integration', 'integration_response', 'method', 'method_response',
                'model', 'model_template', 'models', 'resource', 'resources', 'rest_api', 'rest_apis',
                'sdk', 'stage', 'stages'
                ]
    default: "all"

  rest_api_id
    description:
      - The identifier of the RestApi resource.
    required: false
    default: none

  limit
    description:
      - The maximum number of RestApi resources in the collection to get information about.
        The default limit is 25. It should be an integer between 1 - 500.
    required: false
    default: none
  
  position
    description:
      - The position of the current resource in the collection to get information about.
    required: false
    default: none

  resource_id
    description:
      - The unique identifier for the resource within the API.
    required: false
    default: none

  stage_name
    description:
      - The name of the Stage resource to get information about.
    required: false
    default: none

  sdk_type
    description:
      - The language for the generated SDK. Currently javascript, android, and objectivec
        (for iOS) are supported.
    required: false
    default: none

  parameters
    description:
      - A key-value map of query string parameters that specify properties of the SDK,
        depending on the requested sdkType. For sdkType 'objectivec', a parameter named
        'classPrefix' is required. For sdkType 'android', parameters named 'groupId',
        'artifactId', 'artifactVersion', and 'invokerPackage' are required.
    required: false
    default: none

  flatten
    description:
      - Resolves all external model references and returns a flattened model schema.
    required: false
    default: none

  http_method
    description:
      - Specifies the method request's HTTP method type.
    required: false
    default: none

  status_code
    description:
      - The status code identifier for the MethodResponse resource.
    required: false
    default: none

  deployment_id
    description:
      - The identifier of the Deployment resource to get information about.
    required: false
    default: none

  domain_name
    description:
      - The name of the DomainName resource.
    required: false
    default: none

  model_name
    description:
      - The name of the model as an identifier.
    required: false
    default: none

  base_path
    description:
      - The base path name that callers of the API must provide as part of the URL
        after the domain name.
    required: false
    default: none

  client_certificate_id
    description:
      - The identifier of the ClientCertificate resource to be described.
    required: false
    default: none

author: Pierre Jodouin (@pjodouin)
requirements:
    - boto3
extends_documentation_fragment:
    - aws

'''

EXAMPLES = '''
---
# Simple example listing all info for a given rest_api_id
- name: List all for a specific function
  api_gw_facts:
    query: all
    rest_api_id: 'abcd123'

- name: show api gateway facts
  debug: var=api_gw_facts
'''

RETURN = '''
---

'''

API_CONFIG = dict(
    account=dict(
        get=dict(required=[], optional=[]),
    ),
    api_key=dict(
        get=dict(required=['api_key'], optional=[]),
    ),
    api_keys=dict(
        get=dict(required=[], optional=['position', 'limit']),
    ),
    base_path_mapping=dict(
        get=dict(required=['domain_name', 'base_path'], optional=[]),
    ),
    base_path_mappings=dict(
        get=dict(required=['domain_name'], optional=['position', 'limit']),
    ),
    client_certificate=dict(
        get=dict(required=['client_certificate_id'], optional=[]),
    ),
    client_certificates=dict(
        get=dict(required=[], optional=['position', 'limit']),
    ),
    deployment=dict(
        get=dict(required=['rest_api_id', 'deployment_id'], optional=[]),
    ),
    deployments=dict(
        get=dict(required=['rest_api_id'], optional=['position', 'limit']),
    ),
    domain_name=dict(
        get=dict(required=['domain_name'], optional=[]),
    ),
    domain_names=dict(
        get=dict(required=[], optional=['position', 'limit']),
    ),
    integration=dict(
        get=dict(required=['rest_api_id', 'resource_id', 'http_method'], optional=[]),
    ),
    integration_response=dict(
        get=dict(required=['rest_api_id', 'resource_id', 'http_method', 'status_code'], optional=[]),
    ),
    method=dict(
         get=dict(required=['rest_api_id', 'resource_id', 'http_method'], optional=[]),
    ),
    method_response=dict(
        get=dict(required=['rest_api_id', 'resource_id', 'http_method', 'status_code'], optional=[]),
    ),
    model=dict(
        get=dict(required=['rest_api_id', 'model_name'], optional=['flatten']),
    ),
    models=dict(
        get=dict(required=['rest_api_id'], optional=['position', 'limit']),
    ),
    model_template=dict(
         get=dict(required=['rest_api_id', 'model_name'], optional=[]),
    ),
    resource=dict(
         get=dict(required=['rest_api_id', 'resource_id'], optional=[]),
    ),
    resources=dict(
        get=dict(required=['rest_api_id'], optional=['position', 'limit']),
    ),
    rest_api=dict(
        get=dict(required=['rest_api_id'], optional=[]),
    ),
    rest_apis=dict(
        get=dict(required=[], optional=['position', 'limit']),
    ),
    stage=dict(
       get=dict(required=['rest_api_id', 'stage_name'], optional=[]),
    ),
    stages=dict(
        get=dict(required=['rest_api_id'], optional=['deployment_id']),
    ),
    sdk=dict(
        get=dict(required=['rest_api_id', 'stage_name', 'sdk_type'], optional=['parameters']),
    )
)


import datetime

try:
    import boto3
    import boto
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

    method_params = API_CONFIG[resource_type]['get']
    api_params = get_api_params(method_params['required'], module, resource_type, required=True)
    api_params.update(get_api_params(method_params['optional'], module, resource_type, required=False))

    try:
        results = api_method(**api_params)
    except ClientError, e:
        module.fail_json(msg='Error gathering facts for type {0}: {1}'.format(resource_type, e))

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
        query=dict(required=False, choices=API_CONFIG.keys(), default='account'),
        rest_api_id=dict(default=None, required=False),
        limit=dict(type='int', default=None, required=False),
        position=dict(default=None, required=False),
        resource_id=dict(default=None, required=False),
        stage_name=dict(default=None, required=False),
        sdk_type=dict(default=None, required=False),
        parameters=dict(type='dict', default=None, required=False),
        flatten=dict(type='boolean', default=None, required=False),
        http_method=dict(default=None, required=False),
        status_code=dict(default=None, required=False),
        deployment_id=dict(default=None, required=False),
        domain_name=dict(default=None, required=False),
        model_name=dict(default=None, required=False),
        base_path=dict(default=None, required=False),
        client_certificate_id=dict(default=None, required=False),
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

    results = dict(ansible_facts=dict(results=response), changed=False)

    module.exit_json(**results)


# ansible import module(s) kept at ~eof as recommended
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
