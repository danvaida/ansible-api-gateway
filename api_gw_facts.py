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
            api_params[pc(param)] = value
        else:
            if required:
                module.fail_json(msg='Parameter {0} required for this action on resource type {1}'.format(param, resource_type))

    return api_params


# ----------------------------------
#   Resource management functions
# ---------------------------------
def _resource(client, module):
    """
    Needs a little more work....

    :param client:
    :param module:
    :return:
    """
    changed = False

    # TODO: everything

    return dict(changed=changed)


# ----------------------------------
#           Main function
# ----------------------------------

def main():
    """
    Main entry point.

    :return dict: ansible facts

    """

    type_choices = ['account',
                    'api_key', 'api_keys',
                    'base_path_mapping', 'base_path_mappings',
                    'client_certificate', 'client_certificates',
                    'deployment', 'deployments',
                    'domain_name', 'domain_names',
                    'integration',
                    'integration_response',
                    'method,'
                    'method_response',
                    'model', 'models',
                    'model_template',
                    'resource', 'resources',
                    'rest_api', 'rest_apis',
                    'stage', 'stages',
                    'sdk'
                    ]

    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        # state=dict(default='present', required=False, choices=['present', 'absent', 'updated']),
        name=dict(default=None, required=True),
        type=dict(required=True, choices=type_choices, default='all')
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

    response = _resource(client, module)

    results = dict(ansible_facts=dict(results=response['results']), changed=response['changed'])

    module.exit_json(**results)


# ansible import module(s) kept at ~eof as recommended
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
