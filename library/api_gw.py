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

import datetime
import yaml
import json
import sys

from collections import defaultdict

try:
    import boto3
    import boto
    from botocore.exceptions import ClientError, MissingParametersError, ParamValidationError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

try:
    from swagger_spec_validator import validate_spec_url
    from swagger_spec_validator.common import SwaggerValidationError
    HAS_SWAGGER_VALIDATOR = True
except ImportError:
    HAS_SWAGGER_VALIDATOR = False


DOCUMENTATION = '''
---
module: api_gw
short_description: Creates, updates or deletes AWS API Gateway resources.
description:
    - This module allows the management of AWS API Gateway resources via the Ansible framework.
version_added: "2.1"
author: Pierre Jodouin (@pjodouin)
options:

'''

EXAMPLES = '''
---
- hosts: localhost
  gather_facts: no

  - name: display stuff
    debug: var=results
'''


SWAGGER_SPEC = dict(
    swagger=dict(required=True),
    info=dict(required=True),
    definitions=dict(required=False),
    base_path=dict(required=False),
    responses=dict(required=False),
    consumes=dict(required=False),
    produces=dict(required=False),
    paths=dict(required=True, type='dict', obj='path'),
    schemes=dict(required=False),
    security_definitions=dict(required=False),
    host=dict(required=False),
    parameters=dict(required=False),
 )


class TreeNode:
    """
    Represents a node in a tree-like structure of API Gateway resources.
    """

    rest_api_id = None

    def __init__(self, path, methods=None, resource_id=None, parent_id=None):

        self.path = path
        self.path_part = path.split('/')[-1]
        self.resource_id = resource_id
        self.parent_id = parent_id

        if methods:
            self.methods = methods
        else:
            self.methods = {}

        self.child_nodes = {}

    def __unicode__(self):
        return u'<TreeNode: {0}'.format(self.path)

    def __repr__(self):
        return u'<TreeNode: {0}'.format(self.path)

    def http_methods(self):
        return self.methods.keys() or None

    def http_method_responses(self, http_method):
        try:
            return self.methods[http_method]['responses']
        except KeyError:
            return None

    def http_method_response(self, http_method, status_code):
        try:
            return self.methods[http_method]['responses'][status_code]
        except KeyError:
            return None

    def http_method_integration(self, http_method):
        try:
            return self.methods[http_method]['x-amazon-apigateway-integration']
        except KeyError:
            return None

    def http_method_integration_response(self, http_method, status_code):
        try:
            return self.methods[http_method]['x-amazon-apigateway-integration']['responses'][status_code]
        except KeyError:
            return None

    def build_from_path(self, path, methods=None):

        if path == '/':
            self.methods = methods
            return

        current_node = self
        current_path = ['']
        path_nodes = path.split('/')[1:]
        for path_part in path_nodes:
            current_path.append(path_part)
            if path_part not in current_node.child_nodes:
                current_node.child_nodes[path_part] = TreeNode('/'.join(current_path))
            current_node = current_node.child_nodes[path_part]
        current_node.methods = methods

        return


# ----------------------------------------------------
#   hacks to implement a python tree-like structure
# ----------------------------------------------------

def py_tree():
    """
    Create a python tree structure with magic.

    :return: tree obj
    """
    return defaultdict(py_tree)


def tree_to_dicts(tree):
    """
    Converts tree nodes to proper python dictionaries.

    :param tree:
    :return: dict
    """
    try:
        return dict((key, tree_to_dicts(tree[key])) for key in tree)
    except TypeError:
        return tree


def add(tree, resource_path, node_content):
    """
    Builds tree nodes based on resource paths. Content is appended as leaf nodes.

    :param tree:
    :param resource_path:
    :param node_content:
    """
    nodes = resource_path.split('/')[1:]
    for node in nodes:
        tree = tree[node]

    tree.update(_=node_content)


# ----------------------------------------------------
#          Helper functions
# ----------------------------------------------------

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


def get_api_params(module):
    """
    Check for presence of parameters, required or optional and change parameter case for API.

    :param params: AWS parameters needed for API
    :param module: Ansible module reference
    :param resource_type:
    :param required:
    :return:
    """
    params = module.params['resource_params']
    api_params = dict()

    for key in params.keys():
        value = params[key]
        if value:
            api_params[cc(key)] = value

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

def invoke_api(client, module, swagger_spec):
    """
    Needs a little more work....

    :param client:
    :param module:
    :return:
    """
    # resource_type = module.params['resource_type']
    results = dict()
    changed = False
    current_state = 'absent'

    state = module.params.get('state')

    try:
        info_title = swagger_spec['info']['title']
    except KeyError:
        info_title = None
        module.fail_json(msg="Missing required value in swagger spec: info.title")

    # check if REST API ID is specified, exists and is valid
    rest_api_id = module.params['rest_api_id']
    if rest_api_id == '*':
        try:
            rest_apis = client.get_rest_apis(limit=500)['items']
            choices = [api for api in rest_apis if api['name'] == info_title]
        except ClientError as e:
            choices = None
            module.fail_json(msg="Error retrieving REST APIs: {0}".format(e))

        if len(choices) > 1:
            module.fail_json(msg="More than one API found: {0}".format(choices))
        elif len(choices) > 0:
            try:
                rest_api_id = choices[0]['id']
                rest_api = client.get_rest_api(restApiId=rest_api_id)
                current_state = 'present'
            except (ClientError, ParamValidationError, MissingParametersError) as e:
                if not e.response['Error']['Code'] == 'NotFoundException':
                    module.fail_json(msg='Error retrieving REST API: {0}'.format(e))

    # check for obvious type error: must be a dictionary
    if not isinstance(swagger_spec, dict):
        module.fail_json(msg='Invalid Swagger specification: {0}'.format(swagger_spec))

    # process each high-level swagger spec node type
    facts = dict()

    for key in SWAGGER_SPEC.keys():
        if swagger_spec.get(cc(key)):
            this_module = sys.modules[__name__]
            try:
                this_module_function = getattr(this_module, 'process_{}'.format(key))
                results = this_module_function(module, client, swagger_spec[cc(key)])
                facts.update(results)
            except AttributeError:
                pass

        elif SWAGGER_SPEC[key].get('required'):
            module.fail_json(msg="Element '{0}' absent but required - Error".format(key))

    if state == 'present':
        if current_state == 'present':

            # nothing to do but exit
            facts.update(action='nothing', rest_api=rest_api)
            changed = False
        else:
            # create API

            try:
                rest_api = client.create_rest_api(
                    name=facts['info']['title'],
                    description=facts['info']['description']
                )
                facts.update(action='created', rest_api=rest_api)
                rest_api_id = rest_api['id']
                changed = True

            except (ClientError, ParamValidationError, MissingParametersError) as e:
                module.fail_json(msg='Error creating REST API: {0}'.format(e))

            # create models
            try:
                for model in facts['models'].keys():
                    schema = facts['models'][model]
                    schema.update({
                        "$schema": "http://json-schema.org/draft-04/schema#",
                        "type": "object",
                        "title": "{0} schema".format(model)
                    })
                    results = client.create_model(
                        restApiId=rest_api_id,
                        name=model,
                        description='added by Ansible module',
                        contentType='application/json',
                        schema=json.dumps(schema)
                    )

            except (ClientError, ParamValidationError, MissingParametersError) as e:
                module.fail_json(msg='Error creating API model: {0}'.format(e))

            # create aws resource tree from swagger spec tree
            # root = facts.pop('tree')
            root = facts['tree']
            try:
                resources = client.get_resources(restApiId=rest_api_id, limit=500)['items']
            except ClientError as e:
                module.fail_json(msg="Error retrieving API's resources: {0}".format(e))

            resource_dict = dict()
            for resource in resources:
                resource_dict[resource['path']] = resource

            context = dict(
                rest_api_id=rest_api_id,
                resources=resource_dict,
            )
            results = crawl_tree(client, module, root, context)

    else:
        if current_state == 'present':
            try:
                rest_api = client.delete_rest_api(restApiId=rest_api_id)
                facts.update(action='deleted')
                changed = True

            except (ClientError, ParamValidationError, MissingParametersError) as e:
                module.fail_json(msg='Error deleting REST API: {0}'.format(e))

    if 'tree' in facts:
        facts.pop('tree')

    return dict(changed=changed, results=dict(api_gw_facts=dict(current_state=current_state, swagger=fix_return(facts))))


def crawl_tree(client, module, node, context):

    rest_api_id = context['rest_api_id']
    parent_id = context.get('parent_id')

    if parent_id:
        try:
            resource = client.create_resource(
                restApiId=rest_api_id,
                pathPart=node.path_part,
                parentId=parent_id
                )
            node.resource_id = resource['id']
            node.parent_id = resource['parentId']
            context['parent_id'] = resource['id']

        except (ClientError, AttributeError) as e:
            module.fail_json(msg="Error creating API resource {0} pid: {1}: {2}".format(node, parent_id, e))
    else:
        # must be root node
        node.resource_id = context['resources'][node.path]['id']
        context['parent_id'] = node.resource_id

    # # add methods
    # try:

    for child_node in node.child_nodes:
        context['parent_id'] = node.resource_id
        crawl_tree(client, module, node.child_nodes[child_node], context)

    return


def process_swagger(module, client, version):

    if not version == '2.0':
        module.fail_json(msg="Invalid Swagger specification version: '{0}' ".format(version))

    return dict(version=version)


def process_info(module, client, info_obj):

    if 'description' in info_obj:
        description = info_obj['description']
    else:
        description = 'Created by Ansible API Gateway module.'

    title = info_obj['title']

    return dict(info=dict(description=description, title=title))


def process_paths(module, client, paths_obj):

    swagger_tree = TreeNode('/')

    for path in paths_obj.keys():
        swagger_tree.build_from_path(path, paths_obj[path])

    return dict(resources=paths_obj, tree=swagger_tree)


def process_definitions(module, client, definitions):

    models = dict()

    for ref in definitions:
        models[ref] = definitions[ref]

    return dict(models=models)


def process_security_definitions(module, client, definitions):

    security_definitions = dict()

    for ref in definitions:
        security_definitions[ref] = definitions[ref]

    return dict(securityDefinitions=security_definitions)


def process_base_path(module, client, path):

    base_path = None

    if path:
        base_path = path

    return dict(basePath=base_path)

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
        state=dict(default='present', required=False, choices=['present', 'absent']),
        rest_api_id=dict(required=True,  default=None, aliases=['api_id']),
        swagger_spec=dict(required=True, default=None, aliases=['oai_spec']),
        deploy=dict(type='bool', required=False, default=None),
        stage_name=dict(required=False, default=None),
        stage_description=dict(required=False, default=None)
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[],
        required_together=[['deploy', 'stage_name','stage_description']]
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

    spec_file = module.params['swagger_spec']

    if HAS_SWAGGER_VALIDATOR:
        if spec_file.endswith(('.json', '.jsn')):
            try:
                validate_spec_url('file://{}'.format(spec_file))
            except SwaggerValidationError as e:

                msg = e.message.split('\n', 1)[0]
                module.fail_json(msg='Error validating Swagger specification: {0}'.format(msg))
        else:
            #TODO: could convert YAML to JSON in tmp folder
            pass

    # read the swagger/oai spec file as it's assumed to be valid
    try:
        with open(spec_file, 'r') as spec_data:
            if spec_file.endswith(('.yml', '.yaml')):
                swagger_spec = yaml.load(spec_data)
            else:
                swagger_spec = json.load(spec_data)

    except Exception as e:
        module.fail_json(msg='Invalid or missing API specification: {0}'.format(e))


    response = invoke_api(client, module, swagger_spec)

    results = dict(ansible_facts=response['results'], changed=response['changed'])

    module.exit_json(**results)


# ansible import module(s) kept at ~eof as recommended

from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
