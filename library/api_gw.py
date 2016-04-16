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
import re
import os
import tempfile

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
  state:
    description:
      - Describes the desired state and defaults to "present".
    required: true
    default: "present"
    choices: ["present", "absent"]
  rest_api_id:
    description:
      - Unique identifier of API. Use '*' if unknown, when first creating the API for example.
    required: true
    default: none
  swagger_spec:
    description:
      - File path to JSON/YAML Swagger API specification file.
    required: true
    default: none
  deploy:
    description:
      - Specifies whether the API should be deployed or not.
    required: false
    default: none
  stage_name:
    description:
      - Stage name of deployment.
    required: false
    default: none
  stage_description:
    description:
      - Stage description of deployment.
    required: false
    default: none
requirements:
    - boto3
extends_documentation_fragment:
    - aws
'''

EXAMPLES = '''
---
- hosts: localhost
  gather_facts: no
  vars:
    state: present
    api_gw_spec_file: /path/to/samples/LambdaMicroservice-Dev.yaml
    deployment_package: lambda.zip

  tasks:
  - name: AWS API Gateway
    api_gw:
      state: "{{ state | default('present') }}"
      api_id: '*'
      deploy_api: True
      swagger_spec: "{{ api_gw_spec_file }}"

  - name: show results
    debug: var=api_gw_facts
'''

# top level swagger specification keys
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

# AWS resource limits
AWS_REST_API_LIMIT = 60
AWS_API_RESOURCE_LIMIT = 300

class TreeNode:
    """
    Represents a node in a tree-like structure of API Gateway resources.
    """

    rest_api_id = None
    base_path = None
    swagger_version = '2.0'

    def __init__(self, path, parent=None, **kwargs):
        """

        :param path:
        :param methods:
        :param resource_id:
        :param parent_id:
        :return: obj
        """

        self.path = path
        self.path_part = path.split('/')[-1]
        self.resource_id = kwargs.get('resource_id')
        self.parent = parent
        self.methods = kwargs.get('methods', dict())
        self.child_nodes = dict()

    def __unicode__(self):
        return u'<TreeNode: {0}>'.format(self.path)

    def __repr__(self):
        return u'<TreeNode: {0}>'.format(self.path)

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
                current_node.child_nodes[path_part] = TreeNode('/'.join(current_path), current_node)
            current_node = current_node.child_nodes[path_part]
        current_node.methods = methods

        return

    def http_method(self, http_method):
        try:
            return self.methods[http_method]
        except KeyError:
            return None

    def http_methods(self):
        return self.methods.keys()

    def http_method_responses(self, http_method):
        try:
            return self.methods[http_method]['responses'].keys()
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

    def http_method_integration_responses(self, http_method):
        try:
            return self.methods[http_method]['x-amazon-apigateway-integration']['responses'].keys()
        except KeyError:
            return None

    def http_method_integration_response(self, http_method, status_code):
        try:
            return self.methods[http_method]['x-amazon-apigateway-integration']['responses'][status_code]
        except KeyError:
            return None

    # used for development only
    def print_tree(self, level=1):

        print ' '*2*level, self.path_part, '(', self.path, ')'

        if self.methods:
            for method in self.methods.keys():
                print ' '*2*level, '   +', method
                print ' '*2*level, '    |_', self.methods[method]

        for child in self.child_nodes.keys():
            self.child_nodes[child].print_tree(level+1)


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

    return "{0}{1}".format(token[0].lower(), token[1:])


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


def validate_swagger_spec(spec_file):
    """
    Validate the swagger specification using validator module.

    :param spec_file:
    :return:
    """

    try:
        validate_spec_url('file://{}'.format(spec_file))
        msg = None
        valid = True
    except SwaggerValidationError as e:
        msg = e.message.split('\n', 1)[0]
        valid = False

    return dict(valid=valid, msg=msg)


# ----------------------------------
#   Resource management function
# ----------------------------------

def get_rest_api(client, module, swagger_spec):

    rest_api = None
    info_title = None
    rest_api_id = module.params['rest_api_id']

    try:
        info_title = swagger_spec['info']['title']
    except KeyError:
        module.fail_json(msg="Missing required value in swagger spec: info.title")

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
            except (ClientError, ParamValidationError, MissingParametersError) as e:
                if not e.response['Error']['Code'] == 'NotFoundException':
                    module.fail_json(msg='Error retrieving REST API: {0}'.format(e))

    return rest_api


def get_resource_by_path(client, module, rest_api_id, path):

    resource = None
    try:
        resource_items = client.get_resources(restApiId=rest_api_id, limit=500)['items']
    except ClientError as e:
        resource_items = None
        module.fail_json(msg="Error retrieving API's resources: {0}".format(e))

    for item in resource_items:
        if item['path'] == path:
            resource = item
            break

    return resource


def create_rest_api(client, module, title, description):
    """
    Creates a new API with 'default' model and root resource node.

    :param client:
    :param module:
    :param title:
    :param description:
    :return: API Id
    """

    rest_api = None
    try:
        rest_api = client.create_rest_api(
            name=title,
            description=description
        )

    except (ClientError, ParamValidationError, MissingParametersError) as e:
        module.fail_json(msg='Error creating REST API: {0}'.format(e))

    return rest_api['id']


def delete_rest_api(client, module, rest_api_id):
    """
    Deletes the entire API, including associated models.

    :param client:
    :param module:
    :param rest_api_id:
    :return:
    """

    try:
        client.delete_rest_api(restApiId=rest_api_id)

    except (ClientError, ParamValidationError, MissingParametersError) as e:
        module.fail_json(msg='Error deleting REST API: {0}'.format(e))

    return


def create_models(client, module, rest_api_id, schemas):

    models = None

    try:
        for model in schemas.keys():
            schema = schemas[model]
            schema.update({
                "$schema": "http://json-schema.org/draft-04/schema#",
                "type": "object",
                "title": "{0} schema".format(model)
            })
            models = client.create_model(
                restApiId=rest_api_id,
                name=model,
                description='added by Ansible module',
                contentType='application/json',
                schema=json.dumps(schema)
            )

    except (ClientError, ParamValidationError, MissingParametersError) as e:
        #TODO: should report warning or update existing model
        if not e.response['Error']['Code'] == 'ConflictException':
            module.fail_json(msg='Error creating API model {0}: {1}'.format(model, e))

    return models


def create_resource(client, module, rest_api_id, parent_id, path_part):

    resource = None
    try:
        resource = client.create_resource(
            restApiId=rest_api_id,
            pathPart=path_part,
            parentId=parent_id
            )

    except (ClientError, ParamValidationError, MissingParametersError) as e:
        module.fail_json(msg="Error creating API resource {0} pid: {1}: {2}".format(path_part, parent_id, e))

    return resource


def put_method(client, module, node, http_method):

    method_params = node.http_method(http_method)
    security = node.security

    api_params = dict(
            restApiId=node.rest_api_id,
            resourceId=node.resource_id,
            httpMethod=http_method
    )

    if 'x-amazon-apigateway-auth' in method_params:
        api_params['authorizationType'] = method_params['x-amazon-apigateway-auth'].get('type', 'NONE')
    else:
        api_params['authorizationType'] = 'NONE'

    #TODO: add support for custom authorizers type='CUSTOM'

    if 'security' in method_params:
        for item_dict in method_params['security']:
            if 'api_key' in item_dict:
                api_params['apiKeyRequired'] = True
            if 'sigv4' in item_dict and 'sigv4' in security:
                print "###### SIGV4  "

    if 'consumes' in method_params:
        content_types = list(method_params['consumes'])
    else:
        content_types = []

    # Iterate through parameters, which can be of types querystring, header, path or body.
    # The 'body' parameters are used in combination with consumed content_types to establish the
    # 'requestModels' mappings.
    request_models = []
    if 'parameters' in method_params:
        request_parameters = dict()
        for parameter in method_params['parameters']:
            if parameter['in'] == 'query':
                destination = 'method.request.{0}.{1}'.format('querystring', parameter['name'])
                request_parameters[destination] = parameter['required']
            elif parameter['in'] in ('header', 'path'):
                destination = 'method.request.{0}.{1}'.format(parameter['in'], parameter['name'])
                request_parameters[destination] = parameter['required']
            elif parameter['in'] == 'body' and '$ref' in parameter.get('schema', []):
                request_models.append(parameter['schema']['$ref'].split('/')[-1])
        if request_parameters:
            api_params['requestParameters'] = request_parameters

    # sanity check, making sure both lists are equal in length before assigning the mappings
    if len(content_types) == len(request_models):
        api_params['requestModels'] = dict(zip(content_types, request_models))

    try:
        method = client.put_method(**api_params)

    except (ClientError, ParamValidationError, MissingParametersError) as e:
        method = None
        module.fail_json(msg="Error creating HTTP method {0} rid: {1}: {2}".format(http_method, node.resource_id, e))

    return method


def put_method_response(client, module, rest_api_id, resource_id, http_method, status_code, response):

    method_response = None

    if not re.match(r'^[2-6]\d\d$', str(status_code)):
        module.fail_json(msg="Error creating response {0} for method {1} rid: {2}: invalid response code.".format(status_code, http_method, resource_id))

    api_params = dict(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        statusCode=str(status_code)
    )

    if 'headers' in response:
        response_parameters = dict()
        for header in response['headers'].keys():
            destination = 'method.response.header.{0}'.format(header)
            response_parameters[destination] = True

        if response_parameters:
            api_params['responseParameters'] = response_parameters

    try:
        method_response = client.put_method_response(**api_params)

    except (ClientError, ParamValidationError, MissingParametersError) as e:
        module.fail_json(msg="Error creating response {0} for method {1} rid: {2}: {3}".format(status_code, http_method, resource_id, e))

    return method_response


def put_integration(client, module, rest_api_id, resource_id, http_method, integration):

    method_integration = None

    api_params = dict(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        type=integration['type'].upper(),
    )

    if 'httpMethod' in integration:
        api_params['integrationHttpMethod'] = integration['httpMethod']

    for optional_params in ('uri', 'credentials', 'requestParameters', 'requestTemplates', 'cacheNameSpace'):
        if optional_params in integration:
            api_params[optional_params] = integration[optional_params]

    if 'cacheKeyParameters' in integration:
        cache_key_parameters = []
        for parameter in integration['cacheKeyParameters']:
            cache_key_parameters.append('method.request.querystring.{0}'.format(parameter.split('.')[-1]))
        if cache_key_parameters:
            api_params['cacheKeyParameters'] = cache_key_parameters

    try:
        method_integration = client.put_integration(**api_params)
    except (ClientError, ParamValidationError, MissingParametersError) as e:
        module.fail_json(msg="Error creating integration for method {0} rid: {1}: {2}".format(http_method, resource_id, e))

    return method_integration


def put_integration_response(client, module, rest_api_id, resource_id, http_method, selection_pattern, integration_response):

    response = None

    api_params = dict(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        statusCode=integration_response['statusCode'],
        selectionPattern=selection_pattern
    )

    for optional_params in ('responseParameters', 'responseTemplates', ):
        if optional_params in integration_response:
            api_params[optional_params] = integration_response[optional_params]

    try:
        response = client.put_integration_response(**api_params)
    except (ClientError, ParamValidationError, MissingParametersError) as e:
        module.fail_json(msg="Error creating integration response '{0}' for method '{1}', rid: {2}: {3}".format(selection_pattern, http_method, resource_id, e))

    return response


def manage_state(client, module, swagger_spec):
    """

    :param client:
    :param module:
    :param swagger_spec:
    :return:
    """

    results = dict()
    changed = False
    current_state = 'absent'

    state = module.params.get('state')

    rest_api = get_rest_api(client, module, swagger_spec)
    if rest_api:
        current_state = 'present'
        rest_api_id = rest_api['id']

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
            rest_api_id = create_rest_api(client, module, facts['info']['title'], facts['info']['description'])

            # create models
            create_models(client, module, rest_api_id, facts['models'])

            # create aws resource tree from swagger spec tree
            root = facts.pop('tree')
            root.resource_id = get_resource_by_path(client, module, rest_api_id, '/')['id']
            TreeNode.rest_api_id = rest_api_id
            crawl_tree(client, module, root)

            changed = True
    else:
        if current_state == 'present':
            # delete the API
            delete_rest_api(rest_api_id)
            changed = True

    if 'tree' in facts:
        facts.pop('tree')

    return dict(changed=changed, results=dict(api_gw_facts=dict(current_state=current_state, swagger=fix_return(facts))))


def crawl_tree(client, module, node):

    print "crawl resource_id: ", node.resource_id

    if node.parent:
        # not the root node
        resource = create_resource(client, module, node.rest_api_id, node.parent.resource_id, node.path_part)
        node.resource_id = resource['id']

        for http_method in node.http_methods():
            put_method(client, module, node, http_method)
            for status_code in node.http_method_responses(http_method):
                put_method_response(client, module, node.rest_api_id, node.resource_id, http_method, status_code, node.http_method_response(http_method, status_code))

            put_integration(client, module, node.rest_api_id, node.resource_id, http_method, node.http_method_integration(http_method))

            for selection_pattern in node.http_method_integration_responses(http_method):
                put_integration_response(client, module, node.rest_api_id, node.resource_id, http_method, selection_pattern , node.http_method_integration_response(http_method, selection_pattern))

    for child_node in node.child_nodes:
        print "child node: ", child_node
        crawl_tree(client, module, node.child_nodes[child_node])

    return


def process_swagger(module, client, version):

    swagger_version = '2.0'

    if version:
        swagger_version = version
        TreeNode.swagger_version = version

    return dict(version=swagger_version)


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

    print '\n** Resource Tree **\n'
    swagger_tree.print_tree()

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
        TreeNode.base_path = path

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
        stage_description=dict(required=False, default=None),
        api_resource_limit=dict(type='int', required=False, default=300),
        rest_api_limit=dict(type='int', required=False, default=60)
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

    if module.params['rest_api_limit'] < 501:
        AWS_REST_API_LIMIT  =  module.params['res_api_limit']

    if module.params['resource_limit'] < 501:
        AWS_API_RESOURCE_LIMIT  =  module.params['api_resource_limit']

    spec_file = module.params['swagger_spec']

    try:
        with open(spec_file, 'r') as spec_data:
            if HAS_SWAGGER_VALIDATOR:
                if spec_file.endswith(('.yml', '.yaml')):
                    # convert to JSON first as validator doesn't do YAML
                    swagger_spec = yaml.load(spec_data)
                    temp_file = tempfile.NamedTemporaryFile(delete=False)
                    temp_file.write(json.dumps(swagger_spec))
                    temp_file.close()
                    spec = validate_swagger_spec(temp_file.name)
                    os.remove(temp_file.name)
                else:
                    swagger_spec = json.load(spec_data)
                    spec = validate_swagger_spec(spec_file)

                if not spec['valid']:
                    module.fail_json(msg='Error validating Swagger specification: {0}'.format(spec['msg']))
            else:
                if spec_file.endswith(('.yml', '.yaml')):
                    swagger_spec = yaml.load(spec_data)
                else:
                    swagger_spec = json.load(spec_data)

    except (IOError, EOFError, ValueError) as e:
        module.fail_json(msg="Invalid or missing API specification: {0}".format(e))

    response = manage_state(client, module, swagger_spec)

    results = dict(ansible_facts=response['results'], changed=response['changed'])

    module.exit_json(**results)


# ansible import module(s) kept at ~eof as recommended

from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
