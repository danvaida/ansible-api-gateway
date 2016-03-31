# Ansible Cloud Modules for AWS API Gateway with OpenAPI/ Swagger Specification

### v0.0.0a [![Build Status](https://travis-ci.org/pjodouin/ansible-api-gateway.svg)](https://travis-ci.org/pjodouin/ansible-api-gateway)
*Unstable work in Progress*

The module will use the [Open API Initiative (OAI)](http://swagger.io/specification/) specification,
formerly known as "The Swagger Specification" along with AWS integration extensions to define the APIs.

## Requirements
- ansible
- boto3
- swagger_spec_validator (optional but recommended for validation)
- importlib (only for running tests on < python 2.7)

## Modules
____
### api_gw_facts:
Gathers facts related to AWS API Gateway

##### Example Command
`> ansible localhost -m api_gw_facts`

____
### api_gw:
Manages AWS API Gateway resources

##### Example Playbook

```yaml
- hosts: localhost
  gather_facts: no
  vars:
    state: present
    api_gw_spec_file: /path/to/swagger/spec/LambdaMicroservice-Dev.yaml

  tasks:
  - name: AWS API Gateway
    api_gw:
      state: "{{ state | default('present') }}"
      api_id: '*'
#      deploy_api: True
      swagger_spec: "{{ api_gw_spec_file }}"

  - name: show results
    debug: var=api_gw_facts

```
