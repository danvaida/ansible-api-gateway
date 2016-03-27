# Ansible Cloud Modules for AWS API Gateway -- OAI/Swagger

### v0.1.0 [![Build Status](https://travis-ci.org/pjodouin/ansible-api-gateway.svg)](https://travis-ci.org/pjodouin/ansible-api-gateway)

Just starting on this.  The module will use the [Open API Initiative (OAI)](http://swagger.io/specification/) specification,
formerly known as "The Swagger Specification" along with AWS integration extensions to define the APIs.

## Requirements
- ansible
- boto3
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

##### Example Command
