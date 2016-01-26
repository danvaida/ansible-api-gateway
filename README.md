# Ansible Cloud Modules for AWS API Gateway

### v0.1.0

Just starting on this...  Facts gathering now working.

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
`> ansible localhost -m api_gw -a"resource_type=rest_api name=funky_foo state=present"`
