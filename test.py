from pprint import pprint
from collections import defaultdict
import json
paths = [
    dict(path="/this/old", value=dict(method='get', id='67df4d78dfh', reponse=dict())),
    dict(path="/this/old/man", value=dict(method='post', id='67df4d78dfh', reponse=dict())),
    dict(path="/that/is/some", value=dict(method='options', id='67df4d78dfh')),
    dict(path="/that/is/some/path/to/success", value=dict(method='put', id='67df4d78dfh', reponse=dict())),
    dict(path="/this/old/woman", value=dict(method='get', id='67df4d78dfh', reponse=dict(code=200))),
    # dict(path="/", value=dict(method='del', id='67df4d78dfh', reponse=dict())),
]
def pytree():
    return defaultdict(pytree)

def dicts(tree):
    try:
        return dict((key, dicts(tree[key])) for key in tree)
    except TypeError:
        return tree


def add(tree, path):
    nodes = path['path'].split('/')  #[1:]
    for node in nodes:
        tree = tree[node]
    tree.update(path['value'])
    tree.update(fullpath=path['path'])

def assign(tree, path, value):
    d = tree
    nodes = path.split('/')[1:]
    for node in nodes:
        d = d[node]
        print "=>", d, "<=\n"
    d.update(value)


resources = pytree()

for path in paths:
    # nodes = path.split('/')
    add(resources, path)

# dict_resources = dicts(resources)
# assign(dict_resources, '/this/old/man', dict(method='get', id='67df4d78dfh', reponse=dict()))


# dict_resources['this']['old']['man'] = dict(method='get', id='67df4d78dfh', reponse=dict())
# dict_resources['this']['old'][''] = dict(method='get', id='67df4d78dfh', reponse=dict())


# pprint(dict_resources)
# print json.dumps(dict_resources, indent=4)
print json.dumps(resources, indent=4)
