from pprint import pprint
from collections import defaultdict
import json
paths = [
    "/this/old/man",
    "/this/is/some/path/to/success",
    "/this/",
    "/this/old/woman",
    "/",
]
def tree():
    return defaultdict(tree)

def dicts(tree):
    try:
        return dict((key, dicts(tree[key])) for key in tree)
    except TypeError:
        return tree


def add(tree, path):
    nodes = path.split('/')
    for node in nodes:
        tree = tree[node]

resources = tree()

for path in paths:
    # nodes = path.split('/')
    add(resources, path)

dict_resources = dicts(resources)
# pprint(dict_resources)
print json.dumps(resources, indent=4)
