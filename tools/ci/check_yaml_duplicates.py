#!/usr/bin/env python3
"""Fail if any YAML file has duplicate mapping keys.

PyYAML silently keeps the last duplicate, which in a Sigma rule quietly drops
a detection condition. Usage: check_yaml_duplicates.py FILE...
"""
import sys

import yaml


class StrictLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark)
        seen.add(key)
    return loader.construct_mapping(node, deep)


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)

bad = 0
for path in sys.argv[1:]:
    try:
        list(yaml.load_all(open(path, encoding="utf-8"), Loader=StrictLoader))
    except yaml.YAMLError as exc:
        print(f"FAIL {path}: {exc}")
        bad += 1
print(f"checked {len(sys.argv) - 1} files, {bad} with duplicate keys")
sys.exit(1 if bad else 0)
