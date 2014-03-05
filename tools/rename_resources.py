#!/usr/bin/env python
import os
import re
import sys

def rename(name, mapping):
    tmp = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    tmp = re.sub('([a-z0-9])([A-Z])', r'\1_\2', tmp).lower()
    # allow "v3" and such as a word, else split the numbers off
    tmp = re.sub('([a-uw-z])([0-9])', r'\1_\2', tmp).lower()
    tmp = tmp.replace('pass_phrase', 'pass_phrase')
    tmp = mapping.get(tmp, tmp)
    return tmp

def rename_xml_strings(filepath, mapping):
    data = file(filepath).read()
    names = re.findall(r'name="(.*?)"', data)
    for name in names:
        new_name = rename(name, mapping)
        if new_name != name:
            data = data.replace('"' + name + '"', '"' + new_name + '"')

    file(filepath, 'w').write(data)

def rename_java(filepath, mapping):
    data = file(filepath).read()
    names = re.findall(r'R[.]string[.]([a-zA-Z0-9_]*)', data)
    for name in names:
        new_name = rename(name, mapping)
        if new_name != name:
            data = data.replace('R.string.' + name, 'R.string.' + new_name)

    file(filepath, 'w').write(data)

def rename_xml(filepath, mapping):
    data = file(filepath).read()
    names = re.findall(r'@string/([a-zA-Z0-9_]*)', data)
    for name in names:
        new_name = rename(name, mapping)
        if new_name != name:
            data = data.replace('@string/' + name, '@string/' + new_name)

    file(filepath, 'w').write(data)

def rename_resources(dir, mapping):
    for (path, directories, files) in os.walk(dir):
        for f in files:
            if f == 'strings.xml':
                rename_xml_strings(os.path.join(path, f), mapping)
            elif f.endswith('.xml'):
                rename_xml(os.path.join(path, f), mapping)
            elif f.endswith('.java'):
                rename_java(os.path.join(path, f), mapping)

if __name__ == "__main__":
    mapping = {}
    for s in sys.argv[2:]:
        key, value = s.split(':')
        mapping[key] = value

    rename_resources(sys.argv[1], mapping)
