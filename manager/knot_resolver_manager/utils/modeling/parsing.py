import json
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from .exceptions import DataParsingError
from .renaming import renamed


# custom hook for 'json.loads()' to detect duplicate keys in data
# source: https://stackoverflow.com/q/14902299/12858520
def _json_raise_duplicates(pairs: List[Tuple[Any, Any]]) -> Optional[Any]:
    dict_out: Dict[Any, Any] = {}
    for key, val in pairs:
        if key in dict_out:
            raise DataParsingError(f"Duplicate attribute key detected: {key}")
        dict_out[key] = val
    return dict_out


# custom loader for 'yaml.load()' to detect duplicate keys in data
# source: https://gist.github.com/pypt/94d747fe5180851196eb
class _RaiseDuplicatesLoader(yaml.SafeLoader):
    def construct_mapping(self, node: Union[MappingNode, Any], deep: bool = False) -> Dict[Any, Any]:
        if not isinstance(node, MappingNode):
            raise ConstructorError(None, None, f"expected a mapping node, but found {node.id}", node.start_mark)
        mapping: Dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)  # type: ignore
            # we need to check, that the key object can be used in a hash table
            try:
                _ = hash(key)  # type: ignore
            except TypeError as exc:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found unacceptable key ({exc})",
                    key_node.start_mark,
                )

            # check for duplicate keys
            if key in mapping:
                raise DataParsingError(f"duplicate key detected: {key_node.start_mark}")
            value = self.construct_object(value_node, deep=deep)  # type: ignore
            mapping[key] = value
        return mapping


class _Format(Enum):
    YAML = auto()
    JSON = auto()

    def parse_to_dict(self, text: str) -> Any:
        if self is _Format.YAML:
            # RaiseDuplicatesLoader extends yaml.SafeLoader, so this should be safe
            # https://python.land/data-processing/python-yaml#PyYAML_safe_load_vs_load
            return renamed(yaml.load(text, Loader=_RaiseDuplicatesLoader))  # type: ignore
        elif self is _Format.JSON:
            return renamed(json.loads(text, object_pairs_hook=_json_raise_duplicates))
        else:
            raise NotImplementedError(f"Parsing of format '{self}' is not implemented")

    def dict_dump(self, data: Dict[str, Any]) -> str:
        if self is _Format.YAML:
            return yaml.safe_dump(data)  # type: ignore
        elif self is _Format.JSON:
            return json.dumps(data)
        else:
            raise NotImplementedError(f"Exporting to '{self}' format is not implemented")

    @staticmethod
    def from_mime_type(mime_type: str) -> "_Format":
        formats = {
            "application/json": _Format.JSON,
            "application/yaml": _Format.YAML,
            "application/octet-stream": _Format.JSON,  # default in aiohttp
            "text/vnd.yaml": _Format.YAML,
        }
        if mime_type not in formats:
            raise DataParsingError(
                f"unsupported MIME type '{mime_type}', expected 'application/json' or 'application/yaml'"
            )
        return formats[mime_type]


def parse(data: str, mime_type: str) -> Any:
    return _Format.from_mime_type(mime_type).parse_to_dict(data)


def parse_yaml(data: str) -> Any:
    return _Format.YAML.parse_to_dict(data)


def parse_json(data: str) -> Any:
    return _Format.JSON.parse_to_dict(data)


def try_to_parse(data: str) -> ParsedTree:
    """Attempt to parse the data as a YAML or JSON string."""
    try:
        return parse_yaml(data)
    except yaml.YAMLError as ye:
        try:
            return parse_json(data)
        except json.JSONDecodeError as je:
            raise DataParsingError(f"failed to parse data, YAML: {ye}, JSON: {je}")
