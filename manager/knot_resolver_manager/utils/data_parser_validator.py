import copy
import inspect
import json
import re
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple, Type, TypeVar, Union

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from knot_resolver_manager.exceptions import (
    DataParsingException,
    DataValidationException,
    ParsingException,
    ValidationException,
)
from knot_resolver_manager.utils.custom_types import CustomValueType
from knot_resolver_manager.utils.types import (
    NoneType,
    get_attr_type,
    get_generic_type_argument,
    get_generic_type_arguments,
    is_dict,
    is_enum,
    is_list,
    is_literal,
    is_none_type,
    is_optional,
    is_tuple,
    is_union,
)


def is_internal_field(field_name: str) -> bool:
    return field_name.startswith("_")


def is_obj_type(obj: Any, types: Union[type, Tuple[Any, ...], Tuple[type, ...]]) -> bool:
    # To check specific type we are using 'type()' instead of 'isinstance()'
    # because for example 'bool' is instance of 'int', 'isinstance(False, int)' returns True.
    # pylint: disable=unidiomatic-typecheck
    if isinstance(types, Tuple):
        return type(obj) in types
    return type(obj) == types


def _to_primitive(obj: Any) -> Any:
    """
    Convert our custom values into primitive variants for dumping.
    """

    # CustomValueType instances
    if isinstance(obj, CustomValueType):
        return obj.serialize()

    # nested DataParser class instances
    elif isinstance(obj, SchemaNode):
        return obj.to_dict()

    # otherwise just return, what we were given
    else:
        return obj


def _validated_object_type(
    cls: Type[Any], obj: Any, default: Any = ..., use_default: bool = False, object_path: str = "/"
) -> Any:
    """
    Given an expected type `cls` and a value object `obj`, validate the type of `obj` and return it
    """

    # Disabling these checks, because I think it's much more readable as a single function
    # and it's not that large at this point. If it got larger, then we should definitely split it
    # pylint: disable=too-many-branches,too-many-locals,too-many-statements

    # default values
    if obj is None and use_default:
        return default

    # NoneType
    elif is_none_type(cls):
        if obj is None:
            return None
        else:
            raise DataParsingException(f"Expected None, found '{obj}'.", object_path)

    # Union[*variants] (handles Optional[T] due to the way the typing system works)
    elif is_union(cls):
        variants = get_generic_type_arguments(cls)
        for v in variants:
            try:
                return _validated_object_type(v, obj, object_path=object_path)
            except DataParsingException:
                pass
        raise DataParsingException(f"Union {cls} could not be parsed - parsing of all variants failed.", object_path)

    # after this, there is no place for a None object
    elif obj is None:
        raise DataParsingException(f"Unexpected None value for type {cls}", object_path)

    # int
    elif cls == int:
        # we don't want to make an int out of anything else than other int
        # except for CustomValueType class instances
        if is_obj_type(obj, int) or isinstance(obj, CustomValueType):
            return int(obj)
        raise DataParsingException(f"Expected int, found {type(obj)}", object_path)

    # str
    elif cls == str:
        # we are willing to cast any primitive value to string, but no compound values are allowed
        if is_obj_type(obj, (str, float, int)) or isinstance(obj, CustomValueType):
            return str(obj)
        elif is_obj_type(obj, bool):
            raise DataParsingException(
                "Expected str, found bool. Be careful, that YAML parsers consider even"
                ' "no" and "yes" as a bool. Search for the Norway Problem for more'
                " details. And please use quotes explicitly.",
                object_path,
            )
        else:
            raise DataParsingException(
                f"Expected str (or number that would be cast to string), but found type {type(obj)}", object_path
            )

    # bool
    elif cls == bool:
        if is_obj_type(obj, bool):
            return obj
        else:
            raise DataParsingException(f"Expected bool, found {type(obj)}", object_path)

    # float
    elif cls == float:
        raise NotImplementedError(
            "Floating point values are not supported in the parser."
            " Please implement them and be careful with type coercions"
        )

    # Literal[T]
    elif is_literal(cls):
        expected = get_generic_type_argument(cls)
        if obj == expected:
            return obj
        else:
            raise DataParsingException(f"Literal {cls} is not matched with the value {obj}", object_path)

    # Dict[K,V]
    elif is_dict(cls):
        key_type, val_type = get_generic_type_arguments(cls)
        try:
            return {
                _validated_object_type(key_type, key, object_path=f"{object_path} @ key {key}"): _validated_object_type(
                    val_type, val, object_path=f"{object_path} @ value for key {key}"
                )
                for key, val in obj.items()
            }
        except AttributeError as e:
            raise DataParsingException(
                f"Expected dict-like object, but failed to access its .items() method. Value was {obj}", object_path
            ) from e

    # any Enums (probably used only internally in DataValidator)
    elif is_enum(cls):
        if isinstance(obj, cls):
            return obj
        else:
            raise DataParsingException(f"Unexpected value '{obj}' for enum '{cls}'", object_path)

    # List[T]
    elif is_list(cls):
        inner_type = get_generic_type_argument(cls)
        return [_validated_object_type(inner_type, val, object_path=f"{object_path}[]") for val in obj]

    # Tuple[A,B,C,D,...]
    elif is_tuple(cls):
        types = get_generic_type_arguments(cls)
        return tuple(_validated_object_type(typ, val, object_path=object_path) for typ, val in zip(types, obj))

    # CustomValueType subclasses
    elif inspect.isclass(cls) and issubclass(cls, CustomValueType):
        if isinstance(obj, cls):
            # if we already have a custom value type, just pass it through
            return obj
        else:
            # no validation performed, the implementation does it in the constuctor
            return cls(obj, object_path=object_path)

    # nested SchemaNode subclasses
    elif inspect.isclass(cls) and issubclass(cls, SchemaNode):
        # we should return DataParser, we expect to be given a dict,
        # because we can construct a DataParser from it
        if isinstance(obj, (dict, SchemaNode)):
            return cls(obj, object_path=object_path)  # type: ignore
        raise DataParsingException(f"Expected 'dict' or 'SchemaNode' object, found '{type(obj)}'", object_path)

    # if the object matches, just pass it through
    elif inspect.isclass(cls) and isinstance(obj, cls):
        return obj

    # default error handler
    else:
        raise DataParsingException(
            f"Type {cls} cannot be parsed. This is a implementation error. "
            "Please fix your types in the class or improve the parser/validator.",
            object_path,
        )


# custom hook for 'json.loads()' to detect duplicate keys in data
# source: https://stackoverflow.com/q/14902299/12858520
def json_raise_duplicates(pairs: List[Tuple[Any, Any]]) -> Optional[Any]:
    dict_out: Dict[Any, Any] = {}
    for key, val in pairs:
        if key in dict_out:
            raise ParsingException(f"Duplicate attribute key detected: {key}")
        dict_out[key] = val
    return dict_out


# custom loader for 'yaml.load()' to detect duplicate keys in data
# source: https://gist.github.com/pypt/94d747fe5180851196eb
class RaiseDuplicatesLoader(yaml.SafeLoader):
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
                raise ParsingException(f"duplicate key detected: {key_node.start_mark}")
            value = self.construct_object(value_node, deep=deep)  # type: ignore
            mapping[key] = value
        return mapping


class Format(Enum):
    YAML = auto()
    JSON = auto()

    def parse_to_dict(self, text: str) -> Any:
        if self is Format.YAML:
            # RaiseDuplicatesLoader extends yaml.SafeLoader, so this should be safe
            # https://python.land/data-processing/python-yaml#PyYAML_safe_load_vs_load
            return yaml.load(text, Loader=RaiseDuplicatesLoader)  # type: ignore
        elif self is Format.JSON:
            return json.loads(text, object_pairs_hook=json_raise_duplicates)
        else:
            raise NotImplementedError(f"Parsing of format '{self}' is not implemented")

    def dict_dump(self, data: Dict[str, Any]) -> str:
        if self is Format.YAML:
            return yaml.safe_dump(data)  # type: ignore
        elif self is Format.JSON:
            return json.dumps(data)
        else:
            raise NotImplementedError(f"Exporting to '{self}' format is not implemented")

    @staticmethod
    def from_mime_type(mime_type: str) -> "Format":
        formats = {
            "application/json": Format.JSON,
            "application/octet-stream": Format.JSON,  # default in aiohttp
            "text/vnd.yaml": Format.YAML,
        }
        if mime_type not in formats:
            raise ParsingException("Unsupported MIME type")
        return formats[mime_type]


_T = TypeVar("_T", bound="SchemaNode")


_SUBTREE_MUTATION_PATH_PATTERN = re.compile(r"^(/[^/]+)*/?$")


TSource = Union[NoneType, Dict[Any, Any], "SchemaNode"]


class SchemaNode:
    def __init__(self, source: TSource = None, object_path: str = "/"):
        cls = self.__class__
        annot = cls.__dict__.get("__annotations__", {})

        used_keys: Set[str] = set()
        for name, python_type in annot.items():
            if is_internal_field(name):
                continue

            # convert naming (used when converting from json/yaml)
            source_name = name.replace("_", "-") if isinstance(source, dict) else name

            # populate field
            if not source:
                val = None
            # we have a way how to create the value
            elif hasattr(self, f"_{name}"):
                val = self._get_converted_value(name, source, object_path)
                used_keys.add(source_name)  # the field might not exist, but that won't break anything
            # source just contains the value
            elif source_name in source:
                val = source[source_name]
                used_keys.add(source_name)
            # there is a default value and in the source, the value is missing
            elif getattr(self, name, ...) is not ...:
                val = None
            # the value is optional and there is nothing
            elif is_optional(python_type):
                val = None
            # we expected a value but it was not there
            else:
                raise DataValidationException(f"Missing attribute '{source_name}'.", object_path)

            use_default = hasattr(cls, name)
            default = getattr(cls, name, ...)
            value = _validated_object_type(python_type, val, default, use_default, object_path=f"{object_path}/{name}")
            setattr(self, name, value)

        # check for unused keys in case the
        if source and isinstance(source, dict):
            unused = source.keys() - used_keys
            if len(unused) > 0:
                raise DataParsingException(
                    f"Keys {unused} in your configuration object are not part of the configuration schema."
                    " Are you using '-' instead of '_'?",
                    object_path,
                )

        # validate the constructed value
        self._validate()

    def _get_converted_value(self, key: str, source: TSource, object_path: str) -> Any:
        try:
            return getattr(self, f"_{key}")(source)
        except (ValueError, ValidationException) as e:
            if len(e.args) > 0 and isinstance(e.args[0], str):
                msg = e.args[0]
            else:
                msg = "Failed to validate value type"
            raise DataValidationException(msg, object_path) from e

    def __getitem__(self, key: str) -> Any:
        if not hasattr(self, key):
            raise RuntimeError(f"Object '{self}' of type '{type(self)}' does not have field named '{key}'")
        return getattr(self, key)

    def __contains__(self, item: Any) -> bool:
        return hasattr(self, item)

    def validate(self) -> None:
        for field_name in dir(self):
            if is_internal_field(field_name):
                continue

            field = getattr(self, field_name)
            if isinstance(field, SchemaNode):
                field.validate()
        self._validate()

    def _validate(self) -> None:
        pass

    @classmethod
    def parse_from(cls: Type[_T], fmt: Format, text: str):
        data_dict = fmt.parse_to_dict(text)
        config: _T = cls(data_dict)
        return config

    @classmethod
    def from_yaml(cls: Type[_T], text: str) -> _T:
        return cls.parse_from(Format.YAML, text)

    @classmethod
    def from_json(cls: Type[_T], text: str) -> _T:
        return cls.parse_from(Format.JSON, text)

    def to_dict(self) -> Dict[str, Any]:
        cls = self.__class__
        anot = cls.__dict__.get("__annotations__", {})
        dict_obj: Dict[str, Any] = {}
        for name in anot:
            if is_internal_field(name):
                continue

            value = getattr(self, name)
            dash_name = str(name).replace("_", "-")
            dict_obj[dash_name] = _to_primitive(value)
        return dict_obj

    def dump(self, fmt: Format) -> str:
        dict_data = self.to_dict()
        return fmt.dict_dump(dict_data)

    def dump_to_yaml(self) -> str:
        return self.dump(Format.YAML)

    def dump_to_json(self) -> str:
        return self.dump(Format.JSON)

    def copy_with_changed_subtree(self: _T, fmt: Format, path: str, text: str) -> _T:
        cls = self.__class__

        # prepare and validate the path object
        path = path[:-1] if path.endswith("/") else path
        if re.match(_SUBTREE_MUTATION_PATH_PATTERN, path) is None:
            raise ParsingException("Provided object path for mutation is invalid.")
        path = path[1:] if path.startswith("/") else path

        # now, the path variable should contain '/' separated field names

        # check if we should mutate whole object
        if path == "":
            return cls.parse_from(fmt, text)

        # find the subtree we will replace in a copy of the original object
        to_mutate = copy.deepcopy(self)
        obj = to_mutate
        parent = None

        for dash_segment in path.split("/"):
            segment = dash_segment.replace("-", "_")

            if segment == "":
                raise ParsingException(f"Unexpectedly empty segment in path '{path}'")
            elif is_internal_field(segment):
                raise ParsingException(
                    "No, changing internal fields (starting with _) is not allowed. Nice try though."
                )
            elif hasattr(obj, segment):
                parent = obj
                obj = getattr(parent, segment)
            else:
                raise ParsingException(
                    f"Path segment '{dash_segment}' does not match any field on the provided parent object"
                )
        assert parent is not None

        # assign the subtree
        last_name = path.split("/")[-1].replace("-", "_")
        data = fmt.parse_to_dict(text)
        tp = get_attr_type(parent, last_name)
        parsed_value = _validated_object_type(tp, data)
        setattr(parent, last_name, parsed_value)

        return to_mutate
