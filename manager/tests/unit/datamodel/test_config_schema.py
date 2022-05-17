import inspect
import json
from typing import Any, Dict, Type, cast

from knot_resolver_manager.datamodel import KresConfig
from knot_resolver_manager.datamodel.lua_schema import LuaSchema
from knot_resolver_manager.utils.modeling import BaseSchema
from knot_resolver_manager.utils.modeling.types import (
    get_generic_type_argument,
    get_generic_type_arguments,
    get_optional_inner_type,
    is_dict,
    is_list,
    is_optional,
    is_union,
)


def test_config_check_str_type():
    # check that there is no 'str' type in datamodel schema (except for LuaSchema
    def _check_str_type(cls: Type[Any], object_path: str = ""):
        if cls == str:
            raise TypeError(f"{object_path}: 'str' type not allowed")
        elif is_optional(cls):
            inner: Type[Any] = get_optional_inner_type(cls)
            _check_str_type(inner, object_path)
        elif is_union(cls):
            variants = get_generic_type_arguments(cls)
            for v in variants:
                _check_str_type(v, object_path)
        elif is_dict(cls):
            key_type, val_type = get_generic_type_arguments(cls)
            _check_str_type(key_type, object_path)
            _check_str_type(val_type, object_path)
        elif is_list(cls):
            inner_type = get_generic_type_argument(cls)
            _check_str_type(inner_type, object_path)

        elif inspect.isclass(cls) and issubclass(cls, BaseSchema):
            annot = cls.__dict__.get("__annotations__", {})
            for name, python_type in annot.items():
                # ignore lua section
                if python_type != LuaSchema:
                    _check_str_type(python_type, f"{object_path}/{name}")

    _check_str_type(KresConfig)


def test_config_defaults():
    config = KresConfig()

    # DNS64 default
    assert config.dns64 == False


def test_dnssec_false():
    config = KresConfig({"dnssec": False})

    assert config.dnssec == False


def test_dnssec_default_true():
    config = KresConfig()

    # DNSSEC defaults
    assert config.dnssec.trust_anchor_sentinel == True
    assert config.dnssec.trust_anchor_signal_query == True
    assert config.dnssec.time_skew_detection == True
    assert config.dnssec.refresh_time == None
    assert config.dnssec.trust_anchors == None
    assert config.dnssec.negative_trust_anchors == None
    assert config.dnssec.trust_anchors_files == None
    assert int(config.dnssec.keep_removed) == 0
    assert str(config.dnssec.hold_down_time) == "30d"


def test_dns64_prefix_default():
    assert str(KresConfig({"dns64": True}).dns64.prefix) == "64:ff9b::/96"


def test_config_json_schema():
    dct = KresConfig.json_schema()

    def recser(obj: Any, path: str = "") -> None:
        if not isinstance(obj, dict):
            return
        else:
            obj = cast(Dict[Any, Any], obj)
            for key in obj:
                recser(obj[key], path=f"{path}/{key}")
            try:
                _ = json.dumps(obj)
            except BaseException as e:
                raise Exception(f"failed to serialize '{path}'") from e

    recser(dct)
