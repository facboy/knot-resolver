import re
from typing import Any, Dict, List, Pattern, Type

from knot_resolver_manager.utils.modeling import BaseValueType


class IntBase(BaseValueType):
    """
    Base class to work with integer value.
    """

    _value: int

    def __int__(self) -> int:
        return self._value

    def __str__(self) -> str:
        return str(self._value)

    def __eq__(self, o: object) -> bool:
        return isinstance(o, IntBase) and o._value == self._value

    def serialize(self) -> Any:
        return self._value

    @classmethod
    def json_schema(cls: Type["IntBase"]) -> Dict[Any, Any]:
        return {"type": "integer"}


class StrBase(BaseValueType):
    """
    Base class to work with string value.
    """

    _value: str

    def __int__(self) -> int:
        raise ValueError("Can't convert string to an integer.")

    def __str__(self) -> str:
        return self._value

    def to_std(self) -> str:
        return self._value

    def __hash__(self) -> int:
        return hash(self._value)

    def __eq__(self, o: object) -> bool:
        return isinstance(o, StrBase) and o._value == self._value

    def serialize(self) -> Any:
        return self._value

    @classmethod
    def json_schema(cls: Type["StrBase"]) -> Dict[Any, Any]:
        return {"type": "string"}


class StrLengthBase(StrBase):
    """
    Base class to work with string value length.
    Just inherit the class and set the values for '_min_bytes' and '_max_bytes'.

    class StrMinLen32B(StrLengthBase):
        _min_bytes: int = 32
    """

    _min_bytes: int = 1
    _max_bytes: int

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        if isinstance(source_value, (str, int)) and not isinstance(source_value, bool):
            val_len = len(str(source_value).encode("utf-8"))
            if hasattr(self, "_min_bytes") and (val_len < self._min_bytes):
                raise SchemaException(
                    f"the string value {source_value} is shorter than the minimum {self._min_bytes} bytes.", object_path
                )
            if hasattr(self, "_max_bytes") and (val_len > self._max_bytes):
                raise SchemaException(
                    f"the string value {source_value} is longer than the maximum {self._max_bytes} bytes.", object_path
                )
            self._value = str(source_value)
        else:
            raise SchemaException(
                f"expected integer, got '{type(source_value)}'",
                object_path,
            )

    @classmethod
    def json_schema(cls: Type["StrLengthBase"]) -> Dict[Any, Any]:
        typ: Dict[str, Any] = {"type": "string"}
        if hasattr(cls, "_min_bytes"):
            typ["minLength"] = cls._min_bytes
        if hasattr(cls, "_max_bytes"):
            typ["maxLength"] = cls._max_bytes
        return typ


class EscStrBase(StrBase):
    r"""
    Base class to escape some chars.
    Just inherit the class and set escaped characters in '_esc'.

    class EscTabStr(EscStrBase):
        _esc_chars: List[str] = ["\t"]
    """

    _esc_chars: List[str]

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value, object_path)
        if isinstance(source_value, (str, int)) and not isinstance(source_value, bool):
            source_str = str(source_value)
            for esc_char in self._esc_chars:
                source_str = source_str.replace(esc_char, rf"\{esc_char}")
            self._value = source_str
        else:
            raise ValueError(
                f"Unexpected value for '{type(self)}'."
                f" Expected string or int, got '{source_value}' with type '{type(source_value)}'",
                object_path,
            )


class IntRangeBase(IntBase):
    """
    Base class to work with integer value in range.
    Just inherit the class and set the values for '_min' and '_max'.

    class IntNonNegative(IntRangeBase):
        _min: int = 0
    """

    _min: int
    _max: int

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        if isinstance(source_value, int) and not isinstance(source_value, bool):
            if hasattr(self, "_min") and (source_value < self._min):
                raise ValueError(f"value {source_value} is lower than the minimum {self._min}.")
            if hasattr(self, "_max") and (source_value > self._max):
                raise ValueError(f"value {source_value} is higher than the maximum {self._max}")
            self._value = source_value
        else:
            raise ValueError(
                f"expected integer, got '{type(source_value)}'",
                object_path,
            )

    @classmethod
    def json_schema(cls: Type["IntRangeBase"]) -> Dict[Any, Any]:
        typ: Dict[str, Any] = {"type": "integer"}
        if hasattr(cls, "_min"):
            typ["minimum"] = cls._min
        if hasattr(cls, "_max"):
            typ["maximum"] = cls._max
        return typ


class PatternBase(StrBase):
    """
    Base class to work with string value that match regex pattern.
    Just inherit the class and set regex pattern for '_re'.

    class ABPattern(PatternBase):
        _re: Pattern[str] = re.compile(r"ab*")
    """

    _re: Pattern[str]

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        if isinstance(source_value, str):
            if type(self)._re.match(source_value):
                self._value: str = source_value
            else:
                raise ValueError(f"'{source_value}' does not match '{self._re.pattern}' pattern")
        else:
            raise ValueError(
                f"expected string, got '{type(source_value)}'",
                object_path,
            )

    @classmethod
    def json_schema(cls: Type["PatternBase"]) -> Dict[Any, Any]:
        return {"type": "string", "pattern": rf"{cls._re.pattern}"}


class UnitBase(IntBase):
    """
    Base class to work with string value that match regex pattern.
    Just inherit the class and set '_units'.

    class CustomUnit(PatternBase):
        _units = {"b": 1, "kb": 1000}
    """

    _re: Pattern[str]
    _units: Dict[str, int]
    _value_orig: str

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        type(self)._re = re.compile(rf"^(\d+)({r'|'.join(type(self)._units.keys())})$")
        if isinstance(source_value, str) and self._re.match(source_value):
            self._value_orig = source_value
            grouped = self._re.search(source_value)
            if grouped:
                val, unit = grouped.groups()
                if unit is None:
                    raise ValueError(f"Missing units. Accepted units are {list(type(self)._units.keys())}")
                elif unit not in type(self)._units:
                    raise ValueError(
                        f"Used unexpected unit '{unit}' for {type(self).__name__}."
                        f" Accepted units are {list(type(self)._units.keys())}",
                        object_path,
                    )
                self._value = int(val) * type(self)._units[unit]
            else:
                raise ValueError(f"{type(self._value)} Failed to convert: {self}")
        elif isinstance(source_value, int):
            raise ValueError(
                f"number without units, please convert to string and add unit  - {list(type(self)._units.keys())}",
                object_path,
            )
        else:
            raise ValueError(
                f"expected number with units in a string, got '{type(source_value)}'.",
                object_path,
            )

    def __str__(self) -> str:
        """
        Used by Jinja2. Must return only a number.
        """
        return str(self._value_orig)

    def __repr__(self) -> str:
        return f"Unit[{type(self).__name__},{self._value_orig}]"

    def __eq__(self, o: object) -> bool:
        """
        Two instances are equal when they represent the same size
        regardless of their string representation.
        """
        return isinstance(o, UnitBase) and o._value == self._value

    def serialize(self) -> Any:
        return self._value_orig

    @classmethod
    def json_schema(cls: Type["UnitBase"]) -> Dict[Any, Any]:
        return {"type": "string", "pattern": rf"{cls._re.pattern}"}
