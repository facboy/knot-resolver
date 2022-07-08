from typing import List, Optional, Union

from knot_resolver_manager.datamodel.types import DomainName, IPAddressOptionalPort, PolicyFlagEnum
from knot_resolver_manager.utils.modeling import SchemaNode


class StubServerSchema(SchemaNode):
    """
    Configuration of Stub server.

    ---
    address: IP address of Stub server.
    """

    address: IPAddressOptionalPort


class StubZoneSchema(SchemaNode):
    """
    Configuration of Stub Zone.

    ---
    name: Domain name of the zone.
    servers: IP address of Stub server.
    views: Use this Stub Zone only for clients defined by views.
    options: Configuration flags for Stub Zone.
    """

    name: DomainName
    servers: Union[List[IPAddressOptionalPort], List[StubServerSchema]]
    views: Optional[List[str]] = None
    options: Optional[List[PolicyFlagEnum]] = None
