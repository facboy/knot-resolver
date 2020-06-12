local debug = require("kres_modules/sysrepo-lua/debug")
local ffi = require("ffi")
local os = require("os")

local _clib = nil

--- Access function to the C helper library. Returns table on which C functions can be called
--- directly. When retrieving strings, you must intern them first using `ffi.string()`
local function clib()
    assert(_clib ~= nil, "Tried to use C library before it was properly initialized.")
    return _clib
end

local Helpers = {}
function Helpers.get_children_table(node)
    -- create lookup table for nodes by name
    local lookup = {}
    local child = clib().node_child_first(node)
    while child ~= nil do
        local nm = ffi.string(clib().node_get_name(child))
        lookup[nm] = child
        child = clib().node_child_next(child)
    end

    return lookup
end

function Helpers.node_to_object(node)
    if node == nil then
        return nil
    end

    if clib().node_is_leaf(node) then
        -- is primitive

        if clib().node_is_number_type(node) then
            return tonumber(ffi.string(clib().node_get_value_str(node)))
        else
            return ffi.string(clib().node_get_value_str(node))
        end
    else
        -- is composite
        local result = {}
        local child = clib().node_child_first(node)
        while child ~= nil do
            local nm = ffi.string(clib().node_get_name(child))

            if clib().node_is_list_item(child) then
                if result[nm] == nil then
                    result[nm] = {}
                end

                table.insert(result[nm], Helpers.node_to_object(child))
            else
                result[nm] = Helpers.node_to_object(child)
            end

            child = clib().node_child_next(child)
        end

        return result
    end
end

function Helpers.object_to_node(object, name, schema_node, parent_node)
    if object == nil then
        return nil
    end

    assert(schema_node ~= nil)
    assert(parent_node ~= nil)
    assert(type(name) == "string")
    assert(name == ffi.string(clib().schema_get_name(schema_node)))

    if type(object) ~= "table" then
        -- primitive
        return clib().node_new_leaf(parent_node, clib().schema_get_module(schema_node), name, tostring(object))
    else
        -- composite

        if object[1] ~= nil then
            -- list
            local last = nil
            for _,v in ipairs(object) do
                last = Helpers.object_to_node(v, name, schema_node, parent_node)
            end
            return last
        else
            -- container

            local cont = clib().node_new_container(parent_node, clib().schema_get_module(schema_node), name)
            local child_schema_nodes = Helpers.get_schema_children_table(schema_node)
            for k,v in pairs(object) do
                assert(type(k) == "string")

                if child_schema_nodes[k] == nil then
                    debug.log("Warning while serializing table - unknown child with name {}. Schema does not correspond.", k)
                else
                    Helpers.object_to_node(v, k, child_schema_nodes[k], cont)
                end
            end
            return cont
        end
    end
end

function Helpers.get_children_str_values(node)
    local children = Helpers.get_children_table(node)

    local result = {}
    for nm,nd in pairs(children) do
        result[nm] = ffi.string(clib().node_get_value_str(nd))
    end
    return result
end

function Helpers.get_schema_children_table(schema_node)
    local lookup = {}
    local child = clib().schema_child_first(schema_node)
    while child ~= nil do
        local nm = ffi.string(clib().schema_get_name(child))
        lookup[nm] = child
        child = clib().schema_child_next(schema_node, child)
    end

    return lookup
end


-------------------------------------------------------------------------------
------------------------ Generic Config Modeling Infra ------------------------
-------------------------------------------------------------------------------


local Hook = {}
Hook.__index = Hook

function Hook:create(apply_pre, apply_post)
    assert(apply_pre == nil or type(apply_pre) == "function")
    assert(apply_post == nil or type(apply_post) == "function")

    local res = {}
    setmetatable(res, Hook)

    res.apply_pre = apply_pre
    res.apply_post = apply_post

    return res
end

function Hook:apply_pre(self)
    -- empty default
end

function Hook:apply_post(self)
    -- empty default
end

local EMPTY_HOOK = Hook:create()


local Node = {}
Node.__index = Node

--- Tree node for representing a vertex in configuration model tree
---
--- Nodes can be read by node:read(data_node) and written by node:write(parent_data_node)
---
--- @param name Name of the vertex for constructing XPath
--- @param apply_func Function which takes self, data node from libyang and applies the configuration to the system
--- @param read_func Function which takes self, data node from libyang and optional argument. It adds children to the
---        given node with data from the system or its argument. Returns last node it added.
function Node:create(name, apply_func, read_func, initialize_schema_func)
    assert(type(name) == "string")
    assert(type(apply_func) == 'function')
    assert(type(read_func) == 'function')
    assert(initialize_schema_func == nil or type(initialize_schema_func) == 'function')

    local handler = {}
    setmetatable(handler, Node)

    handler.apply = apply_func
    handler.serialize = read_func
    handler.name = name
    handler.module = nil -- must be filled in later by initialize_schema method
    handler.schema = nil -- must be filled in later by initialize_schema method

    -- default implementation
    local function schema_init(self, lys_node)
        assert(lys_node ~= nil, "Node named \'" .. self.name .. "\' does not exist in the YANG schema"
                                                            .. " (or something else happened).")
        assert(ffi.string(clib().schema_get_name(lys_node)) == self.name)
        self.module = clib().schema_get_module(lys_node)
        self.schema = lys_node
    end
    if initialize_schema_func == nil then
        initialize_schema_func = schema_init
    end
    handler.initialize_schema = initialize_schema_func

    return handler
end

--- Creates a simple child for ContainerNode
---
--- @param node Node that should be used.
local function Child(node)
    return {
        type = 'simple',
        name = node.name,
        node = node,
    }
end

--- Creates a list child for ContainerNode
---
--- @param get_args_func Function that will return a list of arguments that will be passed one by one into
---                      the created node
--- @param factory_func Node factory function that takes a name as its first argument
--- @param name Name of the node (for XPath creation)
--- @param ... arguments passed through to the factory
local function ListChild(get_args_func, factory_func, name, ...)
    assert(type(get_args_func) == "function")
    assert(type(factory_func) == "function")
    assert(type(name) == "string")

    local args = {...}
    local fact = factory_func(name, unpack(args))

    return {
        type = 'list',
        name = name,
        node_factory = fact,
        node = fact(nil),
        get_args = get_args_func,
    }
end

--- Node representing a container in YANG schema. Recursively calls its children.
---
--- @param name Name of the vertex for constructing XPath
--- @param container_model List of children. A child is a table created by some of the functions above.
--- @param hooks Table containing hooks that will be called in specified moments while processing the container.
local function ContainerNode(name, container_model, hooks)
    -- default hooks
    if hooks == nil then
        hooks = EMPTY_HOOK
    end

    -- local variables stored in closure
    local child_schema_nodes = {}

    -- optimize child lookup by name with table
    local child_lookup_table = {}
    for _,v in ipairs(container_model) do
        child_lookup_table[v.name] = v
    end

    --- Node's apply function
    local function handle_cont_read(self, node)
        hooks:apply_pre()

        local node_name = ffi.string(clib().node_get_name(node))
        debug.log("Reading container \"{}\"", self.name)
        assert(node_name == self.name)

        local child = clib().node_child_first(node)
        while child ~= nil do
            local nm = ffi.string(clib().node_get_name(child))
            -- our model doesn't have to be a full copy of the actual model
            -- it has to be a subset. So there might be a node that we can't
            -- find.
            if child_lookup_table[nm] ~= nil then
                -- we don't have to worry about types of children, because
                -- all of them have node property for config application
                child_lookup_table[nm].node:apply(child)
            end

            child = clib().node_child_next(child)
        end

        hooks:apply_post()
    end

    --- Node's serialize function
    local function handle_cont_write(self, parent_node)
        local cont = clib().node_new_container(parent_node, self.module, self.name)

        for _,v in ipairs(container_model) do
            if v.type == "simple" then
                _ = v.node:serialize(cont)
            elseif v.type == "list" then
                -- prepare argument list
                local args = v.get_args()
                local function get_nth(n)
                    return function()
                        return args[n]
                    end
                end

                -- for each argument, we use the node factory to create special node with
                -- that argument. And after initializing, use it once
                for i,_ in ipairs(args) do
                    local node = v.node_factory(get_nth(i))
                    node:initialize_schema(child_schema_nodes[v.name])
                    _ = node:serialize(cont)
                end
            end
        end

        return cont
    end

    local function schema_init(self, lys_node)
        assert(ffi.string(clib().schema_get_name(lys_node)) == self.name)
        self.module = clib().schema_get_module(lys_node)

        child_schema_nodes = Helpers.get_schema_children_table(lys_node)

        -- apply to all children
        for _,v in ipairs(container_model) do
            -- all children have node property, so we initialize just that
            v.node:initialize_schema(child_schema_nodes[v.node.name])
        end
    end

    return Node:create(name, handle_cont_read, handle_cont_write, schema_init)
end

--- Node used for binding of any values. Uses conversion between table and libyang tree.
--- The type that will be returned is deduced from the schema.
---
--- @param name Name of the vertex for constructing XPath
--- @param get_val Function that returns an object with resolvers state, that will be transformed into a libyang tree
--- @param set_val Function with one argument, will get an object with the same structure as the model tree
local function BindNode(name, get_val, set_val)
    --- Node's apply function
    local function handle_apply(self, node)
        -- do nothing when there is no set func
        if set_val == nil then
            return
        end

        -- obtain value from the lyd_node according to specified type
        local val = Helpers.node_to_object(node)

        -- set the value
        local status, err = pcall(set_val, val)

        -- error reporting
        if not status then
            debug.log("Error applying configuration in BindNode(name='{}') with the following object:", name)
            debug.dump_table(val)
            if type(val) == "table" and next(val) == nil then
                debug.log("That table is empty => container node was present, but with no children.")
            end
            error("Error in BindNode(name='" .. name .. "') set_val:\n       " .. err)
        end
    end

    --- Node's serialize function
    local function handle_serialize(self, parent_node)
        if get_val == nil then
            return nil
        end

        -- get the desired value safely
        local status, val = pcall(get_val)
        if not status then
            error("Error in BindNode(name='" .. name .. "') get_val:\n       " .. val)
        end

        return Helpers.object_to_node(val, name, self.schema, parent_node)
    end

    return Node:create(name, handle_apply, handle_serialize, nil)
end

--- Specialized {@link BindNode} which provides read only binding to a variable
---
--- @param name Name of the vertex for constructing XPath
--- @param bind_variable String name of the binded global variable
local function StateNode(name, bind_variable)
    -- generate get function
    local get_val = load("return " .. bind_variable)

    return BindNode(name, get_val, nil)
end

--- Specialized {@link BindNode} which provides read-write binding to a function
---
--- @param name Name of the vertex for constructing XPath
--- @param bind_func String name of the binded global function. When called without arguments, returns
---     current state. When called with one argument, sets value.
local function ConfigFnNode(name, bind_func)
    -- generate set and get functions
    local get_val = function() return bind_func() end
    local set_val = function(new_val) bind_func(new_val) end

    return BindNode(name, get_val, set_val)
end

--- Specialized {@link BindNode} which provides read-write binding to a variable
---
--- @param name Name of the vertex for constructing XPath
--- @param bind_value String name of the binded global variable.
local function ConfigVarNode(name, bind_variable)
    -- generate set and get functions
    local get_val = load("return " .. bind_variable)
    local set_val = load("return function(data) " .. bind_variable .. "= data end")()

    return BindNode(name, get_val, set_val)
end


-------------------------------------------------------------------------------
------------------------ Actual Configuration Binding -------------------------
-------------------------------------------------------------------------------


local function ListenInterfacesNodeFactory(name)
    -- |  |  +--rw listen-interfaces* [name]
    -- |  |  |  +--rw name <string>
    -- |  |  |  +--rw ip-address <ip-address(union)>
    -- |  |  |  +--rw port? <port-number(uint16)>
    -- |  |  |  +--rw cznic-resolver-knot:kind? <dns-transport-protocol(enumeration)>

    assert(name == "listen-interfaces") -- this argument must be there due to the way container node works

    --- the actual factory function
    return function(get_arg_func)
        -- return configured container bind node
        return BindNode(
            "listen-interfaces",
            get_arg_func,
            function(v)
                net.listen(v["ip-address"], v["port"], { kind = v["kind"] })
            end
        )
    end
end

local function TLSNode()
    -- |  |  +--rw tls
    -- |  |  |  +--rw cert? <fs-path(string)>
    -- |  |  |  +--rw cert-key? <fs-path(string)>
    -- |  |  |  +--rw cznic-resolver-knot:sticket-secret? <secret-string(string)>

    return BindNode(
        "tls",
        function()
            local t = net.tls()
            return {
                ["cert"] = t[1],
                ["cert-key"] = t[2],
            }
        end,
        function(vals) net.tls(vals["cert"], vals["cert-key"]) end
    )
end

local function hook_apply_pre_network()
    debug.log("Cleaning previously created listen sockets")

    -- close all previously opened listen sockets
    local already_listening = net.list()
    for _,v in ipairs(already_listening) do
        net.close(v['transport']['ip'], v['transport']['port'])
    end
end

local function get_listen_interfaces()
    -- the data structure from `net.list()` has to be transformed to be understood
    -- by ContainerBindNode
    local id = -1;

    local function transform(arg)
        id = id + 1
        return {
            ["ip-address"] = arg['transport']['ip'],
            ["id"] = tostring(id),
            ["port"] = arg['transport']['port'],
            ["kind"] = arg['kind'],
        }
    end

    local res = {}
    for _,v in ipairs(net.list()) do
        if v["kind"] == "dns" and v["transport"]["protocol"] == "tcp" then
            -- nothing
        else
            table.insert(res, transform(v))
        end
    end

    return res
end

--- Configuration schema reprezentation
local model =
    ContainerNode("dns-resolver", {
        Child(ContainerNode("cache", {
            Child(StateNode("current-size", "cache.current_size")),
            Child(BindNode("max-size", function() return cache.current_size end, function(v) cache.size = v end)),
            Child(ConfigFnNode("max-ttl", cache.max_ttl)),
            Child(ConfigFnNode("min-ttl", cache.min_ttl)),
        })),
        Child(ContainerNode("logging", {
            Child(BindNode("verbosity", function() return verbose() and 1 or 0 end, function(v) verbose(v > 0) end))
        })),
        Child(ContainerNode("network", {
            ListChild(get_listen_interfaces, ListenInterfacesNodeFactory, "listen-interfaces"),
            Child(TLSNode()),
        }, Hook:create(hook_apply_pre_network, nil))),
    })

-------------------------------------------------------------------------------
------------------------ Module Exports ---------------------------------------
-------------------------------------------------------------------------------


--- Module constructor
return function(clib_binding)
    _clib = clib_binding

    local initialized_schema = false
    local function init_schema()
        local depth = 0
        local function print_schema_tree(schema_node)
            debug.log("{}{}", string.rep("  ", depth), ffi.string(clib().schema_get_name(schema_node)))
            depth = depth + 1
            local children = Helpers.get_schema_children_table(schema_node)
            for _,node in pairs(children) do
                print_schema_tree(node)
            end
            depth = depth - 1
        end


        if not initialized_schema then
            -- dump schema tree for debugging purpose
            debug.log("Loaded schema tree:")
            debug.log("")
            print_schema_tree(clib().schema_root())
            debug.log("")
            debug.log("Schema tree end")

            model:initialize_schema(clib().schema_root())
            initialized_schema = true
        end
    end

    local module = {}
    function module.serialize_configuration(root_node)
        init_schema()

        -- serialize operational data
        local node = model:serialize(root_node)
        assert(node ~= nil)

        -- validate the result
        -- local validation_result = clib().node_validate(node)
        -- if validation_result ~= 0 then
        --     clib().node_free(node)
        --     print("Tree validation failed, see printed libyang errors")
        --     node = nil
        -- end

        return node
    end

    function module.apply_configuration(root_node)
        init_schema()

        model:apply(root_node)
    end

    return module
end

