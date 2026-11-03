-- =============================================================================
-- shop.lua - An MCP server an AI client asks about a shop's orders
-- =============================================================================
--
-- USAGE:
--   printf 'claude %s\nops %s admin\n' "$(openssl rand -hex 16)" "$(openssl rand -hex 16)" > /etc/socketley/mcp.keys
--   socketley create mcp shop -p 9600 --keys /etc/socketley/mcp.keys \
--       --lua examples/mcp/shop.lua --tools daemon --instructions "Ask about the shop's orders." -s
--   claude mcp add --transport http shop http://127.0.0.1:9600/mcp \
--       --header "Authorization: Bearer <claude's secret>"
--
-- Or people sign in through an idp runtime, Claude Code opening the sign-in page itself:
--   socketley create idp auth -p 9500 --domain auth.example.com --resources https://shop.example.com/mcp -s
--   socketley create mcp shop -p 9600 --domain shop.example.com --idp auth --lua examples/mcp/shop.lua -s
--   claude mcp add --transport http shop https://shop.example.com/mcp
--
-- The client is offered three tools of this script -- an order's state, the
-- orders of a customer, and marking one sent, which only an admin's key sees --
-- the catalog as a resource, a prompt that writes a customer a note, and with
-- --tools daemon this daemon's runtimes, listed for every key and started and
-- stopped for an admin's.
-- =============================================================================

local orders = {
    ["A-1001"] = { customer = "ann", item = "mug", state = "paid" },
    ["A-1002"] = { customer = "ann", item = "poster", state = "sent" },
    ["A-1003"] = { customer = "ben", item = "t-shirt", state = "paid" },
}

mcp.tool{
    name = "order_status",
    description = "The state of one order: paid, sent or unknown.",
    read_only = true,
    input = { type = "object", properties = { id = { type = "string", description = "An order id such as A-1001" } },
              required = { "id" } },
    output = '{"type":"object","properties":{"id":{"type":"string"},"state":{"type":"string"},"item":{"type":"string"}}}',
    handler = function(args)
        local o = orders[args.id]
        if not o then
            return { text = "There is no order " .. args.id .. ".", error = true }
        end
        return { structured = { id = args.id, state = o.state, item = o.item } }
    end,
}

mcp.tool{
    name = "customer_orders",
    description = "Every order of one customer.",
    read_only = true,
    input = { type = "object", properties = { customer = { type = "string" } }, required = { "customer" } },
    handler = function(args)
        local list = {}
        for id, o in pairs(orders) do
            if o.customer == args.customer then
                list[#list + 1] = { id = id, item = o.item, state = o.state }
            end
        end
        table.sort(list, function(a, b) return a.id < b.id end)
        return { structured = { customer = args.customer, orders = list } }
    end,
}

mcp.tool{
    name = "mark_sent",
    description = "Marks a paid order as sent.",
    admin = true,
    idempotent = true,
    input = { type = "object", properties = { id = { type = "string" } }, required = { "id" } },
    handler = function(args, who)
        local o = orders[args.id]
        if not o or o.state ~= "paid" then
            return { text = "Order " .. args.id .. " is not one waiting to be sent.", error = true }
        end
        o.state = "sent"
        socketley.log(who.name .. " marked " .. args.id .. " sent")
        return "Order " .. args.id .. " is sent."
    end,
}

mcp.resource{
    uri = "shop://catalog",
    name = "catalog",
    description = "What the shop sells.",
    mime = "text/plain",
    ttl_ms = 60000,
    read = function()
        return "mug 12 EUR\nposter 20 EUR\nt-shirt 25 EUR\n"
    end,
}

mcp.prompt{
    name = "customer_note",
    description = "A short note to a customer about their order.",
    arguments = { { name = "id", description = "The order id", required = true } },
    get = function(args)
        local o = orders[args.id]
        local state = o and o.state or "unknown"
        return { description = "A note about " .. args.id,
                 messages = { { role = "user",
                                text = "Write a two-sentence, friendly note to the customer: their order "
                                       .. args.id .. " is " .. state .. "." } } }
    end,
}
