-- campaign.lua - what campaign.sh's template calls, and how each customer and link is changed
--
-- Run once before the first customer, with all of Lua; the template sees what
-- it defines.

-- A price as the shop writes it.
function euro(n)
    return string.format("%.2f €", n)
end

-- A customer who never ordered is left out, and the rest are greeted by their first name.
function on_recipient(r)
    if (r.orders or 0) == 0 then
        return false, "no order yet"
    end
    r.first = (r.name or ""):match("^(%S+)")
end

-- Each link to the shop says it came from this campaign; any other is left as it is.
function on_link(url, r)
    if url:find("^https://shop%.example%.com/") then
        return url .. (url:find("?", 1, true) and "&" or "?") .. "utm_source=mail&utm_campaign=autumn"
    end
end
