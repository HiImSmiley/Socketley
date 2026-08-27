-- Counting messages in on_message, and reporting the rate honestly.
--
-- Attach with:  socketley create server counted -p 9000 --lua message-counter.lua -s
--
-- On the number this prints: os.time() resolves to ONE SECOND, so the rate below
-- is the count divided by a whole number of seconds and is worth about as much
-- as that sounds.  It is here to show the shape of an on_message counter, not to
-- measure this daemon -- test/benchmark/ is where measurement lives, and it
-- exists because a figure like this one was once believed.

local message_count = 0
local start_time = os.time()

function on_start()
    print("Benchmark server started")
    start_time = os.time()
end

function on_message(msg)
    message_count = message_count + 1

    -- Do some work: parse and validate
    if msg and #msg > 0 then
        local processed = string.upper(msg)
        local len = #processed
    end

    -- Log every 1000 messages
    if message_count % 1000 == 0 then
        local elapsed = os.time() - start_time
        if elapsed > 0 then
            print(string.format("processed %d messages, roughly %.0f/sec over %ds",
                message_count, message_count / elapsed, elapsed))
        end
    end
end

function on_stop()
    local elapsed = os.time() - start_time
    print(string.format("Total: %d messages in %d seconds", message_count, elapsed))
end
