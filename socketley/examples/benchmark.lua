-- Benchmark Lua script for socketley
-- Tests on_message callback performance

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
            print(string.format("Processed %d messages (%.0f msg/sec)",
                message_count, message_count / elapsed))
        end
    end
end

function on_stop()
    local elapsed = os.time() - start_time
    print(string.format("Total: %d messages in %d seconds", message_count, elapsed))
end
