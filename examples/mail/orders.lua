-- orders.lua - a mail runtime's script: mail to orders@ goes to a broker, not to a mailbox
--
--   socketley create mail m --mail-domain example.com --lua orders.lua -s
--
-- on_rcpt takes orders@example.com, which no mailbox has, so its messages are
-- the script's alone; on_message publishes each and answers its sender.

function on_rcpt(r, default)
    if r.to == "orders@example.com" then
        return true
    end
    -- Saying nothing keeps what the aliases and the users decide.
end

function on_message(m)
    if m.to[1] ~= "orders@example.com" then
        return
    end
    socketley.mqtt.publish("bus", "orders/new", m.message or "", { qos = 1 })
    socketley.mail.send("m", {
        from = "orders@example.com",
        to = m.from,
        subject = "Re: " .. (m.subject or "your order"),
        text = "Thank you, your order " .. m.id .. " is in.",
    })
end
