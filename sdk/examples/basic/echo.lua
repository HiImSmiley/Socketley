-- What echo_server_lua runs: every message back to the client that sent it.
function on_client_message(client_id, msg)
    self.send(client_id, "echo: " .. msg)
end
