-- Answer every request with the name of the runtime that answered it.
--
-- This is the whole oracle of the docker cluster test.  A plain socketley
-- server in inout mode relays a message to the OTHER clients and says nothing
-- back to the sender, so a client on the far side of a gateway proxy gets a
-- successful connection and zero bytes — which is what test_cluster_docker.sh
-- used to assert, and it is true whether the request reached another container,
-- reached a backend in the gateway's own container, or reached a backend that
-- had been dead for a minute.
--
-- With this script the reply names the container that produced it, so "a
-- request entering the gateway was answered by a backend on a different node"
-- becomes a thing a test can read rather than infer.  The runtime is named
-- web1 on api1 and web2 on api2, one per container, so the name is the node.
--
-- on_message is defined and empty on purpose: defining it claims message
-- handling and suppresses the default broadcast, so the only bytes that ever
-- leave this server are the ones below.  Without it a second concurrent client
-- would also receive the first one's request relayed to it.
function on_message(msg)
end

-- Sender-addressed, not broadcast.  The proxy may hold more than one
-- connection to this backend at a time, and self.broadcast() would answer all
-- of them — every reply would still carry the right node name, so the test
-- would still pass, but it would pass while sending answers to connections
-- that did not ask.
function on_client_message(client_id, msg)
    self.send(client_id, self.name .. "\n")
end
