mt.echo("*** test: Content-Type without MIME-Version is accepted")

local sock = os.getenv("MILTER_SOCKET") or "unix:/tmp/signing-milter-test/miltertest.sock"
conn = mt.connect(sock)
if conn == nil then
    error "mt.connect() failed"
end

if mt.mailfrom(conn, "<sender@example.com>") ~= nil then
    error "mt.mailfrom() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
    error "mt.mailfrom() unexpected reply"
end

if mt.rcptto(conn, "<recipient@example.com>") ~= nil then
    error "mt.rcptto() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
    error "mt.rcptto() unexpected reply"
end

if mt.header(conn, "From", "sender@example.com") ~= nil then
    error "mt.header(From) failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
    error "mt.header(From) unexpected reply"
end

if mt.header(conn, "To", "recipient@example.com") ~= nil then
    error "mt.header(To) failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
    error "mt.header(To) unexpected reply"
end

if mt.header(conn, "Subject", "Repro") ~= nil then
    error "mt.header(Subject) failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
    error "mt.header(Subject) unexpected reply"
end

-- Trigger: a Content-* header without MIME-Version must be accepted.
if mt.header(conn, "Content-Type", "text/plain; charset=\"utf-8\"") ~= nil then
    error "mt.header(Content-Type) failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
    error "mt.header(Content-Type) unexpected reply"
end

if mt.eoh(conn) ~= nil then
    error "mt.eoh() failed"
end

local reply = mt.getreply(conn)
mt.echo("EOH reply: " .. tostring(reply))
if reply ~= SMFIR_CONTINUE then
    error "mt.eoh() unexpected reply (expected CONTINUE)"
end

mt.disconnect(conn)
