mt.echo("*** test: Content-Type without MIME-Version accepted at EOH")

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

mt.header(conn, "From", "sender@example.com")
mt.getreply(conn)
mt.header(conn, "To", "recipient@example.com")
mt.getreply(conn)
mt.header(conn, "Subject", "Repro")
mt.getreply(conn)
mt.header(conn, "Content-Type", "text/plain; charset=\"utf-8\"")
mt.getreply(conn)

if mt.eoh(conn) ~= nil then
    error "mt.eoh() failed"
end

local reply = mt.getreply(conn)
mt.echo("EOH reply code = " .. tostring(reply))
if reply ~= SMFIR_CONTINUE then
    error "mt.eoh() unexpected reply (expected CONTINUE)"
end

mt.disconnect(conn, true)
