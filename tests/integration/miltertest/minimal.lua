mt.echo("*** test: minimal envelope from/quit")

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

mt.disconnect(conn)
