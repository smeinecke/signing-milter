mt.echo("*** test: connect and disconnect")

local sock = os.getenv("MILTER_SOCKET") or "unix:/tmp/signing-milter-test/miltertest.sock"
conn = mt.connect(sock)
if conn == nil then
    error "mt.connect() failed"
end

mt.echo("connected")
mt.disconnect(conn)
