all:
	cdb -c -m signingtable.cdb signingtable
	chown signing-milter signingtable.cdb
	systemctl reload signing-milter
