# @TEST-REQUIRES: test -e ${TRACES}/radius_localhost.pcapng
# @TEST-EXEC: zeek -Cr ${TRACES}/radius_localhost.pcapng %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff radius.log
#
# @TEST-DOC: Test Radius against Zeek with a small trace.

@load analyzer
