
check how it frees up TCP ports
check how it frees up UDP ports
rework logs, each line should have client_ip:client_port
test work on limited number of open files (prevent logs flood)
2025-10-07 
 [x] close connection after MAX_CONNS reached.
2026-02-25
 [x] own accept loop (fix exceptions of accepting sockets under file limits).
2026-03-25
 [x] [dev__aiodns] migrate DNS resolver to `aiodns`
2026-06-22
 [x] UDP Ipv6 fixed.
