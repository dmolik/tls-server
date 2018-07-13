## REFACTORING

  -  [x] Move to thread-local session storage, with event-loop based communication
  -  [ ] Support daemon reload (including session draining)
    -  Session age
    -  TCP keepalive
    -  Send reconnect to clients
    -  Disable listening
    -  Memmory checking - make sure everything is freed up.
  -  [x] move setup into main.c
  -  [ ] support an app.c for Business code
  -  [ ] perl test harness ( requires client )
  -  [ ] support ssl signing in testing - would the ca-signer be included in this repo then? ... probably

## IDEAS

  -  [x] Error Checking
  -  [x] Daemon
  -  [x] Logging
  -  [x] CLI Options
  -  [ ] ENV Options - I'm not sure it's worth adding this in as a base feature. If I get an issue or pr for it I suppose I will do it.
  -  [x] Config file
  -  [ ] support client cert database ( a sort of authorization on top of TLS-client authentication )
