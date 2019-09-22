# Running the client

The client has two modes of operation:

* Interactive
* Fire once

To send messages directly from the commandline, do:

```sh
python client.py --servip localhost --servport 7007 testmsg1 testmsg2 [...]
```

To get an interactive prompt do:

```sh
python client.py --servip localhost --servport 7007 --interactive
```
