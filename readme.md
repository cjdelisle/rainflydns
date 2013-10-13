# RainflyDNS

*how to blow a 9 month lead*

1. `git clone http://gitboria.com/cjd/rainflynamecoin.git`
2. `echo 'rpcpassword=password' > ~/.namecoin/bitcoin.conf`
3. check it `curl --user '':password --data-binary '{"method":"name_scan","params":["","500"],"id":1}' -H 'content-type: text/plain;' http://127.0.0.1:8336/`
