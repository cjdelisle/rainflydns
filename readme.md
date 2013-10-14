# RainflyDNS

*how to blow a 9 month lead*

###Install the namecoin prerequesites:

    sudo aptitude install libdb5.1++-dev libboost-all-dev libglib2.0-dev

###Build namecoin:

    git clone http://gitboria.com/cjd/rainflynamecoin.git
    cd rainflynamecoin/src && make -f makefile.unix

###Setup, start and test namecoin:

    mkdir ~/.namecoin && echo 'rpcpassword=password' > ~/.namecoin/bitcoin.conf
    ./namecoind -daemon
    curl --user '':password --data-binary '{"method":"name_scan","params":["","500"],"id":1}' -H 'content-type: text/plain;' http://127.0.0.1:8336/

###Watch what namecon is doing:

    tail -f ~/.namecoin/debug.log

You will need to wait for namecoin to sync the chain, this could take as much as a few days depending on your system.

###Install node.js

These are debian based install instructions (you probably don't want to use node from your package
manager) debian stuff is always out of date and arch independently compiled node and introduced a
bug.

    cd ~ && mkdir nodejs && cd nodejs && wget http://nodejs.org/dist/v0.10.20/node-v0.10.20-linux-x64.tar.gz
    tar -xf ./node-v0.10.20-linux-x64.tar.gz
    cd node-v0.10.20-linux-x64
    sudo cp ./bin/ ./share/ ./lib/ /usr/local/ -r

### Grab RainflyDNS and install requirements

    cd ~ && git clone git clone http://gitboria.com/cjd/rainflydns.git
    cd rainflydns
    npm install

### Generate your cold configuration

This should be done *offline* or at least on the most secure system you have. This operation
does not require namecoin to carry out, only node.js. Your cold configuration will be needed
*once* to generate your hot configuration and after that it will only be needed if your hot
configuration (the one on the live server) is lost or stolen.
**PROTECT YOUR COLD CONFIGURATION FILE** if it is lost or compromized there is no way to recover.

    offline$ ./rainserv --cold <servername>.h  > /a/very/safe/place/<servername>.cold.json

### Generate your hot configuration

Once you have a cold config you can now generate the hot config which will go on the server.

    offline$ ./rainserv --hot < /a/very/safe/place/cold.conf > <servername>.hot.json

Install your hot configuration on the live server then start it up:

    liveserver$ ./rainserv --start < <servername>.hot.json
