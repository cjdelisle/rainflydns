# RainflyDNS

*how to blow a 9 month lead*

RainflyDNS is effectively Namecoin with extra infrastructure on top so that that
thin clients can reliably verify server replies without the need to have 
the whole blockchain locally or trust a single party. It also provides tools for
mitigating obviously malicious activites such as typo squatting while being 
virtually immune to censorship and DNS poisoning attacks.

This is an implementation of RainflyDNS server in Node.js.
The RainflyDNS client resides in the cjdns codebase.

### How domain resolution works in RainflyDNS

There are three types of entities in RainflyDNS:

1) Core servers

2) Regular servers, like your average DNS server on clearnet

3) Clients

A domain is registered when the core servers achieve consensus about it, i.e.
all core servers agree on what the IP address for a given domain is.
How exactly the consensus is achieved is irrelevant to RainflyDNS.
Every core server then signs the domain/address pair[1] with its private key.

Clients have the public keys of the core servers, and can choose which servers
they trust. A domain registration is considered valid by the client if at least
X trusted core servers have signed the domain/address pair, where X should be
in the vicinity of 80% of trusted servers, but can be varied depending on 
the degree of your carelessness or paranoia.

Each server, regular or core, stores the namecoin blockchain along with the 
entire database of domain/address pairs and their signatures.

To resolve a domain, the client sends a request to a server where it specifies
which core servers it trusts. The server returns the domain/address pair and the
signatures done by the core servers specified by the client. The client checks 
the signatures and validates that there's sufficient consensus among the core 
servers about the domain/address pair.

Therefore, to alter the address of domain you have to convince at least 51%[2]
of the core servers that the address of a domain has changed.

This is very hard to achieve by hacking the servers since you have to hack a lot
 of them at the same time, and any changes would be detected reasonably quickly 
and the attacker would have to start over and discover new vulnerabilities 
in 51% of the servers.

This is also very hard to achieve by exercising political pressure on the core
server administrators, if the core servers are located in distinct and 
politically opposed regions. Beating less than 51% of core server admins into 
submission won't get you anywhere.

Censorship on regular servers via refusing to resolve some domains or returning 
invalid results also will not get you anywhere because the client 
will simply ask the next server in its list. Given enough regular servers 
in politically opposed regions, eventually a regular server that does not block 
the domain will be found. Furthermore, anyone can run their own regular or even
core server to bypass censorship.

Censorship on the transport layer between the client and the regular server
or the regular and core servers (especially selective censorship) is made
impossible by cjdns's encryption and routing algorithms.

Censorship or DoS attacks on regular servers via returning an outdated address
for a domain (assuming the domain is no longer hosted at the given address)
is mitigated by signing a timestamp[3] along with the domain/address pair.
Clients should not accept entries that were signed a long time ago. This would
require continuously re-signing all the domains with a short interval, but 
Namecoin demonstrates that this is a viable approach.

[1] "domain/address" pair is actually a simplification - multiple addresses for
the same domain is supported, as well as storing arbitrary data.

[2] If the consensus is "whatever 51% of servers consider to be correct and the
rest have to agree with", as seen in bitcoin/namecoin/etc. Otherwise you need
to hack X servers at once where X is defined by the client and should be in the
vicinity of 80% of core servers.

[3] The current implementation uses the number of namecoin block the domain
appears in instead of a literal timestamp. 
Clients should determine what the "current" namecoin block is by asking all
regular servers in their list for the latest block number *(not yet implemented).*
Servers should return a recently signed domain as a reply *(not yet implemented).*
The clients verify the signatures and pick the highest valid block number given.
This allows for accurate "epoch" lookup even if all but one servers in the 
client's list are malicious or compromised *(also not yet implemented).*

### Mitigating private key leak

Nothing is perfect, especially security systems. So eventually the private key 
of a core server will be leaked. This is why there are two types of keys:
"hot" and "cold".

The "hot" private key is what's always present on the server and used for
 signing domain entries. It is in turn signed by the "cold" private key, which 
is never present on the core server and was used on another machine only to sign
the "hot" key.

Clients trust the cold public key of the server. To be able to verify signatures
made using the hot key, the client has to find out what the hot key of a given
server is and check that it's not revoked.

Hot keys should be stored in Namecoin block chain and, in addition to being 
signed by the hot keys of all other servers, should be signed by the relevant 
cold key (this procedure is trivial but not yet automated).

On startup the client requests hot keys for core servers it trusts from regular
servers. It verifies that the keys are up to date using the same procedure as
for verifying domains *(not yet implemented, neither server- nor client-side).*

### Mitigating typo squatting, etc

Namecoin demonstrates that entirely uncontrollable DNS is not always desirable.
For example, there's little that can be done against typo squatting in regular
Namecoin.

*Domains can be invalidated if the core servers achieve consensus about it,
but they cannot use namecoin for that - people have to communicate directly.
Not sure how exactly, awaiting more info from cjd.*

RainflyDNS also supports having one (or potentially several) gatekeepers 
in addition to the ring of core servers. If the core servers honor 
the gatekeeper's decisions, he can veto registering any new domain, 
but his decisions are not retroactive, i.e. the gatekeeper's signature 
cannot be revoked. Note that this is an organizational measure rather than 
technical; it is optional and can be trivially altered or disabled by 
core server admins at any time.

### Subdomains

Subdomains are not yet implemented.

## Running the server

### Install the namecoin prerequesites:

    sudo aptitude install libdb5.1++-dev libboost-all-dev libglib2.0-dev curl

### Build namecoin:

    git clone http://gitboria.com/cjd/rainflynamecoin.git
    cd rainflynamecoin/src && make -f makefile.unix

### Setup, start and test namecoin:

    mkdir ~/.namecoin && echo 'rpcpassword=password' > ~/.namecoin/bitcoin.conf
    ./namecoind -daemon
    curl --user '':password --data-binary '{"method":"name_scan","params":["","500"],"id":1}' -H 'content-type: text/plain;' http://127.0.0.1:8336/

### Watch what namecon is doing:

    tail -f ~/.namecoin/debug.log

You will need to wait for namecoin to sync the chain, this could take as much as a few days depending on your system.

### Install node.js

RainflyDNS is developed and tested against Node.js 0.8.x

These are debian based install instructions. You probably don't want to use node from your package manager
because debian stuff is always out of date and arch independently compiled node and introduced a bug.

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
**PROTECT YOUR COLD CONFIGURATION FILE** - if it is lost or compromized there is no way to recover!

    offline$ ./rainserv --cold <servername>.h  > /a/very/safe/place/<servername>.cold.json

### Generate your hot configuration

Once you have a cold config you can now generate the hot config which will go on the server.

    offline$ ./rainserv --hot < /a/very/safe/place/cold.conf > <servername>.hot.json

Install your hot configuration on the live server then start it up:

    liveserver$ ./rainserv --start < <servername>.hot.json
