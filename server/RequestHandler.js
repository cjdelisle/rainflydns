/* vim: set expandtab ts=4 sw=4: */
/*
 * You may redistribute this program and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
var UDP = require('dgram');
var Message = require('../common/Message')
var Serial = require('../common/Serial');
var Crypto = require('../common/Crypto');

var RequestTypes = {
    PING: 0x00,
    HOT_KEYS: 0x01,
    LOOKUP: 0x02
};

var ZERO = new Buffer('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==', 'base64');

var parseList = function(msg, elementSize, count)
{
    if (!count) {
        count = Message.size(msg) / elementSize;
        if (Message.size(msg) !== (elementSize * count)) { throw new Error(); }
    }
    var out = [];
    for (var i = 0; i < count; i++) {
        out.push(Message.pop(msg, elementSize));
    }
    return out;
};

var ping = function(msg, callback)
{
    console.log('ping');
    callback(msg);
};

var hotKeys = function(msg, gossiper, callback)
{
    var keys = [];
    var idents = parseList(msg, Crypto.PUBLIC_KEY_SIZE);
    idents = idents.reverse();
    var manifest = 0;
    idents.forEach(function(ident) {
        manifest <<= 1;
        var k = gossiper.hotKey(ident);
        if (k) {
            manifest |= 1;
            keys.push(k);
        }
    });
    if (Message.size(msg) !== 0) { throw new Error(); }
    keys.forEach(function(key) {
        Message.push(msg, key);
    });
    Message.push32(msg, manifest);
    callback(msg);
};

var lookup = function(msg, gossiper, callback)
{
    var name = Serial.readStrList(msg, 1);
    if (name.length !== 1) { throw new Error(); }
    name = name[0];
    var hotKeys = [];
    while (Message.size(msg) > 0) {
        hotKeys.push(Message.pop(msg, Crypto.PUBLIC_KEY_SIZE));
    }

    var entry = gossiper.lookup(name);

    var hotKey;
    while ((hotKey = hotKeys.pop())) {
        var hotKeyStr = new Buffer(hotKey).toString('base64');
        if (hotKeyStr in entry.sigs) {
            console.log("pushing key");
            Message.push(msg, entry.sigs[hotKeyStr]);
        } else {
            console.log("unknown key, pushing zero");
            Message.push(msg, ZERO);
        }
    }

    Message.push(msg, entry.binEntry);

    callback(msg);
};

/*

HotKeys:

     0               1               2               3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 0  |0|    One      |                     Cookie                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 4  |                                                               |
    +                                                               +
 8  |                                                               |
    +                                                               +
12  |                                                               |
    +                           Key One                             +
16  |                                                               |
    +                                                               +
20  |                                                               |
    +                                                               +
24  |                                                               |
    +                                                               +
28  |                                                               |
    +                                                               +
32  |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
36  |                                                               |
    +                           Key Two ...


HotKeys Reply:

HotKey/signature pairs in the HotKeys reply are in the same order
as ColdKeys in the HotKeys request. BitField represents which
keys from the request were able to be serviced. The least
significant bit in BitField represents the first key in the
request and so on.

     0               1               2               3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 0  |1|    One      |                     Cookie                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 4  |                          BitField                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8  |                                                               |
    +                                                               +
12  |                                                               |
    +                                                               +
16  |                                                               |
    +                                                               +
20  |                                                               |
    +                                                               +
24  |                                                               |
    +                                                               +
28  |                                                               |
    +                                                               +
32  |                                                               |
    +                        Signature One                          +
36  |                                                               |
    +                                                               +
40  |                                                               |
    +                                                               +
44  |                                                               |
    +                                                               +
48  |                                                               |
    +                                                               +
52  |                                                               |
    +                                                               +
56  |                                                               |
    +                                                               +
60  |                                                               |
    +                                                               +
64  |                                                               |
    +                                                               +
68  |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
72  |                                                               |
    +                                                               +
76  |                                                               |
    +                                                               +
80  |                                                               |
    +                                                               +
84  |                         Hot Key One                           |
    +                                                               +
88  |                                                               |
    +                                                               +
92  |                                                               |
    +                                                               +
96  |                                                               |
    +                                                               +
100 |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
104 |                                                               |
    +                                                               +
100 |                        Signature Two                          |
    +
    ...


Lookup:


     0               1               2               3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 0  |0|    Two      |                     Cookie                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 4  |   NameLength  |                                               |
    +-+-+-+-+-+-+-+-+                                               +
 8  |                  Domain (variable length)                     |
    +                                                               +
12  |                                                               |
    +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16  |               |                                               |
    +-+-+-+-+-+-+-+-+    Zero padding to nearest 8 byte boundry     +
20  |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
24  |                                                               |
    +                                                               +
28  |                                                               |
    +                                                               +
32  |                                                               |
    +                                                               +
36  |                       Hot Key One                             |
    +                                                               +
40  |                                                               |
    +                                                               +
44  |                                                               |
    +                                                               +
48  |                                                               |
    +                                                               +
52  |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
56  |                                                               |
    +                                                               +
60  |                                                               |
    +                                                               +
64  |                                                               |
    +                       Hot Key Two                             +
68  |                                                               |
    +                                                               +
72  |                                                               |
    ...

Lookup Reply:

The server must send as many signature entries as the client sent
hot keys, truncating when the packet size reaches 1024 bytes.
If a signature is unavailable, the server must send zeros instead
of that signature.

     0               1               2               3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 0  |1|    Two      |                     Cookie                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 4  |                             Time                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8  |   NameLength  |          Name (variable size)                 |
    +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12  |                               |   NextLength  |               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +       
16  |                 Next Name (variable size)                     |
    +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
20  |               |   ValueLength |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     Value (variable size)     +
24  |                                                               |
    +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
28  |               |    Zero padding to nearest 8 byte boundry     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
32  |                                                               |
    +                                                               +
36  |                                                               |
    +                                                               +
40  |                                                               |
    +                                                               +
44  |                                                               |
    +                                                               +
48  |                                                               |
    +                                                               +
52  |                                                               |
    +                                                               +
56  |                                                               |
    +                                                               +
60  |                                                               |
    +                                                               +
64  |                                                               |
    +                        Signature One                          +
68  |                                                               |
    +                                                               +
72  |                                                               |
    +                                                               +
76  |                                                               |
    +                                                               +
80  |                                                               |
    +                                                               +
84  |                                                               |
    +                                                               +
88  |                                                               |
    +                                                               +
92  |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
96  |                                                               |
    +                                                               +
100 |                                                               |
    +                                                               +
104 |                                                               |
    +                                                               +
100 |                                                               |
    +                                                               +
100 |                                                               |
    +                           Sig Two
    ...

*/

var init = function(address, port, gossiper)
{
  var sock = UDP.createSocket((address.indexOf(':') > -1) ? 'udp6' : 'udp4');
  var handleMessage = function (buff, rinfo) {
    var msg = Message.wrap(buff);
    var typeAndCookie = Message.pop32(msg);
    var callback = function(msg) {
      Message.push16(msg, typeAndCookie & 0xffff);
      Message.push8(msg, (typeAndCookie>>16) & 0xff);
      // flag the message as a reply
      Message.push8(msg, ((typeAndCookie>>24) | (1<<7) & 0xff));
      sock.send(msg.buff, msg.offset, msg.buff.length - msg.offset, rinfo.port, rinfo.address);
    };

    switch (typeAndCookie >> 24) {
      case RequestTypes.PING: return ping(msg, callback);
      case RequestTypes.HOT_KEYS: return hotKeys(msg, gossiper, callback);
      case RequestTypes.LOOKUP: return lookup(msg, gossiper, callback);
      default:
    }
  };

  sock.on("message", function (buff, rinfo) {
      try {
          handleMessage(buff, rinfo);
      } catch (e) {
          console.log("bad request from [" + rinfo.address + "] [" + e.stack + "] "
              + " original message [" + new Buffer(buff).toString('hex') + "]");
      }
  });
  sock.bind(port, address);
};

module.exports.init = init;
