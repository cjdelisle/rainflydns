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
var Message = require('./Message');
var Crypto = require('./Crypto');
var Serial = require('./Serial');
var Crypto = require('./Crypto');

var RequestType = module.exports.RequestType = {
    PING: 0x00,
    HOT_KEYS: 0x01,
    LOOKUP: 0x02
};

var printHex = function(msg)
{
    var buff = msg.buff.slice(msg.offset, msg.buff.length);
    return buff.toString('hex');
};

var sendMsg = module.exports.sendMsg = function (msg, reqType, target, callback)
{
    var sock = UDP.createSocket((target[0].indexOf(':') > -1) ? 'udp6' : 'udp4');
    var cookieOne = Math.floor(Math.random() * ((1<<16)-1));
    Message.push16(msg, cookieOne);
    var cookieTwo = Math.floor(Math.random() * 255);
    Message.push8(msg, cookieTwo);
    Message.push8(msg, reqType);

    sock.on("message", function (buff, rinfo) {
      var msg = Message.wrap(buff);
      var respType = Message.pop8(msg);
      if (respType !== (reqType | (1<<7))) { console.log("wrong response type"); return; }
      var respCookieTwo = Message.pop8(msg);
      if (respCookieTwo !== cookieTwo) { console.log("wrong cookieTwo"); return; }
      var respCookieOne = Message.pop16(msg);
      if (respCookieOne !== cookieOne) { console.log("wrong cookieOne"); return; }

      sock.close();

      callback(msg);
    });

//    console.log("sending: " + printHex(msg));
    sock.send(msg.buff, msg.offset, msg.buff.length - msg.offset, target[1], target[0]);
};

var lookupHotKeys = module.exports.lookupHotKeys = function(keys, target, callback)
{
    var buff = new Buffer(1024);
    var msg = Message.wrap(buff);
    Message.reset(msg);
//    console.log('looking up keys');

    for (var i = keys.length - 1; i >= 0; i--) {
        Message.push(msg, keys[i]);
    }
    sendMsg(msg, RequestType.HOT_KEYS, target, function(msg) {
//        console.log('got response [' + printHex(msg) + ']');
        var bitField = Message.pop32(msg);
        var outKeys = {};
        for (var i = 0; i < keys.length; i++) {
            if (!(bitField & 1)) { bitField >>= 1; continue; }
            bitField >>= 1;
            var sig = Message.pop(msg, Crypto.SIG_SIZE);
            var hotKey = Message.pop(msg, Crypto.PUBLIC_KEY_SIZE);
            if (!Crypto.isValid(hotKey, sig, keys[i])) {
                callback(new Error("bad signature")); return;
            }
            outKeys[new Buffer(keys[i]).toString('base64')] =
                Buffer.concat([new Buffer(sig), new Buffer(hotKey)]);
        }
        callback(undefined, outKeys);
    });
};

var lookup = module.exports.lookup = function (name, hotKeys, target, callback)
{
    var buff = new Buffer(1024);
    var msg = Message.wrap(buff);
    Message.reset(msg);
//    console.log('looking up [' + name + ']');
//console.log(keys.length);
    var hotKeysArray = [];
    var identitiesArray = [];
    for (var ident in hotKeys) {
        hotKeysArray.push(hotKeys[ident]);
        identitiesArray.push(ident);
    }
    for (var i = hotKeysArray.length-1; i >= 0; i--) {
        Message.push(msg, hotKeysArray[i]);
    }

    Serial.writeStrList(msg, [name]);

    sendMsg(msg, RequestType.LOOKUP, target, function(msg) {
//        console.log('got response [' + printHex(msg) + ']');
//console.log(">>"+Message.size(msg));
        var names = Serial.readStrList(msg);
        var sigs = [];
//console.log(hotKeysArray.length)
//console.log(Message.size(msg));
        for (var i = 0; i < hotKeysArray.length && Message.size(msg) > 0; i++) {
            sigs[i] = Message.pop(msg, Crypto.SIG_SIZE);
        }
        Serial.writeStrList(msg, names);
//console.log(printHex(msg));
        var sigContent = Message.pop(msg, Message.size(msg));
        validSigs = {};
        for (var i = 0; i < sigs.length; i++) {
            if (Crypto.isValid(sigContent, sigs[i], hotKeysArray[i])) {
                validSigs[identitiesArray[i]] = hotKeysArray[i];
            } else {
                console.log("invalid signature");
            }
        }
        callback(undefined, {
            entry: names,
            sigs: validSigs
        });
    });
};
