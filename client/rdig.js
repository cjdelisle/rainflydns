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
var Fs = require('fs');
var Message = require('../common/Message');
var Serial = require('../common/Serial');
var Crypto = require('../common/Crypto');

var RequestType = {
    PING: 0x00,
    HOT_KEYS: 0x01,
    LOOKUP: 0x02
};
var HOME = process.env.HOME || process.env.HOMEPATH || process.env.USERPROFILE;

var printHex = function(msg)
{
    var buff = msg.buff.slice(msg.offset, msg.buff.length);
    return buff.toString('hex');
};

var sendMsg = function (msg, reqType, target, callback)
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

    console.log("sending: " + printHex(msg));
    sock.send(msg.buff, msg.offset, msg.buff.length - msg.offset, target[1], target[0]);
};

var dotBitLookup = function (name, keys, minSigs, target)
{
    var buff = new Buffer(1024);
    var msg = Message.wrap(buff);
    Message.reset(msg);
    console.log('looking up [' + name + ']');
console.log(keys.length);
    for (var i = keys.length-1; i >= 0; i--) {
        Message.push(msg, keys[i]);
    }

    Serial.writeStrList(msg, [name]);

    sendMsg(msg, RequestType.LOOKUP, target, function(msg) {
        console.log('got response [' + printHex(msg) + ']');
console.log(">>"+Message.size(msg));
        var names = Serial.readStrList(msg);
        var sigs = [];
console.log(keys.length)
console.log(Message.size(msg));
        for (var i = 0; i < keys.length && Message.size(msg) > 0; i++) {
            sigs[i] = Message.pop(msg, Crypto.SIG_SIZE);
        }
console.log("---"+Message.size(msg));
        Serial.writeStrList(msg, names);
console.log(printHex(msg));
        var sigContent = Message.pop(msg, Message.size(msg));
        validSigs = 0;
        for (var i = 0; i < sigs.length; i++) {
            if (Crypto.isValid(sigContent, sigs[i], keys[i])) {
                validSigs++;
            } else {
                console.log("invalid signature");
            }
        }
        if (validSigs < minSigs) {
            throw new Error("not enough signatures: need [" + minSigs
                + "] have [" + validSigs + "] total sigs: ["
                + sigs.length + "]");
        }
        console.log(JSON.stringify(names));
    });
};

var doKeysLookup = function(keys, target, minSigs, callback)
{
    var buff = new Buffer(1024);
    var msg = Message.wrap(buff);
    Message.reset(msg);
    console.log('looking up keys');

    for (var i = keys.length - 1; i >= 0; i--) {
        Message.push(msg, keys[i]);
    }
    sendMsg(msg, RequestType.HOT_KEYS, target, function(msg) {
        console.log('got response [' + printHex(msg) + ']');
        var bitField = Message.pop32(msg);
        var outKeys = [];
        for (var i = 0; i < keys.length; i++) {
            if (!(bitField & 1)) { bitField >>= 1; continue; }
            bitField >>= 1;
            var sig = new Buffer(Message.pop(msg, Crypto.SIG_SIZE));
            var hotKey = new Buffer(Message.pop(msg, Crypto.PUBLIC_KEY_SIZE));
            if (!Crypto.isValid(hotKey, sig, keys[i])) {
                callback(new Error("bad signature")); return;
            }
            outKeys[outKeys.length] = hotKey;
        }
        if (outKeys.length < minSigs) {
            callback(new Error("not enough keys to satisfy minSignatures")); return;
        }
        callback(undefined, outKeys);
    });
};

var doLookup = function(name)
{
    Fs.readFile(HOME + "/.rdig/conf.json", function(err, json) {
        if (err) { throw err; }
        json = JSON.parse(json);
        var keys = [];
        for (var i = 0; i < json.keys.length; i++) {
            keys[i] = new Buffer(json.keys[i], 'base64');
        }
        var targetIndex = Math.floor(Math.random() * 10000) % json.servers.length;
        var tryServer = function(index) {
            if (index % json.servers.length === targetIndex && index !== targetIndex) {
                throw new Error("Ran out of servers to try.");
            }
            var target = json.servers[index % json.servers.length];
            doKeysLookup(keys, target, json.minSignatures, function(err, keys) {
                if (err) {
                    console.log("Error contacting [" + JSON.stringify(target) + "] ["
                        + err.stack + "]");
                    tryServer(index+1); return;
                }
                dotBitLookup('d/' + name.replace(/.h$/, '') + '/', keys, json.minSignatures, target);
            });
        };
        tryServer(targetIndex);
    })
};

var genconf = function()
{
    console.log(JSON.stringify({
        __COMMENT: "This is a configuration for rdig",
        keys: [
            "AHBVU9rCngoY9v7yQ8mhWBehVwc5UoGHK42MdYB8VSI="
        ],
        servers: [
            [ "127.0.0.1", 9001 ]
        ],
        minSignatures: 1
    }, null, '  '));
};

var usage = function()
{
    console.log("rdig <domain>.h       lookup a domain using default config");
    console.log("rdig --genconf        make a new config file with defaults for nic.h");
    console.log();
    console.log("example:");
    console.log("mkdir ~/.rdig && rdig --genconf > ~/.rdig/conf.json");
    console.log("rdig nic.h");
};

var main = function() {
    for (var i = 0; i < process.argv.length; i++) {
        if (i == process.argv.length-1) {
            var name = process.argv[i];
            if (/.h$/.test(name)) {
                doLookup(name);
                return;
            }
        }

        if (process.argv[i] === '--genconf') {
            genconf();
            return;
        }

    }
    usage();
};

main();
