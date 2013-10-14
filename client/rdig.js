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
var Fs = require('fs');
var Base32 = require('../common/Base32');
var Messenger = require('../common/Messenger');

var HOME = process.env.HOME || process.env.HOMEPATH || process.env.USERPROFILE;

var dotBitLookup = function (name, hotKeys, minSigs, target, messenger)
{
    messenger.lookup(name, hotKeys, target, function (err, entry) {
        if (err) { throw err; }
console.log("valid signatures [" + Object.keys(entry.validSigsByIdent).length + "]");
        for (var key in entry.validSigsByIdent) {
console.log("valid signature from [" + key + "]");
        }
        if (Object.keys(entry.validSigsByIdent).length < minSigs) {
            throw new Error("not enough signatures: need [" + minSigs
                + "] have [" + Object.keys(entry.validSigsByIdent).length + "]");
        }
        console.log(JSON.stringify(entry.entry));
        messenger.shutdown();
    });
};

var doKeysLookup = function(keys, target, minSigs, messenger, callback)
{
    var keyArray = [];
    for (name in keys) { keyArray.push(keys[name]); }
    messenger.lookupHotKeys(keyArray, target, function (err, hotKeys) {
        if (err) { callback(err); return; }
        if (Object.keys(hotKeys).length < minSigs) {
            callback(new Error("not enough keys to satisfy minSignatures")); return;
        }
        var outKeys = {};
        for (name in keys) {
            var keyStr = new Buffer(keys[name]).toString('base64');
            if (typeof(hotKeys[keyStr]) !== 'undefined') {
console.log("have key [" + name + "]");
                outKeys[name] = hotKeys[keyStr];
            }
        }
        callback(undefined, outKeys);
    });
};

var doLookup = function(name)
{
    Fs.readFile(HOME + "/.rainfly/conf.json", function(err, json) {
        if (err) { throw err; }
        var messenger = Messenger.init();
        json = JSON.parse(json);
        var keys = {};
        for (var i = 0; i < json.keys.length; i++) {
            keys[json.keys[i]] = Base32.decode(json.keys[i].replace(/\..*$/, ''));
        }
        var targetIndex = Math.floor(Math.random() * json.servers.length);
        var tryServer = function(index) {
            if (index % json.servers.length === targetIndex && index !== targetIndex) {
                throw new Error("Ran out of servers to try.");
            }
            var target = json.servers[index % json.servers.length];
            doKeysLookup(keys, target, json.minSignatures, messenger, function(err, hotKeys) {
                if (err) {
                    console.log("Error contacting [" + JSON.stringify(target) + "] ["
                        + err.stack + "]");
                    tryServer(index+1); return;
                }
                dotBitLookup('h/' + name.replace(/.h$/, ''), hotKeys, json.minSignatures, target, messenger);
            });
        };
        tryServer(targetIndex);
    })
};

var genconf = function()
{
    console.log(JSON.stringify({
        __COMMENT: "This is a configuration for rdig",
          "keys": [
            "7kuc3jcyql3cm8lx5zdj8vc0tkz8679kyx83utbm1ub5bxpf4mf1.mittens.h",
            "tvlxu5rbcj76rfdmsw9xd3kjn79fhv6kpvl2hzv98637j4rdj1b1.tom.h",
            "kkxfwnm3upf0jv35jq4lx0dn0z3m9bh71gv84cdjlcp68w1qckt1.maru.h",
            "02wmqfu7v0kdq17fwv68hk646bdvhcr8ybk2ycy7ddzv21n5nb60.scruffy.h"
          ],
          "servers": [
            ["fc71:ec46:57a0:2bbc:537d:b680:3630:93e4",9001],
            ["fc8e:9a1c:27c3:281b:29b1:1a04:3701:c125",9001],
            ["fcad:0450:4a40:9778:14e2:e442:6678:3161",9001],
            ["fc2f:baa8:4a89:2db5:6789:aa75:07e6:4cb2",9001]
          ],
        rproxy: {
            bind: [ "::1", 5353 ]
        },
        minSignatures: 2
    }, null, '  '));
};

var usage = function()
{
    console.log("rdig <domain>.h       lookup a domain using default config");
    console.log("rdig --genconf        make a new config file with defaults for nic.h");
    console.log();
    console.log("example:");
    console.log("mkdir ~/.rainfly && rdig --genconf > ~/.rainfly/conf.json");
    console.log("rdig nic.h");
};

var main = module.exports.main = function() {
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
