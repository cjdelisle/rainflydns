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

var dotBitLookup = function (name, keys, minSigs, target)
{
    var hotKeys = {};
    for (var i = 0; i < keys.length; i++) {
        hotKeys[""+i] = keys[i];
    }
    Messenger.lookup(name, hotKeys, target, function (err, entry) {
        if (err) { throw err; }
        if (Object.keys(entry.sigs).length < minSigs) {
            throw new Error("not enough signatures: need [" + minSigs
                + "] have [" + validSigs + "] total sigs: ["
                + sigs.length + "]");
        }
        console.log(JSON.stringify(entry.entry));
    });
};

var doKeysLookup = function(keys, target, minSigs, callback)
{
    Messenger.lookupHotKeys(keys, target, function (err, hotKeys) {
        if (err) { callback(err); return; }
        if (Object.keys(hotKeys).length < minSigs) {
            callback(new Error("not enough keys to satisfy minSignatures")); return;
        }
        var keys = [];
        for (coldKey in hotKeys) { keys.push(hotKeys[coldKey].slice(64)); }
        callback(undefined, keys);
    });
};

var doLookup = function(name)
{
    Fs.readFile(HOME + "/.rdig/conf.json", function(err, json) {
        if (err) { throw err; }
        json = JSON.parse(json);
        var keys = [];
        for (var i = 0; i < json.keys.length; i++) {
            keys[i] = Base32.decode(json.keys[i].replace(/\..*$/, ''));
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
                dotBitLookup('h/' + name.replace(/.h$/, '') + '/', keys, json.minSignatures, target);
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
            "7kuc3jcyql3cm8lx5zdj8vc0tkz8679kyx83utbm1ub5bxpf4mf1.mittens.h",
            "r4fm7r9315x9ytm27n8zmbj1fx9gbpmyssrwmstb4v30zk6gn560.fluffy.h"
        ],
        servers: [
            [ "127.0.0.1", 9001 ]
        ],
        minSignatures: 2
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
