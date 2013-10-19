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
var Crypto = require('crypto');
var BSearch = require("binary-search");
var NMCClient = require('./NMCClient');
var Base32 = require('../common/Base32');
var NaCl = require('../common/Crypto');
var Message = require('../common/Message');
var Serial = require('../common/Serial');
var Messenger = require('../common/Messenger');
var Store = require('./Store');
var NameEntry = require('./NameEntry');

var SLEEP_TIME = 60;


// 1 if B comes before A
// -1 if A comes before B
var sortCompare = function(entryA,entryB)
{
    var a = entryA.name;
    var b = entryB.name;
    // We explicitly want to sort by first seen and not by length because
    // h/cjd and h/cjd/2 are equivilant. If squatters take over h/cjd then I'll just
    // move to h/cjd/2 or h/cjd/3 or h/cjd/abcdefg and so on.

    // First we sort by length and bytes prior to the final slash.
    var aLength = a.lastIndexOf('/');
    var bLength = b.lastIndexOf('/')
    if (aLength !== bLength) { return (aLength > bLength) ? 1 : -1; }
    for (var i = 0; i < aLength; i++) {
        if (a.charCodeAt(i) !== b.charCodeAt(i)) {
            return a.charCodeAt(i) > b.charCodeAt(i) ? 1 : -1;
        }
    }

    if (a.length !== b.length) { return (a.length > b.length) ? 1 : -1; }
    for (var i = aLength; i < a.length; i++) {
        if (a.charCodeAt(i) !== b.charCodeAt(i)) {
            return a.charCodeAt(i) > b.charCodeAt(i) ? 1 : -1;
        }
    }

    // has to be the same entry, namecoin would not allow 2 with dupe names.
    return 0;
};

var compare = function(a,b)
{
    if (a.length !== b.length) { return (a.length > b.length) ? 1 : -1; }
    for (var i = 0; i < a.length; i++) {
        if (a.charCodeAt(i) !== b.charCodeAt(i)) {
            return a.charCodeAt(i) > b.charCodeAt(i) ? 1 : -1;
        }
    }
    return 0;
};

var ASSERT = function(x) {
    if (!x) { throw new Error("Assertion failure"); }
};

var doLookup = function (nameList, name)
{
    var entry = nameList[nameList.length-1];
    for (var i = 0; i < nameList.length; i++) {
        var comp = compare(nameList[i].getName(), name);
        switch (compare(nameList[i].getName(), name)) {
            case 1: return entry;
            case 0: return nameList[i];
            default: entry = nameList[i];
        }
    }
    return entry;
/*
    var idx = BSearch(nameList, { name:name }, compare);
    //console.log("lookup [" + name + "] returned " + idx);
    if (idx < 0) { idx = (-idx) - 2; }
    if (idx < 0) { idx = nameList.length - 1; }

    //console.log("lookup result [" + nameList[idx].name + "] - [" + nameList[idx].nextName + "]");
    return nameList[idx];
*/
};

// for testing the correctness of the algorithm
var verifyList = function (nameList, entries)
{
    for (var i = 0; i < nameList.length; i++) {
        var last = (i === 0) ? nameList[nameList.length-1] : nameList[i-1];
        var error;
        var num;
        if (nameList[i].getFullName() !== last.getNextFullName()) {
            error = "name != last.nextName";
        } else if (nameList[i].getFullName() !== entries[i].name) {
            error = "nameList[i].name !== entries[i].name";
        } else if (i != 0 && compare(nameList[i-1].getName(), nameList[i].getName()) !== -1) {
            error = "compare(nameList[i-1], nameList[i]) !== -1";
        } else if ((num = doLookup(nameList, nameList[i].getName())) !== nameList[i]) {
            error = "lookup(" + nameList[i].getName() + ") != " + nameList[i];
        } else {
            continue;
        }
        for (var j = 0; j < entries.length; j++) {
            delete entries[j].auth;
            delete entries[j].sigs;
            delete entries[j].binEntry;
            console.log(j + '  ' + JSON.stringify(entries[j]));
        }
        for (var j = 0; j < nameList.length; j++) {
            console.log(j + '  ' + JSON.stringify({
                name: nameList[j].getFullName(),
                nextName: nameList[j].getNextFullName(),
                value: nameList[j].getValue(),
            }));
        }
        throw new Error("Problem with name number [" + i + "] [" + error + "]");
    }
};

var filterNames = function(names, authority) {
    for (var i = names.length - 1; i >= 0; i--) {
        // To introduce some churn for testing.
        //if (Math.floor(Math.random() * 5) === 3) { names.splice(i, 1); continue; }
        try {
            var error = '';
            names[i].value = JSON.parse(names[i].value);
            names[i].valueStr = JSON.stringify(names[i].value);
            names[i].auth = new Buffer(names[i].value.auth, 'base64');

            if (typeof(names[i].value) === 'undefined') {
                error = 'value indefined';

            } else if (names[i].value.length > 255) {
                error = 'value too long';

            } else if (names[i].name.length > 64) {
                error = 'name too long';

            } else if (i > 0
                && NameEntry.cannonical(names[i-1].name) === NameEntry.cannonical(names[i].name)
                && names[i-1].first_seen <= names[i].first_seen)
            {
                error = 'dupe of existing name ' + names[i-1].name;

            } else if (i < names.length-1
                && NameEntry.cannonical(names[i+1].name) === NameEntry.cannonical(names[i].name)
                && names[i+1].first_seen < names[i].first_seen)
            {
                error = 'dupe of existing name ' + names[i+1].name;

            } else if (!authority.isDomainAuthorized(names[i])) {
                error = 'unauthorized';

            } else {
                console.log("name [" + names[i].name + "] is valid");
                continue;
            }
            console.log("name [" + names[i].name + "] is invalid [" + error + "]");
        } catch (e) {
            console.log("name [" + names[i].name + "] is invalid [" + e.stack + "]");
        }

        names.splice(i, 1);
    }
}

module.exports.create = function(keyPair,
                                 ident,
                                 sig,
                                 dbFileName,
                                 peers,
                                 zone,
                                 authority)
{
    var nodeID = ident.toString('base64');
    var hotID = new Buffer(keyPair.signPk).toString('base64');

    var hotKeys = {};
    var hotIDs = {};

    // add our own hotkey.
    hotKeys[nodeID] = Buffer.concat([new Buffer(sig), new Buffer(keyPair.signPk)]);
    hotIDs[nodeID] = hotID;

    var hotKey = function(coldKey)
    {
        return hotKeys[new Buffer(coldKey).toString('base64')];
    };

    var lookup = function(name)
    {
        return doLookup(nameList, name);
    };

    var signName = function (entry, firstRun, height)
    {
        var sigs = entry.getSigs();
        if (sigs[hotID]) { return; }
        console.log("Signing [" + entry.getName() + "] - [" + entry.getNextName() + "] [" + entry.getHeight() + "]");
        // While we're at it we can flush out the old keys.
        for (var id in sigs) {
            if (typeof(hotKeys[id]) === 'undefined') { delete sigs[id]; }
        }
        sigs[hotID] = NaCl.sign(entry.getBinary(), keyPair);
    };

    var nameList = [];


    var permKeys = [];
    for (var i = 0; i < peers.keys.length; i++) {
        permKeys[i] = Base32.decode(peers.keys[i].replace(/\..*$/, ''));
    }
    var messenger = Messenger.init();
    var servers = peers.servers;
    var checkHotKeys = function () {
        setTimeout(checkHotKeys, Math.floor(Math.random()*120000));
        var server = servers[Math.floor(Math.random() * servers.length)];
        console.log('checking hot keys with [' + server + ']');
        messenger.lookupHotKeys(permKeys, server, function(err, keyMap) {
            if (err) { console.log('checking hot keys with [' + server + '] caused [' + err + ']'); return; }
            for (var ident in keyMap) {
                if (typeof(hotKeys[ident]) === 'undefined') {
                    hotKeys[ident] = keyMap[ident];
                } else if (new Buffer(keyMap[ident]).toString('base64') !== new Buffer(hotKeys[ident]).toString('base64')) {
                    if (ident === nodeID) {
                        console.log("got different key for ourselves, discarding");
                        continue;
                    }
                    for (var i = 0; i < nameList.length; i++) {
                        if (typeof(nameList[i].getSigs()[ident]) !== 'undefined') { delete nameList[i].getSigs()[ident]; }
                    }
                    hotKeys[ident] = keyMap[ident];
                }
            }
        });
    };


    var checkName = function () {
        setTimeout(checkName, Math.random()*1000);
        if (!servers.length || !nameList.length) { return; }
        var server = servers[Math.floor(Math.random() * servers.length)];
        var begin = Math.floor(Math.random() * nameList.length);
        var name;
        var i = begin;
        var best = 0;
        do {
            var len = Object.keys(nameList[i].getSigs()).length;
            if (len < best) {
                name = nameList[i];
                break;
            }
            best = len;
            i = (i + 1) % nameList.length;
        } while (i !== begin);
        if (typeof(name) === 'undefined') {
            if (best > 1 && Math.random() > 0.0016) { return; }
            name = nameList[begin]
        }

        console.log("checking [" + name.getName() + '] with [' + server + ']');
        messenger.lookup(name.getName(), hotKeys, server, function(err, data) {
            if (err) {
                console.log("checking [" + name.getName() + '] with [' + server
                            + '] error[' + err + "]");
                return;
            }
            var entry = [name.getName(), name.getNextName(), JSON.stringify(name.getValue())];
            if (JSON.stringify(data.entry) !== JSON.stringify(entry)) {
                console.log(JSON.stringify(data.entry) + ' !== ' + JSON.stringify(entry));
                return;
            }
            if (data.blockHeight !== name.getHeight()) {
                return;
            }
            for (ident in data.validSigsByIdent) {
                var hotKeyStr = hotKeys[ident].slice(NaCl.SIG_SIZE).toString('base64');
                if (typeof(name.sigs[hotKeyStr]) === 'undefined') {
                    name.getSigs()[hotKeyStr] = data.validSigsByIdent[ident];
                }
            }
        });
    };

    var getNames = function(callback) {
        NMCClient.nameFilter('^' + zone + '/', function(error, names) {
            if (error) { callback(error); return; }
            NMCClient.getBlockCount(function(error, height) {
                if (error) { callback(error); return; }
                callback(undefined, names, height);
            });
        });
    };

    var syncNames = function(firstRun) {
        getNames(function(error, names, height) {
            if (error) {
                console.log("got error scanning for names [" + error + "], trying again in ["
                    + SLEEP_TIME + "] seconds");
                setTimeout(syncNames, SLEEP_TIME * 1000);
                return;
            }
            console.log("Scanning names:");

            // Reorder the names by our own metric
            names.sort(sortCompare);

            filterNames(names, authority);

            var i = 0;
            var x = 0;
            var interval = setInterval(function() {
              var entry = names[i++];
              var currentIndex = x;
              var current = nameList[currentIndex];

              if (!entry) {

                  // Trim the stored list down to size
                  if (names.length < nameList.length) {
                      for (var ii = nameList.length-1; ii >= names.length; ii--) {
                          console.log("Trim   [" + nameList[ii].getName() + '] - ['
                                      + nameList[ii].getNextName() + "] from [" + ii + ']');
                          nameList.splice(ii, 1);
                      }
                  }

                  verifyList(nameList, names);
                  clearInterval(interval);

                  if (firstRun) {
                      checkName();
                      checkHotKeys();
                  }

                  console.log("Scanning names complete");

                  if (typeof(dbFileName) !== 'undefined') {
                      Store.store(dbFileName, nameList, function() {
                          console.log("sleep for [" + SLEEP_TIME + "] seconds")
                          setTimeout(syncNames, SLEEP_TIME * 1000);
                      });
                  } else {
                      console.log("sleep for [" + SLEEP_TIME + "] seconds")
                      setTimeout(syncNames, SLEEP_TIME * 1000);
                  }
                  return;
              }

              // Get the next name in the list.
              var nextName = names[i % names.length].name;

              // the next result from the stored list is *after* the next result from the new list.
              // this means the entry has been removed.
              while (typeof(current) !== 'undefined'
                  && current.getFullName() !== entry.name
                  && compare(current.getName(), NameEntry.cannonical(entry.name)) === -1)
              {
                  console.log("Remove [" + current.getName() + '] - [' + current.nextName + "] from [" + currentIndex + ']');
                  nameList.splice(currentIndex, 1);
                  current = nameList[currentIndex];
              }

              // current entry will be set so advance x
              x++;

              // Reached the end of the list, append.
              if (typeof(current) === 'undefined') {
                  console.log("Append [" + entry.name + '] - [' + nextName + "] in [" + currentIndex + ']');
                  current = nameList[currentIndex] =
                      NameEntry.create(entry.name, nextName, entry.value, entry.first_seen, height);
                  signName(current, firstRun, height);
                  return;
              }

              current.setHeight(height);

              if (current.getName() === NameEntry.cannonical(entry.name)) {

                  if (JSON.stringify(current.getValue()) !== entry.valueStr) {
                      console.log("Update [" + current.getName() + '] - [' + nextName + "] to [" + entry.valueStr + "]");
                      current.setValue(entry.value);
                  }

                  if (current.getNextFullName() !== nextName) {
                      current.setNextFullName(nextName);
                  }

                  signName(current, firstRun, height);
                  return;
              }

              // the new entry comes first, do an insert
              if (compare(NameEntry.cannonical(entry.name), current.getName()) === -1) {
                  console.log("Insert [" + entry.name + '] - [' + nextName + "] in [" + currentIndex + ']');
                  var newEntry = NameEntry.create(entry.name, nextName, entry.value, entry.first_seen, height);
                  nameList.splice(currentIndex, 0, newEntry);
                  current = nameList[currentIndex];
                  ASSERT(current.getFullName() === entry.name);
                  signName(current, firstRun, height);
                  return;
              } else {
                  ASSERT(false);
              }

            });
        });
    };

    if (typeof(dbFileName) !== 'undefined') {
        Store.load(dbFileName, function(err, nl) {
            if (err) {
                console.log("failed to load database [" + err.stack + "]");
            } else {
                nameList = nl;
            }

            syncNames(true);
        });
    } else {
        syncNames(true);
    }

    return {
        hotKey: hotKey,
        lookup: lookup
    };
}
