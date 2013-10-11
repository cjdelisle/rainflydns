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
var Gossiper = require('gossiper').Gossiper;
var BSearch = require("binary-search");
var NMCClient = require('./NMCClient');
var Base32 = require('../common/Base32');
var Crypto = require('../common/Crypto');
var Message = require('../common/Message');
var Serial = require('../common/Serial');
var Store = require('./Store');

var SLEEP_TIME = 60;

var signable = function (entry)
{
    var buff = new Buffer(512);
    var msg = Message.wrap(buff);
    Message.reset(msg);
    var value = JSON.parse(entry.valueStr);
    delete value.auth;
    value = JSON.stringify(value);
    Serial.writeStrList(msg, [entry.name, entry.nextName, value]);
    return Message.pop(msg, Message.size(msg));
};

var cannonicalize = function (name)
{
    return name.substring(0, name.lastIndexOf('/') + 1);
};

// -1 if B comes before A
// 1 if A comes before B
var compare = function(entryA,entryB)
{
    var a = entryA.name;
    var b = entryB.name;
    // We explicitly want to sort by first seen and not by length because
    // h/cjd and h/cjd/2 are equivilant. If squatters take over h/cjd then I'll just
    // move to h/cjd/2 or h/cjd/3 or h/cjd/abcdefg and so on.

    // First we sort by length and bytes prior to the final slash.
    var aLength = a.lastIndexOf('/');
    var bLength = b.lastIndexOf('/')
    if (aLength !== bLength) { return (aLength > bLength) ? -1 : 1; }
    for (var i = 0; i < aLength; i++) {
        if (a.charCodeAt(i) !== b.charCodeAt(i)) {
            return a.charCodeAt(i) > b.charCodeAt(i) ? -1 : 1;
        }
    }

    // Authorities should not be signing off on multiple domains which alias eachother but if
    // one does, it should not allow him to cease a working domain so oldest one wins.
    if (entryA.first_seen !== entryB.first_seen) {
        return (entryA.first_seen > entryB.first_seen) ? -1 : 1;
    }

    // ok so they were both created in the same block <_< check their length and compare bytes.
    if (a.length !== b.length) { return (a.length > b.length) ? -1 : 1; }
    for (var i = aLength; i < a.length; i++) {
        if (a.charCodeAt(i) !== b.charCodeAt(i)) {
            return a.charCodeAt(i) > b.charCodeAt(i) ? -1 : 1;
        }
    }

    // has to be the same entry, namecoin would not allow 2 with dupe names.
    return 0;
};

var ASSERT = function(x) {
    if (!x) { throw new Error("Assertion failure"); }
};

// for testing the correctness of the algorithm
var verifyList = function (nameList, entries)
{
    for (var i = 0; i < nameList.length; i++) {
        var last = (i === 0) ? nameList[nameList.length-1] : nameList[i-1];
        if (nameList[i].name === last.nextName
            && nameList[i].name === entries[i].name
            && nameList[i].valueStr === entries[i].valueStr)
        {
            if (i == 0 || compare(nameList[i-1], nameList[i]) === 1) {
                continue;
            }
        }
        for (var i = 0; i < entries.length; i++) {
            delete entries[i].auth;
            console.log(i + '  ' + JSON.stringify(entries[i]));
        }
        for (var i = 0; i < nameList.length; i++) {
            delete nameList[i].auth;
            console.log(i + '  ' + JSON.stringify(nameList[i]));
        }
        throw new Error();
    }
};

var makeNameEntry = function(namecoinName, nextName)
{
    return {
        name: namecoinName.name,
        value: namecoinName.value,
        valueStr: namecoinName.valueStr,
        nextName: nextName,
        first_seen: namecoinName.first_seen,
        sigs: {}
    };
};

var throws = function(f) {
    try { f(); } catch (e) { return true; } return false;
};

module.exports.create = function(keyPair,
                                 ident,
                                 sig,
                                 peerAddress,
                                 peerPort,
                                 peers,
                                 dbFileName,
                                 zone,
                                 authority)
{
    var node = new Gossiper(peerPort, peers, peerAddress);
    node.start();

    var nodeID = ident.toString('base64');
    var hotID = new Buffer(keyPair.signPk).toString('base64');

    var hotKeys = {};
    var hotIDs = {};

    // add our own hotkey.
    hotKeys[nodeID] = Buffer.concat([new Buffer(sig), new Buffer(keyPair.signPk)]);
    hotIDs[nodeID] = hotID;

    console.log("our auth: " + hotKeys[nodeID].toString('base64'));
    //console.log("our hotk: " + new Buffer(keyPair.signPk).toString('base64'));

    var hotKey = function(coldKey)
    {
        return hotKeys[new Buffer(coldKey).toString('base64')];
    };

    var lookup = function(name)
    {
        var idx = BSearch(nameList, { name:name }, compare);
        console.log("lookup [" + name + "] returned " + idx);
        if (idx < 0) { idx = (-idx) - 1; }
        if (idx >= nameList.length) { idx = nameList.length - 1; }

        // In case the authority signs off two equivilant domains, return the oldest one.
        while (idx > 0 && cannonicalize(nameList[idx-1].name) == cannonicalize(nameList[idx].name))
        {
            idx--;
        }

        if (typeof(nameList[idx].binEntry) !== 'object') {
            nameList[idx].binEntry = signable(nameList[idx]);
        }

        console.log("lookup result [" + nameList[idx].name + "] - [" + nameList[idx].nextName + "]");
        return nameList[idx];
    };

    var signName = function (entry, firstRun)
    {
        if (entry.sigs[hotID]) {
            if (firstRun) { node.setLocalState(entry.name, entry); }
            return;
        }
        console.log("Signing [" + entry.name + "] - [" + entry.nextName + "]");
        // While we're at it we can flush out the old keys.
        for (var id in entry.sigs) {
            if (typeof(hotKeys[id]) === 'undefined') { delete entry.sigs[id]; }
        }
        entry.binEntry = signable(entry);
        entry.sigs[hotID] = Crypto.sign(entry.binEntry, keyPair);
        if (firstRun) { node.setLocalState(entry.name, entry); }
    };

    var nameList = [];

    var syncNames = function(firstRun) {
      NMCClient.nameFilter('^' + zone + '/', function(error, names) {
        if (error) {
            console.log("got error scanning for names [" + error + "], trying again in ["
                + SLEEP_TIME + "] seconds");
            setTimeout(syncNames, SLEEP_TIME * 1000);
            return;
        }
        console.log("Scanning names:");

        // Reorder the names by our own metric
        names.sort(compare);

        for (var i = names.length - 1; i >= 0; i--) {
            // To introduce some churn for testing.
            //if (Math.floor(Math.random() * 5) === 3) { names.splice(i, 1); continue; }
            try {
                console.log("trying to verify name " + names[i].name);
                names[i].value = JSON.parse(names[i].value);
                names[i].valueStr = JSON.stringify(names[i].value);
                names[i].auth = new Buffer(names[i].value.auth, 'base64');

                if (typeof(names[i].value) === 'undefined') {

                } else if (names[i].value.length > 255) {

                } else if (names[i].name.length > 64) {

                } else if (i > 0
                    && cannonicalize(names[i-1].name) === cannonicalize(names[i])
                    && names[i-1].first_seen <= names[i].first_seen)
                {

                } else if (i < names.length-1
                    && cannonicalize(names[i+1].name) === cannonicalize(names[i])
                    && names[i+1].first_seen < names[i].first_seen)
                {

                } else if (!authority.isDomainAuthorized(names[i])) {

                } else {
                    continue;
                }
            } catch (e) {
                console.log(e.stack)
            }

            names.splice(i, 1);
        }

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
                      console.log("Trim   [" + nameList[ii].name + '] - [' + nameList[ii].nextName + "] from [" + ii + ']');
                      nameList.splice(ii, 1);
                  }
              }

              verifyList(nameList, names);
              clearInterval(interval);

              console.log("Scanning names complete");

              Store.store(dbFileName, nameList, function() {
                  console.log("sleep for [" + SLEEP_TIME + "] seconds")
                  setTimeout(syncNames, SLEEP_TIME * 1000);
              });
              return;
          }

          // Get the next name in the list.
          var nextName = names[i % names.length].name;

          // the next result from the stored list is *after* the next result from the new list.
          // this means the entry has been removed.
          while (typeof(current) !== 'undefined'
              && current.name !== entry.name
              && compare(current, entry) === 1)
          {
              console.log("Remove [" + current.name + '] - [' + current.nextName + "] from [" + currentIndex + ']');
              nameList.splice(currentIndex, 1);
              current = nameList[currentIndex];
          }

          // current entry will be set so advance x
          x++;

          // Reached the end of the list, append.
          if (typeof(current) === 'undefined') {
              console.log("Append [" + entry.name + '] - [' + nextName + "] in [" + currentIndex + ']');
              current = nameList[currentIndex] = makeNameEntry(entry, nextName);
              signName(current, firstRun);
              return;
          }

          if (current.name === entry.name) {

              if (current.valueStr !== entry.valueStr) {
                  console.log("Update [" + current.name + '] - [' + nextName + "] to [" + entry.valueStr + "]");
                  current.value = entry.value;
                  current.valueStr = entry.valueStr;
                  current.sigs = {};
              }

              if (current.nextName !== nextName) {
                  current.nextName = nextName;
                  current.sigs = {};
              }

              signName(current, firstRun);
              return;
          }

          // the new entry comes first, do an insert
          if (compare(entry, current) === 1) {
              console.log("Insert [" + entry.name + '] - [' + nextName + "] in [" + currentIndex + ']');
              nameList.splice(currentIndex, 0, makeNameEntry(entry, nextName));
              current = nameList[currentIndex];
              ASSERT(current.name === entry.name);
              signName(current, firstRun);
              return;
          } else {
              ASSERT(false);
          }

        });
      });
    };

    Store.load(dbFileName, function(err, nl) {
        if (err) {
            console.log("failed to load database [" + err.stack + "]");
        } else {
            nameList = nl;
        }
        syncNames(true);
    });

    return {
        hotKey: hotKey,
        lookup: lookup
    };
}
