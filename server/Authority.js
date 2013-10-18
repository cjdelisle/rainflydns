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
var NMCClient = require('./NMCClient');
var Crypto = require('../common/Crypto');

var isDomainAuthorized = function(keys, nameEntry)
{
    var firstSeen = nameEntry.first_seen;
    var candidate = -1;
    for (height in keys) {
        // without using >= the authority can't sign himself.
        if (firstSeen >= height && height > candidate) {
            candidate = height;
        }
    }
    if (candidate === -1) {
        console.log("Failed to validate domain entry, no authority found");
        return false;
    }
    var fsb = new Buffer(4);
    fsb.writeUInt32BE(nameEntry.first_seen,0);
    var toVerify = Buffer.concat([fsb, new Buffer(nameEntry.name, 'utf8')]);
    return Crypto.isValid(toVerify, nameEntry.auth, keys[candidate]);
};

var init = module.exports.init = function(authority, callback)
{
    // As a matter of requirement, an authority must not have any crap after the last slash.
    // so for example nic.h must equal h/nic/ and can not contain anything after the last /
    var authorityName = authority.split('.').reverse().join('/') + '/';
    console.log("Looking up history for name authority [" + authorityName + "]");
    NMCClient.nameHistory(authorityName, function(err, history) {
        if (err) {
            console.log("This might mean your namecoin instance is not synced yet.");
            throw err;
        }
        var keys = {};
        for (var i = 0; i < history.length; i++) {
            try {
                var entry = history[i];
                var v = JSON.parse(entry.value);
                var height = JSON.parse(entry.block_height);
                var key = new Buffer(v.signingKey, 'base64');
                keys[""+height] = key;
            } catch (e) {
                console.log("Failed to parse authority entry [" +
                    JSON.stingify(history[i], null, '  ') + "]\nerror [" + e.stack + "]");
            }
        }
        if (Object.keys(keys).length === 0) {
            throw new Error("Failed to get keys for authority [" + authority + "]");
        }
        callback({
            isDomainAuthorized: function(name) { return isDomainAuthorized(keys, name); }
        });
    });
};
