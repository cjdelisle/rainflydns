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
var Crypto = require('../common/Crypto');

var newAuthority = function ()
{
    var keyPair = Crypto.keyPair();
    var pubKey = new Buffer(keyPair.signPk).toString('base64')
    var out = {
      __COMMENT: "This is the authority configuration file.",
      privateKey: new Buffer(keyPair.signSk).toString('base64'),
      publicKey: pubKey,
      __COMMENT2: "to register this authority in the nmc chain, use:",
      __COMMENT3: ("./namecoind name_update <name of authority> '" + '{"signingKey":"'
                + pubKey + '"}' + "'")
    };
    console.log(JSON.stringify(out, null, '  '));
};

var signDomain = function (name)
{
    if (name.indexOf('.') !== -1) {
        throw new Error("domain must be in the form h/abc/xxyz, not abc.h");
    }
    process.stdin.resume();
    var dat = '';
    process.stdin.on('data', function(chunk) { dat += chunk; });
    process.stdin.on('end', function() {
        var json = JSON.parse(dat);
        var keyPair = {
            signSk:new Buffer(json.privateKey, 'base64'),
            signPk:new Buffer(json.publicKey, 'base64'),
        };

        NMCClient.nameHistory(name, function(err, history) {
            if (err) {
                console.log("This might mean your namecoin instance is down or not synced yet.");
                throw err;
            }
            if (history.length < 1) {
                console.log("name [" + name + "] not registered");
                return;
            }
            var firstSeen = Infinity;
            for (var i = 0; i < name.length; i++) {
                if (firstSeen > history[i].first_seen) {
                    firstSeen = history[i].first_seen;
                }
            }
            console.log(name + " first seen: " + firstSeen + "\n");

            var fsb = new Buffer(4);
            fsb.writeUint32BE(firstSeen);
            var toVerify = Buffer.concat([fsb, new Buffer(nameEntry.name, 'utf8')]);
            var sig = Crypto.sign(name, keyPair);
            console.log('"auth":"' + new Buffer(sig).toString('base64') + '"');
        });
    });
};

var usage = function(app)
{
    console.log("auth --new              create a new TLD authority");
    console.log("auth --sign <domain>    sign a domain name, domain must be in form h/xyz/");
    console.log("                        you cannot use form xyz.h");
};

var main = module.exports.main = function()
{
  for (var i = 0; i < process.argv.length; i++) {

    if (process.argv[i] === '--sign' && i < process.argv.length-1) {
      return signDomain(process.argv[i+1]);
    }

    if (process.argv[i] === '--new') {
      return newAuthority();
    }

  }

  usage();
};
