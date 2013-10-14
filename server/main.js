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
var Base32 = require('../common/Base32');
var Gossiper = require('./Gossiper');
var Authority = require('./Authority');
var RequestHandler = require('./RequestHandler');

var coldConf = function(name)
{
  name = name.replace(/.h$/,'');
  if (!(/^[a-z0-9-]+$/.test(name))) {
      throw new Error("invalid characters in " + name);
  }
  var keyPair = Crypto.keyPair();
  var out = {
    __COMMENT: "This is the COLD configuration file which should remain offline at all times.",
    privateKey: new Buffer(keyPair.signSk).toString('base64'),
    publicKey: new Buffer(keyPair.signPk).toString('base64'),
    identity: Base32.encode(keyPair.signPk) + '.' + name + '.h',
    name: 'h/' + name,
  };
  console.log(JSON.stringify(out, null, '  '));
};

var hotConf = function()
{
  process.stdin.resume();
  var dat = '';
  process.stdin.on('data', function(chunk) { dat += chunk; });
  process.stdin.on('end', function() {
    var json = JSON.parse(dat);
    var keyPair = Crypto.keyPair();
    var coldKeys = {
        signSk: new Buffer(json.privateKey, 'base64'),
        signPk: new Buffer(json.publicKey, 'base64'),
    };
    var sig = Crypto.sign(keyPair.signPk, coldKeys);
    var out = {
      __COMMENT: "This is the hot configuration file which is installed on the server.",
      privateKey: new Buffer(keyPair.signSk).toString('base64'),
      publicKey: new Buffer(keyPair.signPk).toString('base64'),
      identity: json.identity,
      auth: new Buffer(sig).toString('base64'),
      name: json.name,
      address: "::",
      port: 9001,
//      dbFile: 'names.db',
      zone: 'h',
      authority: 'nic.h',
      peers: {
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
      },
    };
    console.log(JSON.stringify(out, null, '  '));
  });
};

var start = function()
{
  process.stdin.resume();
  var dat = '';
  process.stdin.on('data', function(chunk) { dat += chunk; });
  process.stdin.on('end', function() {
    var json = JSON.parse(dat);
    var hotKeys = {
        signSk: new Buffer(json.privateKey, 'base64'),
        signPk: new Buffer(json.publicKey, 'base64'),
    };
    var sig = new Buffer(json.auth, 'base64');
    var ident = Base32.decode(json.identity.replace(/\..*$/, ''));

    console.log("Node Identity: " + json.identity);

    Authority.init(json.authority, function(authority) {
        var gossiper = Gossiper.create(hotKeys,
                                       ident,
                                       sig,
                                       json.dbFile,
                                       json.peers,
                                       json.zone,
                                       authority);

        RequestHandler.init(json.address, json.port, gossiper);
    });
  });
};

var usage = function()
{
    console.log("rainserv --coldconf <servername>    Create a COLD configuration for this server");
    console.log("                                    this configuration must be guarded closely");
    console.log("                                    and if it is lost or stolen, there is no");
    console.log("                                    recource, it should not be on a server.");
    console.log();
    console.log("rainserv --hotconf < cold.conf      Create a HOT configuration for this server");
    console.log("                                    this configuration can be replaced if it is");
    console.log("                                    lost or compromized and it must be on the");
    console.log("                                    live server.");
    console.log();
    console.log("rainserv --start < hot.conf         Start up the server and begin serving names");
};

var main = module.exports.main = function()
{
  for (var i = 0; i < process.argv.length; i++) {

    if (process.argv[i] === '--coldconf' && i < process.argv.length-1) {
      return coldConf(process.argv[i+1]);
    }

    if (process.argv[i] === '--hotconf') {
      return hotConf();
    }

    if (process.argv[i] === '--start') {
      return start();
    }
  }

  usage();
}
