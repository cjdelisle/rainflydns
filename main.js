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
var Crypto = require('./common/Crypto');
var Base32 = require('./common/Base32');
var Gossiper = require('./server/Gossiper');
var Authority = require('./server/Authority');
var RequestHandler = require('./server/RequestHandler');

var coldConf = function(name)
{
  if (!(/[a-z0-9-]+/.test(name))) {
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
      ident: new Buffer(coldKeys.signPk).toString('base64'),
      signature: new Buffer(sig).toString('base64'),
      name: json.name,
      peerAddress: "::",
      peerPort: 9000,
      rpcAddress: "::",
      rpcPort: 9001,
      dbFile: 'names.db',
      zone: 'h',
      authority: 'nic.h',
      peers: [],
    };
    console.log(JSON.stringify(out, null, '  '));
  });
};

// 01ffffff0100705553dac29e0a18f6fef243c9a15817a15707395281872b8d8c75807c5522
//           00705553dac29e0a18f6fef243c9a15817a15707395281872b8d8c75807c5522

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
    var sig = new Buffer(json.signature, 'base64');
    var ident = new Buffer(json.ident, 'base64');

console.log("node identity: " + ident.toString('hex'));

    Authority.init(json.authority, function(authority) {
        var gossiper = Gossiper.create(hotKeys,
                                       ident,
                                       sig,
                                       json.peerAddress,
                                       json.peerPort,
                                       json.peers,
                                       json.dbFile,
                                       json.zone,
                                       authority);
        RequestHandler.init(json.rpcAddress, json.rpcPort, gossiper);
    });
  });
};

var main = function()
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
main();
