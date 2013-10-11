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
var Nacl = require("js-nacl");

var sign = function(message, keyPair)
{
    if (typeof(message) === 'string') { message = Nacl.encode_utf8(message); }
    var longMsg = Nacl.crypto_sign(message, keyPair.signSk);
    var sig = longMsg.subarray(0, 64);

    //console.log("signing [\n" + new Buffer(sig).toString("base64") + "\n"
    //    + new Buffer(message).toString("base64") + "\n"
    //    + new Buffer(keyPair.signPk).toString("base64") + "]");
    
    return sig;
};

var isValid = function(message, sig, pubKey)
{
    //console.log("validating [\n" + new Buffer(sig).toString("base64") + "\n"
    //    + new Buffer(message).toString("base64") + "\n"
    //    + new Buffer(pubKey).toString("base64") + "]");

    if (typeof(message) === 'string') { message = Nacl.encode_utf8(message); }
    if (!Buffer.isBuffer(message)) { message = new Buffer(message); }
    if (!Buffer.isBuffer(sig)) { sig = new Buffer(sig); }
    if (!Buffer.isBuffer(pubKey)) { pubKey = new Buffer(pubKey); }
     
    var longMsg = Buffer.concat([new Buffer(sig), new Buffer(message)]);
    var openMsg = Nacl.crypto_sign_open(longMsg, pubKey);
    return openMsg !== null;
};

var keyPair = function()
{
    return Nacl.crypto_sign_keypair();
};

var memcmp = function(a,b,length)
{
    var out = 0;
    for (var i = 0; i < length; i++) {
        out |= a[i] ^ b[i];
    }
    return out !== 0;
};

var hexEncode = function(buff)
{
    return Nacl.to_hex(buff);
};

var numForAscii = [
    99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
    99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
    99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,99,99,99,99,99,99,
    99,10,11,12,13,14,15,99,99,99,99,99,99,99,99,99,
    99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
    99,10,11,12,13,14,15,99,99,99,99,99,99,99,99,99,
    99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
];

var hexDecode = function(str)
{
    if (str.length & 1) { throw new Error(); }
    var out = new Uint8Array((str.length/2));
    for (var i = 0,j=0; i < str.length;) {
      var high = numForAscii[str.charCodeAt(i++)];
      var low = numForAscii[str.charCodeAt(i++)];
      if (high > 15 || low > 15) { throw new Error(); }
      out[j++] = (high<<4) | low;
    }
    return out;
};

module.exports = {
    sign:sign,
    isValid:isValid,
    keyPair:keyPair,
    memcmp:memcmp,
    hexEncode:hexEncode,
    hexDecode:hexDecode,
    SIG_SIZE: 64,
    PUBLIC_KEY_SIZE: 32,
    PRIVATE_KEY_SIZE: 64,
};

/*
var m = Nacl.encode_utf8("fffffffffffffffffffffffffffffffffffff");

var sig = sign(m, keyPair);
console.log("sig: " + Nacl.to_hex(sig));
console.log("msg: " + Nacl.to_hex(m));
console.log("sec: " + Nacl.to_hex(keyPair.signSk));
console.log("pub: " + Nacl.to_hex(keyPair.signPk));
console.log("isValid: " + isValid(m, sig, keyPair.signPk));
*/
