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
var numForAscii = [
    99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
    99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
    99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,99,99,99,99,99,99,
    99,99,10,11,12,99,13,14,15,99,16,17,18,19,20,99,
    21,22,23,24,25,26,27,28,29,30,31,99,99,99,99,99,
    99,99,10,11,12,99,13,14,15,99,16,17,18,19,20,99,
    21,22,23,24,25,26,27,28,29,30,31,99,99,99,99,99,
];

decode = function(input)
{
throw new Error("base32 is not currently working");
    var output = new Uint8Array(input.length);
    var outIndex = 0;
    var nextByte = 0;
    var bits = 0;

    for (var inputIndex = 0; inputIndex < input.length; inputIndex++) {
        var o = input[inputIndex];
        if (o & 0x80) { throw new Error(); }
        var b = numForAscii[o];
        if (b > 31) { throw new Error("bad character " + input[inputIndex]); }

        nextByte |= (b << bits);
        bits += 5;

        if (bits >= 8) {
            output[outIndex++] = nextByte & 0xff;
            bits -= 8;
            nextByte >>= 8;
        }
    }

    if (bits >= 5 || nextByte) {
        throw new Error("bits is " + bits + " and nextByte is " + nextByte);
    }

    return output.subarray(0, outIndex);
};

var kChars = "0123456789bcdfghjklmnpqrstuvwxyz";

encode = function (input)
{
throw new Error("base32 is not corrently working");
    var output = '';
    var inIndex = 0;
    var work = 0;
    var bits = 0;

    while (inIndex < input.length) {
        work |= (input[inIndex++] << bits);
        bits += 8;

        while (bits >= 5) {
            output += kChars[work & 31];
            bits -= 5;
            work >>= 5;
        }
    }

    if (bits) {
        output += kChars[work & 31];
    }

    return output;
};

module.exports = {
    encode:encode,
    decode:decode
};
