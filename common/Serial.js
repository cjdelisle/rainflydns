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
var Message = require('./Message');

var writeStrList = module.exports.writeStrList = function(msg, stringList)
{
    if (stringList.length > 255) { throw new Error("too many"); }
    var bytesList = [];
    var totalLength = 0;
    for (var i = 0; i < stringList.length; i++) {
        bytesList[i] = new Buffer(stringList[i], 'utf8');
        if (bytesList[i].length > 255) { throw new Error("too big"); }
        totalLength += bytesList[i].length + 1;
    }
    for (var i = totalLength + 1; i % 8; i++) {
        Message.push8(msg, 0);
    }
    for (var i = bytesList.length - 1; i >= 0; i--) {
        Message.push(msg, bytesList[i]);
        Message.push8(msg, bytesList[i].length);
    }
    Message.push8(msg, bytesList.length);
};

var readStrList = module.exports.readStrList = function(msg)
{
    var count = Message.pop8(msg);
    var out = new Array(count);
    var totalLen = 1;
    for (var i = 0; i < count; i++) {
        var len = Message.pop8(msg);
        out[i] = new Buffer(Message.pop(msg, len)).toString('utf8');
        totalLen += len + 1;
    }

    if ((totalLen / 8) * 8) {
        var zero = Message.pop(msg, ((256 - totalLen) & 7) );
        for (var i = 0; i < zero.length; i++) {
            if (zero[i]) { throw new Error("invalid crap in padded string"); }
        }
    }
    return out;
};
