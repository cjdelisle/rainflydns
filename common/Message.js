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
module.exports.wrap = function(buff)
{
    return {
        buff:buff,
        offset:0
    };
};

var shift = module.exports.shift = function(msg, len)
{
    if (len < 0 && (msg.offset - len) > msg.buff.length) { throw new Error(); }
    if ((msg.offset - len) < 0) {
        len -= msg.offset;
        shift(msg, msg.offset);
        var bufferLength = msg.buff.length;
        msg.buff = Buffer.concat([new Buffer(bufferLength), msg.buff]);
        shift(msg, len-bufferLength);
        return;
    }
    msg.offset -= len;
};

module.exports.size = function(msg)
{
    return msg.buff.length - msg.offset;
}

module.exports.pop = function(msg, len)
{
    shift(msg, -len);
    var out = new Uint8Array(len);
    for (var i = 0, j = msg.offset-len; i < len;) {
        out[i++] = msg.buff[j++];
    }
    return out;
};

module.exports.push = function(msg, bytes)
{
    shift(msg, bytes.length);
    for (var i = msg.offset, j = 0; j < bytes.length;) {
        msg.buff[i++] = bytes[j++];
    }
};

module.exports.reset = function(msg)
{
    msg.offset = msg.buff.length;
}

module.exports.pop8 = function(msg)
{
    var out = msg.buff.readUInt8(msg.offset);
    shift(msg, -1);
    return out;
};

module.exports.pop16 = function(msg)
{
    var out = msg.buff.readUInt16BE(msg.offset);
    shift(msg, -2);
    return out;
};

module.exports.pop32 = function(msg)
{
    var out = msg.buff.readUInt32BE(msg.offset);
    shift(msg, -4);
    return out;
};


module.exports.push8 = function(msg, num)
{
    shift(msg, 1);
    msg.buff.writeUInt8(num, msg.offset);
};

module.exports.push16 = function(msg, num)
{
    shift(msg, 2);
    msg.buff.writeUInt16BE(num, msg.offset);
};

module.exports.push32 = function(msg, num)
{
    shift(msg, 4);
    msg.buff.writeUInt32BE(num, msg.offset);
};
