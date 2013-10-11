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
var Fs = require('fs');
var crypto = require('crypto');
var Serial = require('../common/Serial');
var Message = require('../common/Message');

var serializeEntry = function (entry, msg)
{
    for (var key in entry.sigs) {
        Message.push(msg, entry.sigs[key]);
        Message.push(msg, new Buffer(key, 'base64'));
    }
    Message.push8(msg, Object.keys(entry.sigs).length);
    Serial.writeStrList(msg, [entry.name, entry.nextName, entry.valueStr]);
};

var deserializeEntry = function (msg)
{
    var entries = Serial.readStrList(msg);
    if (entries.length !== 3) { throw new Error("wrong entry count"); }
    var out = {
        name: entries[0],
        nextName: entries[1],
        valueStr: entries[2],
        value: JSON.parse(entries[2]),
    };
//console.log(JSON.stringify(out));
    var sigCount = Message.pop8(msg);
    out.sigs = {};
    for (var i = 0; i < sigCount; i++) {
        var key = new Buffer(Message.pop(msg, 32)).toString('base64');
        out.sigs[key] = Message.pop(msg, 64);
    }
    return out;
};

var hashEntry = function (entry, hash)
{
    hash.update(entry.name.length + ':' + entry.name
        + entry.nextName.length + ':' + entry.nextName
        + entry.value.length + ':' + entry.value);
    for (var key in entry.sigs) {
        hash.update(key);
        hash.update(entry.sigs[key]);
    }
};

var load = module.exports.load = function (fileName, callback)
{
    var expectedHashHex;

    var readData = function(msg, i, nameList, done, callback) {
        for (; i >= 0; i--) {
            try {
                nameList[i] = deserializeEntry(msg);
            } catch (e) { callback(e); return; }
        }

        var hash = crypto.createHash('sha512');
        for (var j = 0; j < nameList.length; j++) {
            hashEntry(nameList[j], hash);
        }
        if (expectedHashHex !== hash.digest('hex')) { callback(new Error('hash mismatch')); return; }
        callback(undefined, nameList);
    };

    Fs.open(fileName, "r", null, function(err, fd) {
        if (err) { callback(err); return; }
        var expectedHashAndLengths = new Buffer(8 + 64);
        Fs.read(fd, expectedHashAndLengths, 0, expectedHashAndLengths.length, null, function(err, bytesRead) {
            if (err) { callback(err); return; }
            var length = expectedHashAndLengths.readUInt32BE(64);
            var count = expectedHashAndLengths.readUInt32BE(68);
            expectedHashHex = expectedHashAndLengths.slice(0, 64).toString('hex');
            var array = new Array(count);

            if (length > (1<<24)) { callback(new Error("file is too big")); return; }
            console.log("File length is [" + length + "]");
            console.log("Entry count if [" + count + "]");
            if (count === 0) {
                callback(undefined, []); return;
            }
            var buff = new Buffer(length);

            var position = 0;
            var readMore = function() {
                Fs.read(fd, buff, position, buff.length, null, function(err, bytesRead) {
                    if (err) { callback(err); return; }
                    position += bytesRead;
                    if (position !== buff.length) {
                        if (bytesRead === -1) { callback(new Error("file too short")); return; }
                        try {
                            readMore();
                        } catch (err) { callback(err); return; }
                        return;
                    }
                    Fs.close(fd, function(err) {
                        if (err) { callback(err); return; }
                        console.log("Loaded [" + bytesRead + "] from disk.");
                        var msg = Message.wrap(buff);
                        readData(msg, count-1, array, 0, callback);
                    });
                });
            };
            try {
                readMore();
            } catch (err) {
                callback(err); return;
            }
        });
    });
};

var store = module.exports.store = function (fileName, nameList, callback)
{
    var buff = new Buffer(1<<17);
    var msg = Message.wrap(buff);
    var totalWritten = 0;
    Message.reset(msg);

    var writeData = function(fd, i) {
        for (; i < nameList.length; i++) {
            serializeEntry(nameList[i], msg);
        }

        Message.push32(msg, nameList.length);
        Message.push32(msg, Message.size(msg) - 4);
        var hash = crypto.createHash('sha512');
        for (var j = 0; j < nameList.length; j++) {
            hashEntry(nameList[j], hash);
        }
        Message.push(msg, new Buffer(hash.digest('hex'), 'hex'));

        Fs.write(fd, msg.buff, msg.offset, Message.size(msg), null, function(err, written, buffer) {
            if (err) { callback(err); return; }
            totalWritten += written;
            Fs.close(fd, function(err) {
                if (err) { callback(err); return; }
                console.log("Flushed [" + totalWritten + "] bytes to disk.");
                Fs.rename(fileName + '.tmp', fileName, function(err) {
                    if (err) { callback(err); return; }
                    callback();
                });
            });
        });
    };

    Fs.open(fileName + '.tmp', "w", null, function(err, fd) {
        if (err) { callback(err); return; }
        writeData(fd, 0);
    });
};
