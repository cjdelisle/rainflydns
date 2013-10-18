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
var Crypto = require('crypto');
var Message = require('../common/Message');
var Serial = require('../common/Serial');

var signable = function (name, nextName, value, height)
{
    var buff = new Buffer(512);
    var msg = Message.wrap(buff);
    Message.reset(msg);
console.log(name + '  ' + nextName + '  ' + value);
    Serial.writeStrList(msg,[name,nextName,value]);
    Message.push32(msg, height);
    return Message.pop(msg, Message.size(msg));
};

var cannonical = module.exports.cannonical = function (name)
{
    return name.substring(0, name.lastIndexOf('/') + 1);
};

var create = module.exports.create = function(fullName, nextFullName, value, firstSeen, height)
{
    var out = {};
    var value = {
        Sigs:{},
        Binary:new Buffer(0)
    };

    [
        'Name',
        'NextName',
        'FullName',
        'NextFullName',
        'Auth',
        'CurrentHeight',
        'FirstSeen',
        'Value',
        'Sigs',
        'Binary'
    ].forEach(function(name) {
        out['get'+name] = function() { return value[name]; };
    });

    var makeDirty = function() {
        var bin = signable(value.Name, value.NextName, JSON.stringify(value.Value), value.Height);
        if (bin.toString('base64') !== value.Binary.toString('base64')) {
            value.Binary = bin;
            value.Sigs = {};
        }
    };

    out.setFirstSeen = function(fs) {
        if (value.FirstSeen === fs) { return; }
        value.FirstSeen = fs;
        makeDirty();
    };
    out.setFullName = function(fn) {
        value.FullName = fn;
        value.Name = cannonical(fn);

        var sha = Crypto.createHash('sha512');
        sha.update(value.Name);
        value.CurrentHeight = (out.height || 0) & 0xffffff00;
        value.CurrentHeight |= new Number('0x' + sha.digest('hex').substring(0,2));
        makeDirty();
    };
    out.setCurrentHeight = function(height) {
        if ((value.Height ^ height) & 0xffffff00) {
            value.Height = (height & 0xffffff00) | (value.Height & 0xff);
            makeDirty();
        }
    };
    out.setNextFullName = function(nfn) {
        value.NextFullName = nfn;
        value.NextName = cannonical(nfn);
        makeDirty();
    };
    out.setValue = function(v) {
        out.Auth = v.auth;
        value.Value = JSON.parse(JSON.stringify(v));
        delete value.Value.auth;
        makeDirty();
    };

    out.setFullName(fullName);
    out.setNextFullName(nextFullName);
    out.setValue(value);
    out.setFirstSeen(firstSeen);
    out.setCurrentHeight(height);
    return out;
};
