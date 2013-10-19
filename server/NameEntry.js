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
    Serial.writeStrList(msg,[name,nextName,value]);
    Message.push32(msg, height);
    return Message.pop(msg, Message.size(msg));
};

var cannonical = module.exports.cannonical = function (name)
{
    return name.substring(0, name.lastIndexOf('/'));
};

var create = module.exports.create = function(fullName, nextFullName, value, firstSeen, height)
{
    var out = {};
    var data = {
        Sigs:{},
        Binary:new Buffer(0),
        Name:'',
        NextName:'',
        Value:{},
        Height:''
    };

    [
        'Name',
        'NextName',
        'FullName',
        'NextFullName',
        'Auth',
        'Height',
        'FirstSeen',
        'Value',
        'Sigs',
        'Binary'
    ].forEach(function(name) {
        out['get'+name] = function() { return data[name]; };
    });

    var makeDirty = function() {
        var buff = new Buffer(512);
        var msg = Message.wrap(buff);
        Message.reset(msg);
        var list = [data.Name,data.NextName,JSON.stringify(data.Value)];
console.log("new binary: " + JSON.stringifY(list));
        Serial.writeStrList(msg,list);
        Message.push32(msg, data.Height);
        var bin = Message.pop(msg, Message.size(msg));
        if (bin.toString('base64') !== data.Binary.toString('base64')) {
            data.Binary = bin;
            data.Sigs = {};
        }
    };

    out.setFirstSeen = function(fs) {
        if (data.FirstSeen === fs) { return false; }
        data.FirstSeen = fs;
        makeDirty();
        return true;
    };

    out.setFullName = function(fn) {
        if (data.FullName === fn) { return false; }
        data.FullName = fn;
        data.Name = cannonical(fn);
        var sha = Crypto.createHash('sha512');
        sha.update(data.Name);
        data.Height = (out.height || 0) & 0xffffff00;
        data.Height |= new Number('0x' + sha.digest('hex').substring(0,2));
        makeDirty();
        return true;
    };

    out.setHeight = function(height) {
        if (!((data.Height ^ height) & 0xffffff00)) { return false; }
        data.Height = (height & 0xffffff00) | (data.Height & 0xff);
        makeDirty();
        return true;
    };

    out.setNextFullName = function(nfn) {
        if (data.NextFullName === nfn) { return false; }
        data.NextFullName = nfn;
        data.NextName = cannonical(nfn);
        makeDirty();
        return true;
    };

    out.setValue = function(v) {
        var val = JSON.parse(JSON.stringify(v));
        var auth = val.auth;
        delete val.auth;
        if (out.Auth === auth && JSON.stringify(val) === JSON.stringify(data.Value)) {
            return false;
        }
        out.Auth = auth;
        data.Value = val;
        makeDirty();
        return true;
    };

    out.setFullName(fullName);
    out.setNextFullName(nextFullName);
    out.setValue(value);
    out.setFirstSeen(firstSeen);
    out.setHeight(height);
    return out;
};
