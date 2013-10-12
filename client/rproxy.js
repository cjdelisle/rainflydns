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
var UDP = require('dgram');
var Message = require('../common/Message');
var Messenger = require('../common/Messenger');
var Base32 = require('../common/Base32');

var Record = {
    TXT:16,
    AAAA:28
};

var printHex = function(msg)
{
    var buff = msg.buff.slice(msg.offset, msg.buff.length);
    return buff.toString('hex');
};


var parseFlags = function(flags)
{
    var out = {};
    out.rcode = flags & ((1<<4)-1);
    out.cd = (flags >> 4) & 1;

    // The server believes the data is authentic
    out.authenticated = (flags >>= 1) & 1;

    out.z = (flags >>= 1) & 1;

    out.recursionAvailable = (flags >>= 1) & 1;
    out.recursionDesired = (flags >>= 1) & 1;

    out.truncated = (flags >>= 1) & 1;

    out.authoritative = (flags >>= 1) & 1;

    out.opCode = (flags >>= 1) & ((1<<4)-1);

    out.isResponse = (flags >>= 4) & 1;

    if ((flags >>= 1) !== 0) { throw new Error(flags); }
    return out;
};

var flagsAsInt = function(flags)
{
    var out = 0;
    out |= (flags.isResponse & 1); out <<= 4;
    out |= (flags.opCode & ((1<<4)-1)); out <<= 1;
    out |= (flags.authoritative & 1); out <<= 1;
    out |= (flags.truncated & 1); out <<= 1;
    out |= (flags.recursionDesired & 1); out <<= 1;
    out |= (flags.recursionAvailable & 1); out <<= 1;
    out |= (flags.z & 1); out <<= 1;
    out |= (flags.authenticated & 1); out <<= 1;
    out |= (flags.cd & 1); out <<= 4;
    out |= (flags.rcode & ((1<<4)-1));
    return out;
};

var parseName = function(msg)
{
    var length = Message.pop8(msg);
    var name = [];
    while (length > 0) {
        name.push(new Buffer(Message.pop(msg, length)).toString('utf8'));
        length = Message.pop8(msg);
    }
    return name;
};

var serializeName = function(msg, name)
{
    Message.push8(msg, 0);
    for (var i = name.length-1; i >= 0; i--) {
        var nameBuff = new Buffer(name[i], 'utf8');
        Message.push(msg, nameBuff);
        Message.push8(msg, nameBuff.length);
    }
};

var parseQuestion = function(msg)
{
    var q = {};
    q.name = parseName(msg);
    q.type = Message.pop16(msg);
    q.cls = Message.pop16(msg);
    return q;
};

var serializeQuestion = function(msg, q)
{
    Message.push16(msg, q.cls);
    Message.push16(msg, q.type);
    serializeName(msg, q.name);
};

var parseRR = function(msg)
{
    var rr = {};
    rr.name = parseName(msg);
    rr.type = Message.pop16(msg);
    rr.cls = Message.pop16(msg);
    rr.ttl = Message.pop32(msg);
    var dataLen = Message.pop16(msg);
    rr.data = new Buffer(Message.pop(msg, dataLen));
    return rr;
};

var serializeRR = function(msg, rr)
{
    Message.push(msg, rr.data);
    Message.push16(msg, rr.data.length);
    Message.push32(msg, rr.ttl);
    Message.push16(msg, rr.cls);
    Message.push16(msg, rr.type);
    serializeName(msg, rr.name);
};

var parseMessage = function(msg)
{
    var parsed = {
        questions: [],
        answers: [],
        authorities: [],
        additionals: [],
    };

    parsed.id = Message.pop16(msg);
    parsed.flags = parseFlags(Message.pop16(msg));
    var totalQuestions = Message.pop16(msg);
    var totalAnswerRRs = Message.pop16(msg);
    var totalAuthorityRRs = Message.pop16(msg);
    var totalAdditionalRRs = Message.pop16(msg);

    for (var i = 0; i < totalQuestions; i++) {
        parsed.questions.push(parseQuestion(msg));
    }
    for (var i = 0; i < totalAnswerRRs; i++) {
        parsed.answers.push(parseRR(msg));
    }
    for (var i = 0; i < totalAuthorityRRs; i++) {
        parsed.authorities.push(parseRR(msg));
    }
    for (var i = 0; i < totalAdditionalRRs; i++) {
        parsed.additionals.push(parseRR(msg));
    }

    return parsed;
};

var serializeMessage = function(msg, parsed)
{
    parsed.additionals = parsed.additionals || [];
    parsed.authorities = parsed.authorities || [];
    parsed.answers = parsed.answers || [];
    parsed.questions = parsed.questions || [];

    for (var i = 0; i < parsed.additionals.length; i++) {
        serializeRR(msg, parsed.additionals[i]);
    }
    for (var i = 0; i < parsed.authorities.length; i++) {
        serializeRR(msg, parsed.authorities[i]);
    }
    for (var i = 0; i < parsed.answers.length; i++) {
        serializeRR(msg, parsed.answers[i]);
    }
    for (var i = 0; i < parsed.questions.length; i++) {
        serializeQuestion(msg, parsed.questions[i]);
    }

    Message.push16(msg, parsed.additionals.length);
    Message.push16(msg, parsed.authorities.length);
    Message.push16(msg, parsed.answers.length);
    Message.push16(msg, parsed.questions.length);

    Message.push16(msg, flagsAsInt(parsed.flags));
    Message.push16(msg, parsed.id);
};

var RCode = {
    NO_ERROR: 0,
    FORMAT_ERROR: 1,
    SERVER_ERROR: 2,
    NXDOMAIN: 3,
    NOT_IMPLEMENTED: 4,
    REFUSED: 5,
    XYDOMAIN: 6,
    YXRRSET: 7,
    NXRRSET: 8,
    NOT_AUTH: 9,
};

var makeError = function(msg, query, rcode)
{
    serializeMessage(msg, {
        questions: query.questions,
        id: query.id,
        flags: {
            rcode: rcode,
            isResponse: 1,
        }
    });
};

var makeAAAA = function(msg, query, address)
{
    serializeMessage(msg, {
        answers: [
            {
                type: Record.AAAA,
                data: address,
                ttl: 0,
                cls: 1,
                name:query.questions[0].name
            }
        ],
        questions: query.questions,
        id: query.id,
        flags: {
            isResponse: 1,
        }
    });
};

var isValid = function (name)
{
    for (var i = 0; i < name.length; i++) {
        name[i] = name[i].toLowerCase();
        if (!(/^[a-z0-9-]+$/.test(name[i]))) {
            return false;
        }
    }
    return true;
};

// 1 if B comes before A
// -1 if A comes before B
var compare = function(entryA,entryB)
{
    var a = entryA.name;
    var b = entryB.name;
    // We explicitly want to sort by first seen and not by length because
    // h/cjd and h/cjd/2 are equivilant. If squatters take over h/cjd then I'll just
    // move to h/cjd/2 or h/cjd/3 or h/cjd/abcdefg and so on.

    // First we sort by length and bytes prior to the final slash.
    var aLength = a.lastIndexOf('/');
    var bLength = b.lastIndexOf('/')
    if (aLength !== bLength) { return (aLength > bLength) ? 1 : -1; }
    for (var i = 0; i < aLength; i++) {
        if (a.charCodeAt(i) !== b.charCodeAt(i)) {
            return a.charCodeAt(i) > b.charCodeAt(i) ? 1 : -1;
        }
    }

    if (a.length !== b.length) { return (a.length > b.length) ? 1 : -1; }
    for (var i = aLength; i < a.length; i++) {
        if (a.charCodeAt(i) !== b.charCodeAt(i)) {
            return a.charCodeAt(i) > b.charCodeAt(i) ? 1 : -1;
        }
    }

    // has to be the same entry, namecoin would not allow 2 with dupe names.
    return 0;
};


var doLookup = function (rname,
                         hotKeys,
                         servers,
                         serverNum,
                         firstNum,
                         messenger,
                         minSignatures,
                         callback)
{
    serverNum %= servers.length;
    var server = servers[serverNum];
console.log("looking up with " + Object.keys(hotKeys) + "  keys");
    messenger.lookup(rname, hotKeys, server, function (err, ret) {
        if (err) {
            console.log(err);
        } else if (Object.keys(ret.validSigsByIdent).length < minSignatures) {
            console.log("Not enough signatures searching for [" + rname + "] needed ["
                + minSignatures + "] got [" + Object.keys(ret.validSigsByIdent).length + "] "
                + "consider reducing minSignatures");
        } else if (rname !== ret.entry[0]) {
            if (compare(ret.entry[0], rname) === -1 && compare(rname, ret.entry[1]) === -1) {
                callback(RCode.NXDOMAIN);
                return;
            }
            console.log("Made request for [" + rname + "] and got [" + ret.entry[0] + "] -> [" + ret.entry[1] + "] tell cjd");
        } else {
            var value;
            try {
                value = JSON.parse(ret.entry[2]);
            } catch (err) {
                console.log("couldn't parse [" + ret.entry[2] + "] as json");
                callback(RCode.SERVER_ERROR);
                return;
            }
            if (typeof(value.cjdns) === 'undefined') {
                callback(0);
                return;
            }
            var buff = Base32.decode(value.cjdns.replace(/\..*$/, ''));
            var sha = crypto.createHash('sha512');
            sha.update(buff);
            buff = new Buffer(sha.digest('hex'), 'hex');
            sha = crypto.createHash('sha512');
            sha.update(buff);
            buff = new Buffer(sha.digest('hex'), 'hex');

            callback(0, buff.slice(0,16));
            return;
        }

        serverNum = (serverNum + 1) % servers.length;
        if (serverNum === firstNum) {
            console.log("ran out of servers to try for [" + rname + "]");
            callback(RCode.SERVER_ERROR);
            return;
        }
        doLookup(rname, hotKeys, servers, serverNum, firstNum, messenger, minSignatures, callback);
    });
};

var handleReq = function(buff, rinfo, sock, messenger, hotKeys, minSigs, servers)
{
    var msg = Message.wrap(buff);
    var query = parseMessage(msg);
    if (Message.size(msg) !== 0) { console.log("trailing crap in query [" + printHex(msg) + "]"); }
    Message.reset(msg);

    var name = query.questions[0].name;
    if (name[name.length-1] !== 'h' && name[name.length-1] !== 'H') {
        makeError(msg, query, RCode.NOT_AUTH);

    } else if (query.questions[0].type !== Record.AAAA || !isValid(name)) {
        makeError(msg, query, RCode.NXDOMAIN);

    } else {
        var rname = 'h/' + name[name.length-2];
        var randSrv = Math.floor(Math.random()*servers.length);
        doLookup(rname, hotKeys, servers, randSrv, randSrv, messenger, minSigs, function(code, ret) {
            if (typeof(ret) === 'undefined') {
                makeError(msg, query, code);
            } else {
                makeAAAA(msg, query, ret);
            }
            sock.send(msg.buff, msg.offset, msg.buff.length - msg.offset, rinfo.port, rinfo.address);
        });
        return;
    }

    sock.send(msg.buff, msg.offset, msg.buff.length - msg.offset, rinfo.port, rinfo.address);
};

var run = function(config)
{
    var json = JSON.parse(config);
    var hotKeys;
    var messenger = Messenger.init();
    var start = function() {
        var addr = json.rproxy.bind[0];
        var port = json.rproxy.bind[1];
        var sock = UDP.createSocket((addr.indexOf(':') > -1) ? 'udp6' : 'udp4');
        sock.on('message', function(buff, rinfo) {
            handleReq(buff, rinfo, sock, messenger, hotKeys, json.minSignatures, json.servers);
        });
        sock.bind(port, addr);
    };

    var initializing = 1;
    var coldKeys = [];
    for (var i = 0; i < json.keys.length; i++) {
        coldKeys[i] = Base32.decode(json.keys[i].replace(/\..*$/, ''));
    }
    var getHotKeys = function()
    {
        var server = json.servers[Math.floor(Math.random() * json.servers.length)];
        messenger.lookupHotKeys(coldKeys, server, function (err, ret) {
            if (err) {
                setTimeout(getHotKeys, Math.random()*2000);
                return;
            }
            if (Object(ret).length < json.minSignatures) {
                console.log("not able to attain a quarum, try lowering minSignatures");
                setTimeout(getHotKeys, Math.random()*3000);
                return;
            }
            hotKeys = ret;
            setTimeout(getHotKeys, Math.random()*600000);
            if (initializing) {
                console.log("Got quarum of [" + Object.keys(hotKeys).length + "] keys");
                initializing = 0;
                start();
                return;
            }
        });
    };
    getHotKeys();
};

var main = module.exports.main = function() {
    var home = process.env.HOME || process.env.HOMEPATH || process.env.USERPROFILE;

    Fs.readFile(home+'/.rainfly/conf.json', function(err, dat) {
        if (err) {
            throw err;
        }
        run(dat);
    });
};

main();
