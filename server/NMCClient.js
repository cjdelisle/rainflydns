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
var http = require('http');

var rpcCall = function(msg, callback)
{
  console.log("Sending request: " + JSON.stringify(msg));
  post = JSON.stringify(msg) + '\n';
  var dat = '';
  var req = http.request({
      host: '127.0.0.1',
      port:8336,
      auth:':password',
      method:'POST',
      agent:false,
      headers: {
        'User-Agent': 'bitcoin-json-rpc/0.3.50',
        'Host': '127.0.0.1',
        'Content-Type': 'application/json',
        'Content-Length': post.length,
        'Accept': 'application/json',
      }
    },
    function(res) {
      res.setEncoding('utf8');
      res.on('data', function (chunk) {
        dat += chunk;
      });
      res.on('end', function () {
        callback(dat);
      });
    }
  );
  req.write(post);
  req.end();
};

var nameHistory = module.exports.nameHistory = function(name, callback) {
    rpcCall({
        method: "name_history",
        params: [ name ]
    }, function(dat) {
      try {
          var content = JSON.parse(dat);
      } catch (e) { callback(e.stack, undefined); }
      if (content.error) { callback(content.error, null); }
      callback(undefined, content.result);
    });
};

/*
nameHistory('h/nic/', function(err, dat) {
    console.log(JSON.stringify(dat, null, '  '));
});
*/

var nameScan = module.exports.nameScan = function(callback, count, beginWith) {
  var post = {
      method: "name_scan",
      params: [
          String(beginWith || ""),
          String((count < 500 ? count : 500))
      ]
  };
  if (count !== undefined) {
      count -= 500;
      if (count < 0) { count = 0; }
  }
  rpcCall(post, function(dat) {
    if (false && names.length > 1 && (count === undefined || count > 0)) {
      getNames(function(moreNames) {
        var overlapName = names.pop();
        if (overlapName.name !== moreNames[0].name) {
          throw new Error(JSON.stringify(overlapName) + ' !== ' + JSON.stringify(moreNames[0]));
        }
        names.push.apply(names, moreNames);
        callback(names);
      }, count, names[names.length-1].name);
    } else {
      callback(names);
    }
  });
};

var nameFilter = module.exports.nameFilter = function(regex, callback)
{
  rpcCall({
      method: "name_filter",
      params: [ regex ],
    }, function(dat) {
      try {
          var content = JSON.parse(dat);
      } catch (e) { callback(e.stack, undefined); }
      if (content.error) { callback(content.error, null); }
      callback(undefined, content.result);
    }
  );
};
/*
nameFilter('^tor/', function(err, dat) {
    console.log(JSON.stringify(dat, null, '  '));
});
*/
