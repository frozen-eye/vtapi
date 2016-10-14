# vtapi - VirusTotal API library written in LUA

## Dependences
VT API library depends on:
* multipart-post (https://github.com/catwell/lua-multipart-post) - custom License, see LICENSE.txt
* json (https://github.com/craigmj/json4lua) - MIT License

## Usage
```lua
local vt = require'vtapi'
local api_key = '<your api key here>'
local res, err = vt.scan_url(api_key, 'https://virustotal.com')
res, err = vt.url_report(api_key, res.scan_id)
```

## Reources to download
* https://github.com/catwell/lua-multipart-post/raw/master/multipart-post.lua
* https://github.com/craigmj/json4lua/raw/master/json/json.lua

## Links
* https://virustotal.com/

## License
MIT
