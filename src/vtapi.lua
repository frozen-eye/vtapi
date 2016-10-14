local http = require'socket.http'
local ltn12 = require'ltn12'
local json = require'json'
local multipart = require'multipart-post'

local urls = {
  file = {
    scan = 'https://www.virustotal.com/vtapi/v2/file/scan',
    rescan = 'https://www.virustotal.com/vtapi/v2/file/rescan',
    report = 'https://www.virustotal.com/vtapi/v2/file/report',
  },
  url = {
    scan = 'https://www.virustotal.com/vtapi/v2/url/scan',
    report = 'https://www.virustotal.com/vtapi/v2/url/report',
  },
  ip = {
    report = 'https://www.virustotal.com/vtapi/v2/ip-address/report',
  },
  domain = {
    report = 'https://www.virustotal.com/vtapi/v2/domain/report',
  },
  extra = {
    comment = 'https://www.virustotal.com/vtapi/v2/comments/put',
  },
  doc = {
    api = 'https://www.virustotal.com/en/documentation/public-api/'
  }
}

local function urlencode(str)
  assert(str)

  str = string.gsub(str, '\n', '\r\n')
  str = string.gsub(str, '([^%w ])', function (c) return string.format('%%%02X', string.byte(c)) end)
  str = string.gsub(str, ' ', '+')

  return str
end

-- https://virustotal.com/en/documentation/public-api/#scanning-urls
local function url_scan(apikey, url)
--  print('url_scan')
  assert(apikey)
  assert(url)

  local reqbody = 'apikey=' .. apikey .. '&url=' .. urlencode(url)
  local respbody = {}
  local r, c = http.request{
    method = 'POST',
    url = urls.url.scan,
    source=ltn12.source.string(reqbody),
    headers = {
      ["content-length"] = string.len(reqbody)
    },
    sink = ltn12.sink.table(respbody)
  }

  if r == nil then
    print('The server is unreachable: '.. c)
  else
    print(r, c)
    if c == 200 then
      r = json.decode(table.concat(respbody))
      c = nil
    else
      r = nil
    end
  end

  return r, c
end

-- https://virustotal.com/en/documentation/public-api/#getting-url-scans
local function url_report(apikey, resource)
--  print('url_report')
  assert(apikey)
  assert(resource)

  local reqbody = 'apikey=' .. apikey .. '&resource=' .. resource
  local respbody = {}
  local r, c = http.request{
    method = 'POST',
    url = urls.url.report,
    source = ltn12.source.string(reqbody),
    headers = {
      ["content-length"] = string.len(reqbody)
    },
    sink = ltn12.sink.table(respbody)
  }

  if r == nil then
    print('The server is unreachable: '.. c)
  else
    print(r, c)
    if c == 200 then
      r = json.decode(table.concat(respbody))
      c = nil
    else
      r = nil
    end
  end

  return r, c
end

-- https://virustotal.com/en/documentation/public-api/#scanning-files
local function file_scan(apikey, file)
--  print('file_scan')
  assert(apikey)
  assert(file)

  local f = io.open(file, 'rb')
  local respbody = {}
  local file_name = string.sub(file,(string.find(file, '/[^/]-$') or 0) + 1)
  file_name = string.sub(file,(string.find(file, '\\[^\\]-$') or 0) + 1)

  local request = multipart.gen_request{apikey=apikey, file = {name = file_name, data = f:read('*a')}}

  request.url = urls.file.scan
  request.sink = ltn12.sink.table(respbody)
  local r, c = http.request(request)
  print(r, c)

  f:close()

  if r == nil then
    print('The server is unreachable: '.. c)
  else
    r = json.decode(table.concat(respbody))
    c = nil
  end

  return r, c
end

-- https://virustotal.com/en/documentation/public-api/#rescanning-files
local function file_rescan(apikey, resource)
--  print('file_rescan')
  assert(apikey)
  assert(resource)

  local reqbody = 'apikey=' .. apikey .. '&resource=' .. resource
  local respbody = {}
  local r, c = http.request{
    method = 'POST',
    url = urls.file.rescan,
    source = ltn12.source.string(reqbody),
    headers = {
      ["content-length"] = string.len(reqbody)
    },
    sink = ltn12.sink.table(respbody)
  }

  if r == nil then
    print('The server is unreachable: '.. c)
  else
    print(r, c)
    if c == 200 then
      r = json.decode(table.concat(respbody))
      c = nil
    else
      r = nil
    end
  end

  return r, c
end

-- https://virustotal.com/en/documentation/public-api/#getting-file-scans
local function file_report(apikey, resource)
--  print('file_report')
  assert(apikey)
  assert(resource)

  local reqbody = 'apikey=' .. apikey .. '&resource=' .. resource
  local respbody = {}
  local r, c = http.request{
    method = 'POST',
    url = urls.file.report,
    source = ltn12.source.string(reqbody),
    headers = {
      ["content-length"] = string.len(reqbody)
    },
    sink = ltn12.sink.table(respbody)
  }

  if r == nil then
    print('The server is unreachable: '.. c)
  else
    print(r, c)
    if c == 200 then
      r = json.decode(table.concat(respbody))
      c = nil
    else
      r = nil
    end
  end

  return r, c
end

-- https://virustotal.com/en/documentation/public-api/#getting-ip-reports
local function ip_report(apikey, ip)
--  print('ip_report')
  
  assert(apikey)
  assert(ip)

  local reqbody = '?apikey=' .. apikey .. '&ip=' .. ip
  local u = urls.ip.report..reqbody
  
  local respbody = {}
  local r, c, h = http.request{
    url = u,
    sink = ltn12.sink.table(respbody)
  }

  if r == nil then
    print('The server is unreachable: '.. c)
  else
    print(r, c)
    if c == 200 then
      r = json.decode(table.concat(respbody))
      c = nil
    else
      r = nil
    end
  end

  return r, c
end

-- https://virustotal.com/en/documentation/public-api/#getting-domain-reports
local function domain_report(apikey, domain)
--  print('domain_report')
  
  assert(apikey)
  assert(domain)

  local reqbody = '?apikey=' .. apikey .. '&domain=' .. domain
  local u = urls.domain.report..reqbody
  
  local respbody = {}
  local r, c, h = http.request{
    url = u,
    sink = ltn12.sink.table(respbody)
  }

  if r == nil then
    print('The server is unreachable: '.. c)
  else
    print(r, c)
    if c == 200 then
      -- TODO need to create a pull request with empty array issue
      respbody = string.gsub(table.concat(respbody), '%[]', '[0]')
      r = json.decode(respbody)
      c = nil
    else
      r = nil
    end
  end

  return r, c
end

-- https://virustotal.com/en/documentation/public-api/#making-comments
local function comment(apikey, resource, comment)
  -- print(comment)
  return nil, 'Error: Not implemented'
end

return {
--  wait_time = 3, -- in seconds
--  max_retries = 32, -- number of retries before failure
  url_scan = url_scan,
  url_report = url_report,
  file_scan = file_scan,
  file_rescan = file_rescan,
  file_report = file_report,
  ip_report = ip_report,
  domain_report = domain_report,
  comment = comment,
}
