local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local strbuf = require "strbuf"

description = [[
]]

---
--@output

author = "Frank Breedijk of Dutch Institute for Vulnerability Disclosure (DIVD.nl)"
last_update = "May 08, 2021"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service( {80, 443, 6060}, {"http", "https"}, "tcp", "open")


-- Extract version information from body
-- <title>CtrlSDataAssurance-ReadMe.html</title>
-- <td>BuildDate</td>
-- <td>Date 27-July-2013 Time 10_21_46</td>
-- </tr>
-- <tr>
-- <td>Build Version</td>
-- <td>4.4.0</td>
-- </tr>
-- <tr>
-- <td>Build Number</td>
-- <td>4402013071205</td>
-- </tr>
local function extract_version_info(body)
  local version = ""
  local patchlevel = ""
  local customer_id = ""
  -- BDR/CtrlS
  for line in body:gmatch("<title>%a+") do
    stdnse.debug1("Found product line: %s", line)
    product = string.gsub(line,"<title>","")
    stdnse.debug1("Found product: %s", product)
  end
  -- StoreGrid
  for line in body:gmatch("<TITLE> About %a+") do
    stdnse.debug1("Found product line: %s", line)
    product = string.gsub(line,"<TITLE> About ","")
    stdnse.debug1("Found product: %s", product)
  end
  -- BDR/CtrlS
  for line in body:gmatch("<td>Build Version</td>.-<td>[%d%.]+") do
    stdnse.debug1("Found version line: %s", line)
    version = string.gsub(line,"[^%d%.]","")
    stdnse.debug1("Found version: %s", version)
  end
  -- StorGrid
  for line in body:gmatch("<TD>Build Version</TD>.-<TD>[%d%.]+") do
    stdnse.debug1("Found version line: %s", line)
    version = string.gsub(line,"[^%d%.]","")
    stdnse.debug1("Found version: %s", version)
  end
  -- BDR/CtrlS
  for line in body:gmatch("<td>Build Number</td>.-<td>[%d%.]+") do
    stdnse.debug1("Found build line: %s", line)
    build = string.gsub(line,"[^%d%.]","")
    stdnse.debug1("Found build: %s", build)
  end
  -- StorGrid
  for line in body:gmatch("<TD>Build Number</TD>.-<TD>[%d%.]+") do
    stdnse.debug1("Found build line: %s", line)
    build = string.gsub(line,"[^%d%.]","")
    stdnse.debug1("Found build: %s", build)
  end
  bdate=""
  for line in body:gmatch("<td>Build *Date</td>%c+<td>Date [%a%d-_ ]+") do
    stdnse.debug1("Found build date line: %s", line)
    bdate = string.gsub(line,"<td>Build *Date</td>%c+<td>Date ","")
    bdate = string.gsub(bdate,"Time ","")
    bdate = string.gsub(bdate,"_",":")
    stdnse.debug1("Found build date: %s", bdate)
  end
  return version,product,build,bdate
end

action = function(host, port, redirects)
  local dis_count, noun

  options = {header={}}    
  options['header']['User-Agent'] = "Mozilla/5.0 (Vembu BDR version check)"

  -- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
  local status_404, result_404, known_404 = http.identify_404(host,port)
  if ( status_404 and result_404 == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", host.ip, port.number)
    return "Not a VembuBDR server, 404 and 200 are the same"
  end

  local answer = http.get(host, port, "/readme.html", options )


  if answer.status == 301 or answer.status == 302 then
    return "Error " .. answer.status .. " : " .. table.concat(answer.location," -> ")
  elseif answer.status ~= 200 then
    return "Error: " .. tostring(answer["status-line"]) 
  end

  local v_level = nmap.verbosity() + (nmap.debugging()*2)
  local output = strbuf.new()
  local detail = 15

  if not http.page_exists(answer, result_404, known_404, "/readme.html", false) then
    return "Not a VembuBDR server, no /readme.html found"
  end

  isVembu=false

  if string.match(answer.body,'VembuBDR') then
    isVembu=true
  end

  if string.match(answer.body,'CtrlSDataAssurance') then
    isVembu=true
  end

  if string.match(answer.body,'StoreGrid') then
    isVembu=true
  end

  if not isVembu then
    return "Not a VembuBDR installation, readme.html exists, but does not match"
  end


  version, product, build, build_date = extract_version_info(answer.body)
  if (string.find(version,"^[%d%.]+$") and string.find(build,"^[%d%.]+$")) then
    if build_date ~= "" then
      build_date = string.format("- Build date: %s", build_date)
    end
    port.version.name = string.format("%s v%s", product, version)
    port.version.name_confidence = 8
    port.version.product = product
    port.version.version = version
    port.version.extrainfo = string.format("Build: %s %s", build, build_date)
    port.version.devicetype = "generic"
    if answer.ssl then
      port.version.service_tunnel = "ssl"
    else
      port.version.service_tunnel = "none"
    end
    port.version.service_dtype = "probe"
    -- port.version.cpe = {"cpe:/a:vembu:bdr:" .. version} -- THere is no CPE for this one
    nmap.set_port_version(host, port)
    return string.format("%s - Version: %s - Build: %s %s", product, version, build, build_date) 
  end
  return 
end

