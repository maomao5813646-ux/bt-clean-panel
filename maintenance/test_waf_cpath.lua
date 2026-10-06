-- Run with LuaJIT; execute only the initializer, not production request handlers.
local file = assert(io.open(arg[1], "r"))
local source = file:read("*a")
file:close()
local start = assert(source:find('local bt_waf_cpath_suffix = ', 1, true))
local finish = assert(source:find('\nend', start, true)) + 3
local init = assert(loadstring(source:sub(start, finish)))
init()
local expected = package.cpath
for i = 1, 100000 do init() end
assert(package.cpath == expected, 'module path grew across requests')
print('PASS: 100000 repeated initializations; module path unchanged')
