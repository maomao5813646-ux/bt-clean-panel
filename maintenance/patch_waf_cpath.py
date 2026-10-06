"""Prevent per-request growth of Lua module search paths; preserve WAF rules."""
SUFFIX = ';/usr/lib/x86_64-linux-gnu/lua/5.1/?.so;/usr/lib64/lua/5.1/?.so;/usr/local/lib/lua/5.1/?.so;/usr/lib/lua/5.1/?.so'
OLD = 'package.cpath = package.cpath .. "' + SUFFIX + '"'
NEW = ('local bt_waf_cpath_suffix = "' + SUFFIX + '"\n'
       'if not string.find(package.cpath, bt_waf_cpath_suffix, 1, true) then\n'
       '    package.cpath = package.cpath .. bt_waf_cpath_suffix\nend')


def patch(data):
    text = data.decode('utf-8').replace('\r\n', '\n')
    if OLD in text:
        if text.count(OLD) != 1:
            raise ValueError('Unexpected multiple legacy path initializers')
        return text.replace(OLD, NEW).encode('utf-8')
    if NEW in text:
        return data
    raise ValueError('Unknown WAF initializer; refusing blind replacement')
