"""Repair the known PHP-token syntax error without replacing unrelated panel code."""
import re

START = 'get_php_version_token:function(c,o){'
END = ',set_soft_config:function(c)'
FIXED = '''get_php_version_token:function(c,o){
var r=[c];
if(o){
  r.push(o.name,o.s_version,o.version,o.display_version,o.title);
  if(o.versions&&o.versions.length){
    r.push(o.versions[0].m_version);
    if(o.versions[0].version)r.push(String(o.versions[0].m_version||"")+"."+String(o.versions[0].version||""));
    r.push(o.versions[0].version_msg,o.versions[0].display_version);
  }
}
for(var e=0;e<r.length;e++){
  var t=r[e];
  if(null!=t&&""!=(t=String(t))&&"-1"!==t){
    var m=t.match(/php[-_\\s]*([0-9])\\.?([0-9])/i)||t.match(/^([0-9])\\.?([0-9])$/);
    if(m)return m[1]+m[2];
  }
}
return "";
}'''


def patch_utils(data):
    text = data.decode('utf-8-sig')
    if text.count(START) != 1 or text.count(END) != 1:
        raise ValueError('Unknown panel helper layout')
    start, end = text.index(START), text.index(END)
    old = text[start:end]
    if old == FIXED:
        return data
    if not old.startswith(START + 'for(var r=[c],e=0;if(o&&') or not old.endswith('return""}'):
        raise ValueError('Unknown PHP-token implementation; refusing replacement')
    return (text[:start] + FIXED + text[end:]).encode('utf-8')


def patch_template(data):
    text = data.decode('utf-8-sig')
    pattern = r'/static/js/utils\.min\.js\?v=[A-Za-z0-9-]+'
    updated, count = re.subn(pattern, '/static/js/utils.min.js?v=20261025-waf-loader1', text)
    if count != 1:
        raise ValueError('Expected exactly one shared-script reference')
    if updated == text:
        return data
    return updated.encode('utf-8')
