import sys
html = open('buildamalwareworkshop.html', 'r', encoding='utf-8').read()
start = html.find('const malwareParts = [')
if start == -1:
    raise SystemExit('START_NOT_FOUND')
depth = 0
in_string = False
escape = False
quote = ''
end = -1
for idx, ch in enumerate(html[start:]):
    if in_string:
        if escape:
            escape = False
        elif ch == '\\':
            escape = True
        elif ch == quote:
            in_string = False
    elif ch == '"' or ch == "'":
        in_string = True
        quote = ch
    elif ch == '[':
        depth += 1
    elif ch == ']':
        depth -= 1
        if depth == 0:
            end = start + idx + 1
            break
if end == -1:
    raise SystemExit('END_NOT_FOUND')
array_text = html[start:end]
with open('tmp-array.js', 'w', encoding='utf-8') as f:
    f.write(array_text + '\nconsole.log(malwareParts.length)')
print('WROTE', len(array_text))
