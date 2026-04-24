import os
for root, _, files in os.walk('.'):
    for f in files:
        if f.endswith('.py') and f != 'fix_quotes.py':
            path = os.path.join(root, f)
            try:
                with open(path, 'r', encoding='utf-8') as file:
                    content = file.read()
                if '\\\"' in content:
                    content = content.replace('\\\"', '\"')
                    with open(path, 'w', encoding='utf-8') as file:
                        file.write(content)
                    print(f"Fixed quotes in {path}")
            except Exception as e:
                pass
