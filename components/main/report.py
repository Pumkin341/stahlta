import os
import datetime
from html import escape

# {
#   'severity': <string>,
#   'category': <string>,
#   'description': <string>,
#   'details': <dict of key→value>,
#   'timestamp': <ISO‐8601 timestamp when added>
# }
vulnerabilities = []


def validate_output_path(output_path: str, default_name: str = 'stahlta_report_') -> str:
    default_name = default_name + datetime.datetime.now().strftime('%Y%m%d_%H%M%S') + '.html'

    base, ext = os.path.splitext(output_path)
    ext = ext.lower()

    if ext == '.html':
        folder = os.path.dirname(output_path) or '.'
        final_path = output_path
        
    else:
        folder = output_path or '.'
        final_path = os.path.join(folder, default_name)

    if not os.path.isdir(folder):
        return None

    return final_path


def report_vulnerability(severity: str, category: str, description: str, details: dict):
    entry = {
        'severity': severity,
        'category': category,
        'description': description,
        'details': details or {},
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    vulnerabilities.append(entry)


def generate_html_report(output_path: str, total_resources: int):
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    total_vulns = len(vulnerabilities)

    severity_counts = {}
    for v in vulnerabilities:
        sev = v['severity']
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    categories = {}
    for v in vulnerabilities:
        category = v.get('category', 'UNKNOWN').upper()
        categories.setdefault(category, []).append(v)

    html_parts = [
        '<!DOCTYPE html>',
        '<html lang="en">',
        '<head>',
        '  <meta charset="UTF-8">',
        '  <meta name="viewport" content="width=device-width, initial-scale=1.0">',
        '  <title>Stahlta Scan Report</title>',
        '  <style>',
        '    /* Dark-themed body */',
        '    body {',
        '      background-color: #121212;',
        '      color: #e0e0e0;',
        '      font-family: Arial, sans-serif;',
        '      margin: 0;',
        '      padding: 0;',
        '    }',
        '    /* Centered container, increased width */',
        '    .container {',
        '      max-width: 1200px;',
        '      margin: 20px auto;',
        '      background-color: #1e1e1e;',
        '      padding: 30px;',
        '      border-radius: 8px;',
        '      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);',
        '    }',
        '    h1 {',
        '      text-align: center;',
        '      font-size: 2.5em;',
        '      margin-bottom: 10px;',
        '      color: #ffffff;',
        '    }',
        '    h2, h3 {',
        '      color: #e0e0e0;',
        '      margin-top: 30px;',
        '      margin-bottom: 10px;',
        '    }',
        '    .summary {',
        '      margin-bottom: 30px;',
        '    }',
        '    .summary p {',
        '      margin: 6px 0;',
        '      font-size: 1em;',
        '    }',
        '    ul {',
        '      padding-left: 20px;',
        '    }',
        '    /* Vulnerability list styling */',
        '    .vuln-list {',
        '      list-style: none;',
        '      padding: 0;',
        '    }',
        '    .vuln-item {',
        '      border: 1px solid #333;',
        '      border-left: 5px solid transparent;',
        '      border-radius: 4px;',
        '      padding: 16px;',
        '      margin-bottom: 20px;',
        '      background-color: #2a2a2a;',
        '      transition: background-color 0.2s;',
        '    }',
        '    .vuln-item:hover {',
        '      background-color: #333333;',
        '    }',
        '    .severity-label {',
        '      font-weight: bold;',
        '      padding: 2px 6px;',
        '      border-radius: 4px;',
        '      color: #ffffff;',
        '      margin-right: 8px;',
        '    }',
        '    .sev-CRITICAL .severity-label { background-color: #b71c1c; }',
        '    .sev-HIGH .severity-label     { background-color: #d32f2f; }',
        '    .sev-MEDIUM .severity-label   { background-color: #f57c00; color: #000000; }',
        '    .sev-LOW .severity-label      { background-color: #388e3c; }',
        '    .vuln-item p {',
        '      margin: 8px 0;',
        '      font-size: 1em;',
        '    }',
        '    .vuln-details {',
        '      margin-top: 8px;',
        '      margin-left: 16px;',
        '      font-size: 0.95em;',
        '      color: #cfcfcf;',
        '    }',
        '    .no-vulns {',
        '      font-style: italic;',
        '      color: #757575;',
        '    }',
        '  </style>',
        '</head>',
        '<body>',
        '  <div class="container">',
        f'    <h1>Stahlta Scan Report</h1>',
        '    <div class="summary">',
        f'      <p><strong>Generated on:</strong> {escape(now)}</p>',
        f'      <p><strong>Total crawled resources:</strong> {total_resources}</p>',
        f'      <p><strong>Total vulnerabilities found:</strong> {total_vulns}</p>',
        '      <h3>By Severity:</h3>',
        '      <ul>',
    ]

    for sev, count in sorted(severity_counts.items(), key=lambda x: x[0]):
        color_class = f'sev-{escape(sev)}'
        html_parts.append(
            f'        <li><span class="severity-label {color_class}">{escape(sev)}</span>: {count}</li>'
        )

    if not severity_counts:
        html_parts.append('        <li class="no-vulns">No vulnerabilities detected.</li>')
    html_parts.append('      </ul>')
    html_parts.append('    </div>')  # close summary

    if total_vulns > 0:
        html_parts.append('    <h2>Vulnerabilities Details</h2>')
        
        for category in sorted(categories.keys()):
            items = categories[category]
            html_parts.append(f'    <h3>{escape(category)}</h3>')
            html_parts.append('    <ul class="vuln-list">')
            
            for idx, v in enumerate(items, start=1):
                sev = escape(v['severity'])
                desc = escape(v['description'])
                ts = escape(v['timestamp'])

                if v['details']:
                    detail_rows = []
                    for key, val in v['details'].items():
                        detail_rows.append(f'<strong>{escape(str(key))}:</strong> {escape(str(val))}')
                    detail_html = '<br>'.join(detail_rows)
                else:
                    detail_html = '<span class="no-vulns">—</span>'

                color_class = f'sev-{sev}'

                html_parts.extend([
                    f'      <li class="vuln-item {color_class}">',
                    f'        <p><span class="severity-label {color_class}">{sev}</span>{desc}</p>',
                    f'        <p><strong>Timestamp:</strong> {ts}</p>',
                    f'        <div class="vuln-details"><strong>Details:</strong><br>{detail_html}</div>',
                    '      </li>',
                ])
            html_parts.append('    </ul>')

    html_parts.extend([
        '  </div>',
        '</body>',
        '</html>'
    ])

    # Write to file
    full_html = '\n'.join(html_parts)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(full_html)
        
        
if __name__ == '__main__':
    report_vulnerability('HIGH', 'SQL Injection', 'Potential SQL injection in login form',
                         {'Target': 'http://example.com/login', 'Parameter': 'username', 'Payload': "' OR 1=1 --"})
    report_vulnerability('CRITICAL', 'XSS', 'Reflected XSS in search page',
                         {'Target': 'http://example.com/search', 'Parameter': 'query', 'Payload': '<script>alert(1)</script>'})
    report_vulnerability('LOW', 'SQL Injection', 'Blind SQL injection in user profile',
                         {'Target': 'http://example.com/profile', 'Parameter': 'id', 'Payload': '1\' AND 1=1 --'})
    
    output_file = validate_output_path('report.html')
    if output_file:
        generate_html_report(output_file, total_resources=100)
        print(f'Report generated at: {output_file}')
    else:
        print('Invalid output path provided.')
