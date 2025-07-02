import os
import datetime
from html import escape

PREVENTION_TIPS = {
    'SQL Injection': (
        "<ul>"
        "<li>Use parameterized queries (prepared statements) to separate SQL logic from data.</li>"
        "<li>Validate and sanitize all user inputs on both client and server side.</li>"
        "<li>Use ORM frameworks to abstract database queries.</li>"
        "<li>Limit database permissions for the application user.</li>"
        "<li>Avoid displaying detailed database errors to users.</li>"
        "</ul>"
    ),
    'XSS': (
        "<ul>"
        "<li>Always encode user-supplied data before rendering in the browser.</li>"
        "<li>Implement Content Security Policy (CSP) headers.</li>"
        "<li>Use secure frameworks that auto-escape outputs.</li>"
        "<li>Sanitize HTML/JavaScript input on both server and client sides.</li>"
        "</ul>"
    ),
    'Command Injection': (
        "<ul>"
        "<li>Never pass user input directly to system commands.</li>"
        "<li>Use safe APIs for executing system commands (e.g., subprocess in Python).</li>"
        "<li>Validate and sanitize all user inputs.</li>"
        "<li>Use allowlists for acceptable input values.</li>"
        "<li>Run applications with the least privileges necessary.</li>"
        "</ul>"
    ),
    'CSRF': (
        "<ul>"
        "<li>Use anti-CSRF tokens in forms and AJAX requests.</li>"
        "<li>Validate the origin of requests on the server side.</li>"
        "<li>Implement SameSite cookie attributes.</li>"
        "<li>Use secure headers like X-Frame-Options to prevent clickjacking.</li>"
        "</ul>"
    ),
    'Cookie Flags': (
        "<ul>"
        "<li>Set the HttpOnly flag on cookies to prevent JavaScript access.</li>"
        "<li>Use the Secure flag to ensure cookies are only sent over HTTPS.</li>"
        "<li>Implement the SameSite attribute to control cross-site cookie behavior.</li>"
        "<li>Regularly review and update cookie policies.</li>"
        "</ul>"
    ),
    'HTTP Headers': (
        "<ul>"
        "<li>Use security headers like Content Security Policy (CSP), X-Content-Type-Options, and X-Frame-Options.</li>"
        "<li>Implement strict Transport Security (HSTS) to enforce HTTPS.</li>"
        "<li>Regularly review and update security headers.</li>"
        "<li>Use tools to scan and validate header configurations.</li>"
        "</ul>"
    ),
}

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

def generate_html_report(output_path: str, total_resources: int, scan_info: dict = None):
    """
    scan_info example:
        {
            "Target": "https://example.com",
            "Headless": "yes",
            "Resources Scanned": 123,
            ...
        }
    """
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    total_vulns = len(vulnerabilities)

    severity_counts = {}
    for v in vulnerabilities:
        sev = v['severity']
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    categories = {}
    for v in vulnerabilities:
        category = v.get('category', 'UNKNOWN')
        categories.setdefault(category, []).append(v)

    html_parts = [
        '<!DOCTYPE html>',
        '<html lang="en">',
        '<head>',
        '  <meta charset="UTF-8">',
        '  <meta name="viewport" content="width=device-width, initial-scale=1.0">',
        '  <title>Stahlta Scan Report</title>',
        '  <style>',
        '    body { background-color: #121212; color: #e0e0e0; font-family: Arial, sans-serif; margin: 0; padding: 0; }',
        '    .container { max-width: 1800px; margin: 20px auto; background-color: #1e1e1e; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5); }',
        '    h1 { text-align: center; font-size: 2.5em; margin-bottom: 10px; color: #ffffff; }',
        '    h2, h3 { color: #e0e0e0; margin-top: 30px; margin-bottom: 10px; }',
        '    .summary { margin-bottom: 30px; }',
        '    .summary p { margin: 6px 0; font-size: 1em; }',
        '    .scan-info { background: #222; padding: 12px 18px; border-radius: 7px; margin-bottom: 20px; }',
        '    .scan-info strong { color: #fff; }',
        '    ul { padding-left: 20px; }',
        '    .vuln-list { list-style: none; padding: 0; }',
        '    .vuln-item { border: 1px solid #333; border-left: 5px solid transparent; border-radius: 4px; padding: 16px; margin-bottom: 20px; background-color: #2a2a2a; transition: background-color 0.2s; }',
        '    .vuln-item:hover { background-color: #333333; }',
        '    .severity-label { font-weight: bold; padding: 2px 6px; border-radius: 4px; color: #ffffff; margin-right: 8px; }',
        '    .sev-CRITICAL .severity-label { background-color: #b71c1c; }',
        '    .sev-HIGH .severity-label     { background-color: #d32f2f; }',
        '    .sev-MEDIUM .severity-label   { background-color: #f57c00; color: #000000; }',
        '    .sev-LOW .severity-label      { background-color: #388e3c; }',
        '    .vuln-item p { margin: 8px 0; font-size: 1em; }',
        '    .vuln-details { margin-top: 8px; margin-left: 16px; font-size: 0.95em; color: #cfcfcf; }',
        '    .vuln-prevention { margin-top: 10px; margin-left: 16px; font-size: 0.98em; background: #19202a; color: #a6e3a1; padding: 10px 16px; border-radius: 5px; border-left: 4px solid #4caf50; }',
        '    .generated-on { text-align: center; font-size: 1.08em; color: #c9d1d9; margin-bottom: 16px; }',
        '    .no-vulns { font-style: italic; color: #757575; }',
        '  </style>',
        '</head>',
        '<body>',
        '  <div class="container">',
        f'    <h1>Stahlta Scan Report</h1>',
        '    <div class="summary">',
        f'      <div class="generated-on"><strong>Generated on:</strong> {escape(now)}</div>',

    ]

    # Add scan info at the top
    if scan_info:
        html_parts.append('      <div class="scan-info">')
        for k, v in scan_info.items():
            html_parts.append(f'        <p><strong>{escape(str(k))}:</strong> {escape(str(v))}</p>')
        html_parts.append('      </div>')

    html_parts.extend([
        '      <h3>By Severity:</h3>',
        '      <ul>',
    ])

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
                        if 'html' in str(key).lower():
                            detail_rows.append(f'<strong>{escape(str(key))}:</strong> {val}')  # Do NOT escape val
                        else:
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

            # Add prevention tip ONCE for the whole category, if it exists
            prevention = PREVENTION_TIPS.get(category, None) or PREVENTION_TIPS.get(category.upper(), None)
            if prevention:
                html_parts.append(f'    <div class="vuln-prevention"><strong>How to prevent:</strong> {prevention}</div>')

    html_parts.extend([
        '  </div>',
        '</body>',
        '</html>'
    ])

    # Write to file
    full_html = '\n'.join(html_parts)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(full_html)

# Example usage
if __name__ == '__main__':
    report_vulnerability('HIGH', 'SQL Injection', 'Potential SQL injection in login form',
                         {'Target': 'http://example.com/login', 'Parameter': 'username', 'Payload': "' OR 1=1 --"})
    report_vulnerability('CRITICAL', 'XSS', 'Reflected XSS in search page',
                         {'Target': 'http://example.com/search', 'Parameter': 'query', 'Payload': '<script>alert(1)</script>'})
    report_vulnerability('LOW', 'SQL Injection', 'Blind SQL injection in user profile',
                         {'Target': 'http://example.com/profile', 'Parameter': 'id', 'Payload': '1\' AND 1=1 --'})

    scan_info = {
        "Target": "https://example.com",
        "Headless": "yes",
        "Resources Scanned": 123
    }

    output_file = validate_output_path('report.html')
    if output_file:
        generate_html_report(output_file, total_resources=123, scan_info=scan_info)
        print(f'Report generated at: {output_file}')
    else:
        print('Invalid output path provided.')
