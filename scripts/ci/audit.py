import json
import subprocess

table_header = '| Id  | Package  | Title  | Date  |\n|----:|---------:|-------:|------:|'

table_row = '|{}|{}|{}|{}|'

table = [table_header]

command = ['cargo', 'audit', '--json']
p = subprocess.Popen(command, stdout=subprocess.PIPE)
output = p.stdout.read()
retcode = p.wait()

for vulnerability in json.loads(output)['vulnerabilities']['list']:
    vuln_description = vulnerability['advisory']
    vuln_id = vuln_description['id']
    vuln_title = vuln_description['title']
    vuln_package = vuln_description['package']
    vuln_date = vuln_description['date']
    new_table_row = table_row.format(vuln_id, vuln_package, vuln_title, vuln_date)
    table.append(new_table_row)

print('\n'.join(table))