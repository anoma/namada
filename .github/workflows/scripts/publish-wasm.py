from ghapi.all import GhApi
from os import environ
from json import loads

PR_COMMENT = 'pls publish wasm'

api = GhApi(owner="Fraccaman", repo="namada", token="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")

user_membership = api.teams.get_membership_for_user_in_org('heliaxdev', 'company', 'fraccaman')
if user_membership['state'] != 'active':
    exit()

comment_event = loads(environ['GITHUB_CONTEXT'])
pr_comment = comment_event['event']['comment']['body']
pr_number = comment_event['event']['issue']['number']

if pr_comment == PR_COMMENT:
    pr_info = api.pulls.get(pr_number)
    head_sha = pr_info['head']['sha']

    artifacts = api.actions.list_artifacts_for_repo(per_page=50)

    for artifact in artifacts['artifacts']:
        if artifact['name'] == 'wasms-{}'.format(head_sha) and not artifact['expired']:
            print(artifact['archive_download_url'])

    

    