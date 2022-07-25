from ghapi.all import GhApi
from os import environ
from json import loads
from tempfile import gettempdir
import subprocess

def log(data: str):
    print(data)

def download_artifact(link: str, path: str, token: str):
    return subprocess.run(["curl", "-H", "Accept: application/vnd.github+json".format(token), "-H", "Authorization: token {}".format(token), link, "-L", "-o", "{}/wasm.zip".format(path)], capture_output=True)

def unzip(path: str):
    return subprocess.run(["unzip", "-o", "{}/wasm.zip".format(path), "-d", path], capture_output=True)

def replace_checksums(path: str):
    return subprocess.run(["mv", "{}/checksums.json".format(path), "wasm/"], capture_output=True)

def commit_and_push():
    subprocess.run(["git", "add", "wasm/checksums.json"], capture_output=True)
    subprocess.run(["git", "commit", "-m", "[ci skip] wasm update"], capture_output=True)
    subprocess.run(["git", "push", ], capture_output=True)


TOKEN = environ["GITHUB_TOKEN"]
TMP_DIRECTORY = gettempdir()
PR_COMMENT = 'pls update wasm'
ARTIFACT_PER_PAGE = 75

api = GhApi(owner="Fraccaman", repo="namada", token=TOKEN)

user_membership = api.teams.get_membership_for_user_in_org('heliaxdev', 'company', 'fraccaman')
if user_membership['state'] != 'active':
    exit(0)

comment_event = loads(environ['GITHUB_CONTEXT'])
pr_comment = comment_event['event']['comment']['body']
pr_number = comment_event['event']['issue']['number']

if pr_comment == PR_COMMENT:
    pr_info = api.pulls.get(pr_number)
    head_sha = pr_info['head']['sha']

    artifacts = api.actions.list_artifacts_for_repo(per_page=ARTIFACT_PER_PAGE)

    for artifact in artifacts['artifacts']:
        if 'wasm' in artifact['name'] and artifact['workflow_run']['head_sha'] == head_sha and not artifact['expired']:
            artifact_download_url = artifact['archive_download_url']
            
            log("Downloading artifacts...")
            curl_command_outcome = download_artifact(artifact_download_url, TMP_DIRECTORY, TOKEN)
            if curl_command_outcome.returncode != 0:
                exit(1)

            
            unzip_command_outcome = unzip(TMP_DIRECTORY)
            if unzip_command_outcome.returncode != 0:
                exit(1)

            log("Replacing checksums.json...")
            replace_command_outcome = replace_checksums(TMP_DIRECTORY)
            if replace_command_outcome.returncode != 0:
                exit(1)

            log("Pushing new checksums.json...")
            commit_and_push_command_outcome = commit_and_push()
            if commit_and_push_command_outcome.returncode != 0:
                exit(1)

            log("Done!")