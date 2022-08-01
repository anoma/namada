from ghapi.all import GhApi
from os import environ
from json import loads, load
from tempfile import gettempdir
import subprocess


def download_artifact(link: str, path: str, token: str):
    return subprocess.run(["curl", "-H", "Accept: application/vnd.github+json".format(token), "-H", "Authorization: token {}".format(token), link, "-L", "-o", "{}/wasm.zip".format(path)], capture_output=True)


def unzip(path: str):
    return subprocess.run(["unzip", "-o", "{}/wasm.zip".format(path), "-d", path], capture_output=True)


def publish_wasm(path: str, file_name: str, bucket: str):
    return subprocess.run(["aws", "s3", "cp", "{}/{}".format(path, file_name), "s3://{}".format(bucket), "--acl", "public-read"], capture_output=True)


def log(data: str):
    print(data)


TOKEN = environ["GITHUB_TOKEN"]
READ_ORG_TOKEN = environ['GITHUB_READ_ORG_TOKEN']
REPOSITORY_NAME = environ['GITHUB_REPOSITORY_OWNER']
TMP_DIRECTORY = gettempdir()
ARTIFACT_PER_PAGE = 75
WASM_BUCKET = 'namada-wasm-master'

read_org_api = GhApi(token=READ_ORG_TOKEN)
api = GhApi(owner=REPOSITORY_NAME, repo="namada", token=TOKEN)

comment_event = loads(environ['GITHUB_CONTEXT'])

user_membership = read_org_api.teams.get_membership_for_user_in_org(
    'heliaxdev', 'company', comment_event['event']['sender']['login'])
if user_membership['state'] != 'active':
    exit(0)

comment_event = loads(environ['GITHUB_CONTEXT'])
pr_comment = comment_event['event']['comment']['body']
pr_number = comment_event['event']['issue']['number']

pr_info = api.pulls.get(pr_number)
head_sha = pr_info['head']['sha']

artifacts = api.actions.list_artifacts_for_repo(per_page=ARTIFACT_PER_PAGE)

for artifact in artifacts['artifacts']:
    if 'wasm' in artifact['name'] and artifact['workflow_run']['head_sha'] == head_sha and not artifact['expired']:
        artifact_download_url = artifact['archive_download_url']

        log("Downloading artifacts...")
        curl_command_outcome = download_artifact(
            artifact_download_url, TMP_DIRECTORY, TOKEN)
        if curl_command_outcome.returncode != 0:
            exit(1)

        log("Unzipping wasm.zip...")
        unzip_command_outcome = unzip(TMP_DIRECTORY)
        if unzip_command_outcome.returncode != 0:
            exit(1)

        checksums = load(open("{}/checksums.json".format(TMP_DIRECTORY)))
        for wasm in checksums.values():
            log("Uploading {}...".format(wasm))
            publish_wasm_command_outcome = publish_wasm(
                TMP_DIRECTORY, wasm, WASM_BUCKET)
            if publish_wasm_command_outcome.returncode != 0:
                print("Error uploading {}!".format(wasm))

        log("Done!")
