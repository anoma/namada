from ghapi.all import GhApi
from os import environ
from json import loads, load
from tempfile import gettempdir
import subprocess
import re
import json
import boto3
import toml
from datetime import timedelta, date


def download_artifact(url: str, path: str, zip_name: str, token: str):
    return subprocess.run(["curl", "-s", "--fail-with-body", "-H", "Accept: application/vnd.github+json".format(token), "-H", "Authorization: token {}".format(token), url, "-L", "-o", "{}/{}.zip".format(path, zip_name)], capture_output=True)


def unzip(path: str, zip_name: str):
    return subprocess.run(["unzip", "-o", "{}/{}.zip".format(path, zip_name), "-d", path], capture_output=True)


def publish_wasm(path: str, file_name: str, bucket: str):
    return subprocess.run(["aws", "s3", "cp", "{}/{}".format(path, file_name), "s3://{}".format(bucket), "--acl", "public-read"], capture_output=True)


def upload_chain_data_archive(path: str, bucket: str):
    return subprocess.run(["aws", "s3", "cp", path, "s3://{}".format(bucket)], capture_output=True)


def zip_setup_folder(chain_id: str):
    return subprocess.run(["zip", "-r", "{}-setup.zip".format(chain_id), ".anoma"], capture_output=True) 


def download_genesis_template(repository_owner: str, template_name: str, to: str):
    url = "https://raw.githubusercontent.com/{}/anoma-network-config/master/templates/{}.toml".format(
        repository_owner, template_name)
    return subprocess.run(["curl", "-s", "--fail-with-body", url, "-o", "{}/template.toml".format(to)])


def generate_genesis_template(folder: str, chain_prefix: str):
    permissions_command_outcome = subprocess.run(
        ["chmod", "+x", "{}/namadac".format(folder)], capture_output=True)
    if permissions_command_outcome.returncode != 0:
        return permissions_command_outcome
    command = "{0}/namadac utils init-network --chain-prefix {1} --genesis-path {0}/genesis.toml --consensus-timeout-commit 10s --wasm-checksums-path {0}/checksums.json --unsafe-dont-encrypt --allow-duplicate-ip".format(
        folder, chain_prefix)
    return subprocess.run(command.split(" "), capture_output=True)


def dispatch_release_workflow(chain_id: str, repository_owner: str, github_token: str):
    data = {
        "event_type": "release",
        "client_payload": {
            "chain-id": chain_id,
            "is_prelease": True
        }
    }
    return subprocess.run([
        "curl", "-d", json.dumps(data), "-H", "Content-Type: application/json", "-H", "Authorization: token {}".format(github_token), "-H", "Accept: application/vnd.github.everest-preview+json", "https://api.github.com/repos/{}/anoma-network-config/dispatches".format(repository_owner)
    ], capture_output=True)


def debug(file_path: str):
    output = subprocess.run(['cat', file_path], capture_output=True)
    if output.returncode != 0:
        print(output.stderr)
        exit(1)
    else:
        print(output.stdout)


def read_toml(path: str):
    return toml.loads(open(path, 'r').read())


def write_toml(data, path: str):
    return toml.dump(data, open(path, 'w'))


def fix_genesis_template(template, ips):
    for index, validator in enumerate(template['validator']):
        validator_port = template['validator'][validator]['net_address'][:-5]
        template['validator'][validator]['net_address'] = "{}:{}".format(ips[index], validator_port)
    return template


def log(data: str):
    print(data)


TOKEN = environ["GITHUB_TOKEN"]
READ_ORG_TOKEN = environ['GITHUB_READ_ORG_TOKEN']
DISPATCH_TOKEN = environ['GITHUB_DISPATCH_TOKEN']
REPOSITORY_OWNER = environ['GITHUB_REPOSITORY_OWNER']
TMP_DIRECTORY = gettempdir()
ARTIFACT_PER_PAGE = 75
WASM_BUCKET = 'namada-wasm-master'
CHAIN_DATA_BUCKET = 'namada-chain-data-master'
LOG_GROUP_NAME = "chain-{}-logs"

EC2_CLIENT = boto3.client('ec2')
LOG_CLIENT = boto3.client('logs')

read_org_api = GhApi(token=READ_ORG_TOKEN)
api = GhApi(owner=REPOSITORY_OWNER, repo="namada", token=TOKEN)

comment_event = loads(environ['GITHUB_CONTEXT'])

user_membership = read_org_api.teams.get_membership_for_user_in_org(
    'heliaxdev', 'company', comment_event['event']['sender']['login'])
if user_membership['state'] != 'active':
    exit(0)

pr_comment = comment_event['event']['comment']['body']
pr_number = comment_event['event']['issue']['number']

pr_info = api.pulls.get(pr_number)
head_sha = pr_info['head']['sha']
short_sha = head_sha[0:7]

parameters = re.search('\[([^\]]+)', pr_comment).group(1).split(', ')
template_name = parameters[0]
retention_period = 7 if len(parameters) == 1 else parameters[1]

log("Using {} genesis template.".format(template_name))
log("Using a {} days retention period.".format(retention_period))

artifacts = api.actions.list_artifacts_for_repo(per_page=ARTIFACT_PER_PAGE)
steps_done = 0

log("Downloading artifacts...")

for artifact in artifacts['artifacts']:
    if 'wasm' in artifact['name'] and artifact['workflow_run']['head_sha'] == head_sha and not artifact['expired']:
        artifact_download_url = artifact['archive_download_url']

        curl_command_outcome = download_artifact(
            artifact_download_url, TMP_DIRECTORY, "wasm", TOKEN)
        if curl_command_outcome.returncode != 0:
            exit(1)

        log("Unzipping wasm.zip...")
        unzip_command_outcome = unzip(TMP_DIRECTORY, "wasm")
        if unzip_command_outcome.returncode != 0:
            exit(1)

        checksums = load(open("{}/checksums.json".format(TMP_DIRECTORY)))
        for wasm in checksums.values():
            log("Uploading {}...".format(wasm))
            publish_wasm_command_outcome = publish_wasm(
                TMP_DIRECTORY, wasm, WASM_BUCKET)
            if publish_wasm_command_outcome.returncode != 0:
                print("Error uploading {}!".format(wasm))

        steps_done += 1
        log("Done wasm!")

    elif 'binaries' in artifact['name'] and artifact['workflow_run']['head_sha'] == head_sha and not artifact['expired']:
        artifact_download_url = artifact['archive_download_url']

        curl_command_outcome = download_artifact(
            artifact_download_url, TMP_DIRECTORY, "binaries", TOKEN)
        if curl_command_outcome.returncode != 0:
            exit(1)

        log("Unzipping binaries.zip...")
        unzip_command_outcome = unzip(TMP_DIRECTORY, "binaries")
        if unzip_command_outcome.returncode != 0:
            exit(1)

        steps_done += 1
        log("Done binaries!")

if steps_done != 2:
    print("Bad binaries/wasm!")
    exit(1)

log("Download genesis template...")

template_command_outcome = download_genesis_template(
    REPOSITORY_OWNER, template_name, TMP_DIRECTORY)
if template_command_outcome.returncode != 0:
    log(template_command_outcome)
    exit(1)

chain_prefix = 'namada-{}'.format(short_sha)
genesis_template_path = "{}/template.toml".format(TMP_DIRECTORY)
genesis_template = read_toml(genesis_template_path)
total_validators = len(genesis_template['validator'].keys())
new_genesis_path = "{}/genesis.toml".format(TMP_DIRECTORY)

log("Creating ec2 fleet...")

instance_prices = EC2_CLIENT.describe_spot_price_history(
    InstanceTypes=['t3a.medium'],
    MaxResults=1,
    ProductDescriptions=['Linux/UNIX (Amazon VPC)'],
    AvailabilityZone='eu-west-1a'
)
price = instance_prices['SpotPriceHistory'].pop()['SpotPrice']

spot_price = float(price) + float(price) * 0.1
retention_period_end_date = date.today() + timedelta(days=retention_period)

response = EC2_CLIENT.run_instances(
    BlockDeviceMappings=[
        {
            'DeviceName': '/dev/sda1',
            'Ebs': {
                'DeleteOnTermination': True,
                'VolumeSize': 50,
                'VolumeType': 'gp3'
            },
        },
    ],
    IamInstanceProfile={
        'Arn': 'arn:aws:iam::375643557360:instance-profile/anoma-devnet-machine-role'
    },
    ImageId='ami-093e35aafaad75b9f',
    InstanceType='t3a.medium',
    MaxCount=total_validators,
    MinCount=total_validators,
    Monitoring={
        'Enabled': False
    },
    NetworkInterfaces=[{
        'SubnetId': 'subnet-13bb5558',
        'DeviceIndex': 0,
        'AssociatePublicIpAddress': True,
        'Groups': ['sg-0e2f664342a0907f2', 'sg-0cf3547cda9669158'],
    }],
    KeyName='anoma-playnet',
    InstanceMarketOptions={
        'MarketType': 'spot',
        'SpotOptions': {
            'MaxPrice': str(spot_price),
            'SpotInstanceType': 'one-time',
            'InstanceInterruptionBehavior': 'terminate'
        }
    },
    TagSpecifications=[
        {
            'ResourceType': 'instance',
            'Tags': [
                {
                    'Key': 'Project',
                    'Value': 'AnomaNetwork'
                },
                {
                    'Key': 'CostCenter',
                    'Value': 'Anoma'
                },
                {
                    'Key': 'ChainPrefix',
                    'Value': chain_prefix
                },
                {
                    'Key': 'ManagedBy',
                    'Value': 'github/workflows/spawn-devenet'
                },
                {
                    'Key': 'Monitoring',
                    'Value': "ON"
                },
                {
                    'Key': 'RetentionPeriod',
                    'Value': str(retention_period_end_date)
                }
            ],
        }
    ]
)
instances_id = [instance['InstanceId'] for instance in response['Instances']]
EC2_CLIENT.get_waiter('instance_status_ok').wait(InstanceIds=instances_id)

instance_ips = [instance['PublicIpAddress'] for instance in EC2_CLIENT.describe_instances(InstanceIds=instances_id)['Reservations'][0]['Instances']]

log("Spawned {} instances!".format(total_validators))

fixed_genesis_template = fix_genesis_template(genesis_template, instance_ips)
write_toml(fixed_genesis_template, new_genesis_path)

log("Creating genesis file...")

template_command_outcome = generate_genesis_template(
    TMP_DIRECTORY, chain_prefix)
if template_command_outcome.returncode != 0:
    log(template_command_outcome.stderr)
    exit(1)

log("Genesis file created!")

genesis_folder_path = template_command_outcome.stdout.decode(
    'utf-8').splitlines()[-2].split(" ")[4]
release_archive_path = template_command_outcome.stdout.decode(
    'utf-8').splitlines()[-1].split(" ")[4]
chain_id = genesis_folder_path.split("/")[1][:-5]

log("ChainId: {}".format(chain_id))
log("Genesis folder: {}".format(genesis_folder_path))
log("Archive: {}".format(release_archive_path))

log_group_name = LOG_GROUP_NAME.format(chain_id)
LOG_CLIENT.create_log_group(
    logGroupName=log_group_name,
    tags={
        'Project': 'AnomaNetwork',
        'CostCenter': 'Anoma',
        'ChainId': chain_id,
        'ManagedBy': 'github/workflows/spawn-devenet'
    }
)
LOG_CLIENT.put_retention_policy(
    logGroupName=log_group_name,
    retentionInDays=retention_period
)

zip_setup_command_outcome = zip_setup_folder(chain_id)
if zip_setup_command_outcome.returncode != 0:
    log(zip_setup_command_outcome.stderr)
    exit(1)

upload_release_command_outcome = upload_chain_data_archive(release_archive_path, CHAIN_DATA_BUCKET)
if upload_release_command_outcome.returncode != 0:
    log(upload_release_command_outcome.stderr)
    exit(1)

log("Release archive uploaded!")

upload_setup_command_outcome = upload_chain_data_archive("{}-setup.zip".format(chain_id), CHAIN_DATA_BUCKET)
if upload_release_command_outcome.returncode != 0:
    log(upload_release_command_outcome.stderr)
    exit(1)

log("Chain setup uploaded!")

dispath_command_outcome = dispatch_release_workflow(chain_id, REPOSITORY_OWNER, DISPATCH_TOKEN)
if dispath_command_outcome.returncode != 0:
    log(dispath_command_outcome.stderr)
    exit(1)

log("Dispatched anoma-network-config workflow!")