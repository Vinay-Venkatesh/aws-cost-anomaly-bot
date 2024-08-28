import json
from slack_sdk.webhook import WebhookClient
import boto3
import base64
from botocore.exceptions import ClientError
import os

def get_secret():
    secret_name = os.environ['SLACK_WEBHOOK_URL']
    region_name = os.environ['REGION']

    # Create a secrets Manager client
    client = get_session("secretsmanager", region_name)

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return secret
        else:
            # If the string is binary encoded
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret


class Field:
    def __init__(self, type, text, emoji):
        self.type = type
        # text: text to be displayed
        self.text = text
        # emoji: boolean
        self.emoji = emoji


class Block:
    # def __init__(self, type,  text=None, fields=None):
    def __init__(self, type, **kwargs):
        self.type = type
        # fields: an array of fields in the section
        if kwargs.get("fields"):
            self.fields = kwargs.get("fields")
        if kwargs.get("text"):
            self.text = kwargs.get("text")


class Text:
    # def __init__(self, type, text, emoji):
    def __init__(self, type, text, **kwargs):
        self.type = type
        # text: text to be displayed
        self.text = text
        # emoji: boolean
        if kwargs.get("emoji"):
            self.emoji = kwargs.get("emoji")


def get_aws_account_name(account_id):
    # Function is used to fetch account name corresponding to an account number. The account name is used to display in the Slack notification.
    print("Fetching Account Name corresponding to accountId:" + account_id)

    # Initialise Organisations
    client = get_session("organizations", "us-west-2")

    # Call describe_account in order to return the account_id corresponding to the account_number.
    response = client.describe_account(AccountId=account_id)

    accountName = response["Account"]["Name"]
    print("Fetching Account Name complete. Account Name:" + accountName)

    # Return the Account Name corresponding the Input Account ID.
    return response["Account"]["Name"]


def lambda_handler(event, context):
    print(json.dumps(event))

    print("Retrieve Slack URL from Secrets Manager")

    slack_url = json.loads(get_secret())["slack-webhook-url"]

    print("Slack Webhook URL retrieved")

    print("Initialise Slack Webhook Client")

    webhook = WebhookClient(slack_url)

    print("Decoding the SNS Message")
    anomalyEvent = json.loads(event["Records"][0]["Sns"]["Message"])

    # Total Cost of the Anomaly
    totalcostImpact = anomalyEvent["impact"]["totalImpact"]

    # Anomaly Detection Interval
    anomalyStartDate = anomalyEvent["anomalyStartDate"]
    anomalyEndDate = anomalyEvent["anomalyEndDate"]

    # anomalyDetailsLink
    anomalyDetailsLink = anomalyEvent["anomalyDetailsLink"]

    # Blocks is the main array that holds the full message for slack.
    blocks = []

    headerText = Text("plain_text", ":warning: Cost Anomaly Detected ", emoji=True)
    totalAnomalyCostText = Text("mrkdwn", "*Total Anomaly Cost*: $" + str(totalcostImpact))
    rootCausesHeaderText = Text("mrkdwn", "*Root Causes* :mag:")
    anomalyStartDateText = Text("mrkdwn", "*Anomaly Start Date*: " + str(anomalyStartDate))
    anomalyEndDateText = Text("mrkdwn", "*Anomaly End Date*: " + str(anomalyEndDate))
    anomalyDetailsLinkText = Text("mrkdwn", "*Anomaly Details Link*: " + str(anomalyDetailsLink))

    # Second, Start appending the 'blocks' object with the header, totalAnomalyCost and rootCausesHeaderText
    blocks.append(Block("header", text=headerText.__dict__))
    blocks.append(Block("section", text=totalAnomalyCostText.__dict__))
    blocks.append(Block("section", text=anomalyStartDateText.__dict__))
    blocks.append(Block("section", text=anomalyEndDateText.__dict__))
    blocks.append(Block("section", text=anomalyDetailsLinkText.__dict__))
    blocks.append(Block("section", text=rootCausesHeaderText.__dict__))

    # iterate through all possible root causes in the Anomaly Event and append the blocks as well as fields objects.
    for rootCause in anomalyEvent["rootCauses"]:
        fields = []
        for rootCauseAttribute in rootCause:
            fields.append(Field("plain_text", rootCauseAttribute + " : " + rootCause[rootCauseAttribute], False))
        blocks.append(Block("section", fields=[ob.__dict__ for ob in fields]))

    # Finally, send the message to the Slack Webhook.
    response = webhook.send(
        text=anomalyEvent,
        blocks=json.dumps([ob.__dict__ for ob in blocks])
    )

    print(str(json.dumps(response.body)))
    assert response.status_code == 200
    assert response.body == "ok"

    return {
        'statusCode': 200,
        'responseMessage': 'Posted to Slack Channel Successfully'
    }


def get_session(resource, region_name):
    session = boto3.session.Session()
    return session.client(
        service_name=resource,
        region_name=region_name
    )