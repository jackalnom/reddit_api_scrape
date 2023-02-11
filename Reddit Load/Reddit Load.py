import requests
import json
import boto3
from datetime import datetime
from botocore.exceptions import ClientError

def get_reddit_secrets(session):
    secret_name = "reddit_auth_secrets"
    region_name = "us-west-2"

    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    # Decrypts secret using the associated KMS key.
    return json.loads(get_secret_value_response['SecretString'])

def auth_reddit(reddit_secrets):
    # Building request to reddit API
    auth = requests.auth.HTTPBasicAuth(reddit_secrets['reddit_auth_token'], reddit_secrets['reddit_auth_secret'])

    data = {'grant_type': 'password',
            'username': reddit_secrets['reddit_username'],
            'password': reddit_secrets['reddit_password']}

    headers = {'User-Agent': 'RedditParserBot/0.0.1'}

    res = requests.post('https://www.reddit.com/api/v1/access_token',
                        auth=auth, data=data, headers=headers)

    TOKEN = res.json()['access_token']

    # add authorization to our headers dictionary
    headers = {**headers, **{'Authorization': f"bearer {TOKEN}"}}

    # while the token is valid (~2 hours) we just add headers=headers to our requests
    requests.get('https://oauth.reddit.com/api/v1/me', headers=headers)

    return headers

def print_reddit_json(res):
    json_res = res.json()

    # Example parsing we can do of the structure json structure.
    posts = json_res['data']['children']
    for post in posts:
        post_data = post['data']

        title = post_data['title']
        user = post_data['author_fullname']
        upvote_ratio = post_data['upvote_ratio']

        print(f"{title} by {user}: {upvote_ratio}")

def write_json_to_s3_with_timestamp(session, body):
    # Creating S3 Resource From the Session.
    s3 = session.resource('s3')

    now = datetime.now()  # current date and time

    date_time = now.strftime("%m-%d-%Y, %H:%M:%S")
    print("date and time:", date_time)

    object = s3.Object('reddit-dataisbeautiful-top', f"{date_time}.json")

    # We will just save the entire raw json response into S3.
    result = object.put(Body=body)


# Initialize our AWS Session
session = boto3.Session()

headers = auth_reddit(get_reddit_secrets(session))

res = requests.get("https://oauth.reddit.com/r/dataisbeautiful/top", headers=headers)
# just for example debugging purposes, let's print out the json in a pretty way. This functionally does nothing
# for the script though.
print_reddit_json(res)

write_json_to_s3_with_timestamp(session, res.text)
