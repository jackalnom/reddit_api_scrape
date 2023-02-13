import requests
import json
import boto3
from datetime import datetime
from botocore.exceptions import ClientError
import pandas as pd

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

def clean_data(res):
    json_res = res.json()
    cleaned = []

    # Example parsing we can do of the structure json structure.
    posts = json_res['data']['children']
    for post in posts:
        post_data = post['data']

        title = post_data['title']
        author = post_data['author']
        score = post_data['score']
        permalink = post_data['permalink']

        cleaned.append([title, author, score, permalink])

    return pd.DataFrame(cleaned, columns=['title', 'author', 'score', 'permalink'])

def write_to_s3_with_timestamp(session, postfix, body, ext):
    # Creating S3 Resource From the Session.
    s3 = session.resource('s3')

    now = datetime.now()  # current date and time

    date_time = now.strftime("%Y-%m-%d %H:%M:%S")

    object = s3.Object('reddit-dataisbeautiful-top', f"{date_time} - {postfix} .{ext}")

    # We will just save the entire raw json response into S3.
    result = object.put(Body=body)

# Initialize our AWS Session
session = boto3.Session()

headers = auth_reddit(get_reddit_secrets(session))

res = requests.get("https://oauth.reddit.com/r/dataisbeautiful/top", headers=headers)
# Print out raw for later debugging or if we want to re-process data
write_to_s3_with_timestamp(session, "raw", res.text, "json")

# Print out cleaned data. Can ingest with a notebook or into a database from here.
cleaned_data = clean_data(res)
write_to_s3_with_timestamp(session, "clean", cleaned_data.to_csv(), "csv")
