import os
import requests
import sys
from dotenv import load_dotenv
import json
import csv


load_dotenv()


TENANT_ID = os.getenv('TENANT_ID')
APP_ID = os.getenv('APP_ID')
APP_SECRET = os.getenv('APP_SECRET')

url = 'https://login.microsoftonline.com/%s/oauth2/token' % (TENANT_ID)

RESOURCE_APP_ID_URI = 'https://api.securitycenter.microsoft.com'

body = {
    'resource': RESOURCE_APP_ID_URI,
    'client_id': APP_ID,
    'client_secret': APP_SECRET,
    'grant_type': 'client_credentials'
}

with requests.Session() as s:
    r = s.get(url=url, data=body)
    data = r.json()
    
    AAD_TOKEN = data['access_token']

    s.headers.update({
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'Bearer {AAD_TOKEN}'
    })

    all_rows = []
    url = 'https://api.securitycenter.microsoft.com/api/vulnerabilities'
    
    while url:
        r = s.get(url, timeout=120)
        r.raise_for_status()
        data = r.json()
        rows = data.get('value', [])
        all_rows.extend(rows)

        next_link = data.get('@odata.nextLink')
        if next_link:
            url = next_link
        else:
            url = None

    fieldnames = sorted({k for row in all_rows for k in row.keys()})
    with open('vulnerabilities.csv', 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(all_rows)

    print(f'{len(all_rows)} rows written to vulnerabilities.csv')



