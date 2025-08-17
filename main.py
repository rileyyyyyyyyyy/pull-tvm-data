import os
import requests
from dotenv import load_dotenv
import csv

load_dotenv()

TENANT_ID = os.getenv('TENANT_ID')
APP_ID = os.getenv('APP_ID')
APP_SECRET = os.getenv('APP_SECRET')


class Requestor:
    def __init__(self, tenant_id, app_id, app_secret):
        self._token_url = 'https://login.microsoftonline.com/%s/oauth2/token' % (tenant_id)
        self._resource_app_id_uri = 'https://api.securitycenter.microsoft.com'
        self._body = {
            'resource': RESOURCE_APP_ID_URI,
            'client_id': APP_ID,
            'client_secret': APP_SECRET,
            'grant_type': 'client_credentials'
        }
        self._aad_token = None
        
    def open_session(self):
        return requests.Session()
    
    def _get_token(self, session):
        request = session.get(url=url, data=body)
        data = request.json()
        
        self._aad_token = data['access_token']

        session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': f'Bearer {self._aad_token}'
        })

    def request_data(self, session):
        if self.__aad_token is None:
            self._get_token(session)
        
        all_rows = []
        url = 'https://api.securitycenter.microsoft.com/api/vulnerabilities'
        
        while url:
            response = session.get(url, timeout=120)
            response.raise_for_status()
            data = response.json()
            rows = data.get('value', [])
            all_rows.extend(rows)

            next_link = data.get('@odata.nextLink')
            if next_link:
                url = next_link
            else:
                url = None

        fieldnames = all_rows[0].keys()
        
        with open('output.csv', 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(all_rows)

        print(f'{len(all_rows)} rows written to output.csv')



requestor = Requestor(TENANT_ID, APP_ID, APP_SECRET)

with requestor.open_session() as s:
    requestor.request_data(s)
    
