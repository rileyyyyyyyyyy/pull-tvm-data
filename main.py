import os
import requests
from dotenv import load_dotenv
import csv


class Requestor:
    def __init__(self, tenant_id, app_id, app_secret):
        self._tenant_id = tenant_id
        self._app_id = app_id
        self._app_secret = app_secret
        self._token_url = 'https://login.microsoftonline.com/%s/oauth2/token' % (self._tenant_id)
        self._resource_app_id_uri = 'https://api.securitycenter.microsoft.com'
        self._body = {
            'resource': self._resource_app_id_uri,
            'client_id': self._app_id,
            'client_secret': self._app_secret,
            'grant_type': 'client_credentials'
        }
        self._aad_token = None
        
    def open_session(self):
        return requests.Session()
    
    def _get_token(self, session):
        request = session.get(url=self._token_url, data=self._body)
        data = request.json()
        
        self._aad_token = data['access_token']

        session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': f'Bearer {self._aad_token}'
        })

    def request_data(self, session, url):
        if self._aad_token is None:
            self._get_token(session)
        
        all_rows = []        
        
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


def main():
    load_dotenv()
    
    TENANT_ID = os.getenv('TENANT_ID')
    APP_ID = os.getenv('APP_ID')
    APP_SECRET = os.getenv('APP_SECRET')
    
    requestor = Requestor(TENANT_ID, APP_ID, APP_SECRET)

    with requestor.open_session() as s:
        requestor.request_data(
            s,
            'https://api.securitycenter.microsoft.com/api/vulnerabilities'
        )
    
if __name__ == '__main__':
    main()
