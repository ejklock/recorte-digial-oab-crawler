import pickle
import os.path
import base64
import re
import json
from google.oauth2 import credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from email.parser import BytesParser
from bs4 import BeautifulSoup
from email.policy import default

# Se modificar esses SCOPES, exclua o arquivo token.pickle.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def clean(text):
    return text.strip()

def clean_text(text):
    cleaned_text = re.sub(r'\xa0|\u200b', ' ', text).strip()
    return cleaned_text

def get_gmail_service():
    creds = None
    # O arquivo token.pickle armazena os tokens de acesso e atualização do usuário e é
    # criado automaticamente quando a autorização é concluída pela primeira vez.
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # Se não houver credenciais válidas disponíveis, solicite ao usuário que efetue login.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Salve as credenciais para a próxima execução
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    return build('gmail', 'v1', credentials=creds)


def extract_advogados(descricao):
    advogados = re.findall(r"ADVOGADO:\s*(.*?)\s*- OAB:", descricao)
    return ', '.join(advogados)

def extract_polo_ativo(descricao):
    match = re.search(r"POLO ATIVO:(.*?)(?:ADVOGADO:|$)", descricao, re.DOTALL)
    return clean_text(match.group(1).strip()) if match else ""

def extract_numero_processo(descricao):
    match = re.search(r"PROCESSO:\s*([\d.-]+)", descricao)
    return match.group(1).strip() if match else ""


def extract_data_from_email_string(email_data):
    publications = []
    publication = {}

    def process_text(text):
        nonlocal publication
        lines = text.splitlines()
        current_header = None
        capturing_description = False
        description = []

        for line in lines:
            if line.strip():
                if capturing_description:
                    if match := re.match(r"Publicação:\s*(.*)", line):
                        publication["descricao"] = " ".join(description)
                        publication["numero_processo"] = extract_numero_processo(publication["descricao"])
                        publication["polo_ativo"] = extract_polo_ativo(publication["descricao"])
                        publication["advogados"] = extract_advogados(publication["descricao"])
                        publications.append(publication)
                        publication = {}
                        publication["publicacao"] = match.group(1).strip()
                        description = []
                        capturing_description = False
                    else:
                        description.append(line)
                elif current_header:
                    publication[current_header] = clean_text(line)
                    if current_header == "página":
                        capturing_description = True
                    current_header = None
                elif match := re.match(r"Publicação:\s*(.*)", line):
                    if publication:
                        publications.append(publication)
                        publication = {}
                    publication["publicacao"] = match.group(1).strip()
                elif match := re.search(r"(Data de Disponibilização|Data de Publicação|Jornal|Caderno|Local|Página|PROCESSO|POLO ATIVO):", line):
                    current_header = match.group(1).lower().replace(" ", "_")

        if publication:
            if description:
                publication["descricao"] = " ".join(description)
            publications.append(publication)

    payload = email_data['payload']

    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/html':
                data = part['body']['data']
                charset = part.get('headers', {}).get('charset', 'utf-8')
                html = base64.urlsafe_b64decode(data).decode(charset)
                soup = BeautifulSoup(html, 'html.parser')
                text = soup.get_text('\n')
                process_text(text)
    else:
        # Se não houver "parts", extraia o texto diretamente do "body"
        data = payload['body']['data']
        html = base64.urlsafe_b64decode(data).decode('utf-8')
        soup = BeautifulSoup(html, 'html.parser')
        text = soup.get_text('\n')
        process_text(text)

    return publications


def extract_html_from_email_string(email_body):
    email_bytes = base64.urlsafe_b64decode(email_body)
    email_message = BytesParser(policy=default).parsebytes(email_bytes)

    html = ""
    if email_message.is_multipart():
        for part in email_message.walk():
            if part.get_content_type() == "text/html":
                html += str(part.get_payload(decode=True), 'utf-8')
    else:
        if email_message.get_content_type() == "text/html":
            html += str(email_message.get_payload(decode=True), 'utf-8')
    
    return html

def get_emails_from(sender, start_date):
    
    service = get_gmail_service()
    emails = []

    query = f"from:{sender} after:{start_date}"
    result = service.users().messages().list(userId='me', q=query).execute()
    print(result)
    messages = result.get('messages', [])
    
    for message in messages:
        
        msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
        payload = msg['payload']

        parts = payload.get('parts')
        
        if not parts:
            body = payload.get('body')
            data = body.get('data')
            html = base64.urlsafe_b64decode(data).decode('utf-8')
            msgstr = BeautifulSoup(html,'html.parser').get_text()
            emails.append(msg)
       
    
    return emails

def main():
    sender = 'mailer@setec.ufmt.br>'  # Insira o endereço de e-mail do remetente aqui
    start_date = '2023-03-27'        # Insira a data a partir da qual você deseja obter e-mails

    email_strings = get_emails_from(sender, start_date)
    print(email_strings)
    for email_string in email_strings:
        extracted_data = extract_data_from_email_string(email_string)
        
        print(json.dumps(extracted_data, indent=2, ensure_ascii=False))

if __name__ == '__main__':
    main()
