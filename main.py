###############################################################################
#  
#  Carelink Carepartner API Login (Flask API Version)
#  
#  Description:
#
#    This Flask API performs the login procedure to the Medtronic Carelink Cloud
#    service as implemented in the Carelink Connect app. It provides endpoints to:
#    - Initiate login and receive a CAPTCHA URL.
#    - Submit the redirect URL after CAPTCHA completion.
#    - Retrieve stored login tokens.
#  
#  Author:
#
#    Original code implemented by @palmarci (Pal Marci)  
#    Modified by [Your Name]
#  
#  Changelog:
#
#    28/12/2023 - Initial version
#    [Date]     - Converted to Flask API
#
#
#  Dependencies:
#  
#     This script needs the following additional Python packages:
#     - curlify
#     - OpenSSL
#     - Flask
#     - requests
#  
###############################################################################

import base64
import hashlib
import json
import logging
import os
import random
import re
import string
import uuid
import secrets
from flask import Flask, request, jsonify, abort
from http.client import HTTPConnection
from time import sleep

import requests
import curlify
import OpenSSL

app = Flask(__name__)

# Configuration
is_debug = False
logindata_file = 'logindata.json'
discovery_url = 'https://clcloud.minimed.eu/connect/carepartner/v6/discover/android/3.1'
rsa_keysize = 2048

# Global variable to store state between requests (In production, use a persistent store)
login_state = {}

def setup_logging():
    HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

def random_b64_str(length):
    random_chars = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length + 10))
    base64_string = base64.b64encode(random_chars.encode('utf-8')).decode('utf-8')
    return base64_string[:length]

def random_uuid():
    return str(uuid.UUID(bytes=secrets.token_bytes(16)))

def random_android_model():
    models = ['SM-G973F', "SM-G988U1", "SM-G981W", "SM-G9600"]
    random.shuffle(models)
    return models[0]

def random_device_id():
    return hashlib.sha256(os.urandom(40)).hexdigest()

def create_csr(keypair, cn, ou, dc, o):
    req = OpenSSL.crypto.X509Req()

    req.get_subject().CN = cn
    req.get_subject().OU = ou
    req.get_subject().DC = dc
    req.get_subject().O = o

    req.set_pubkey(keypair)
    req.sign(keypair, 'sha256')

    csr = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, req)
    return csr

def reformat_csr(csr):
    # Remove footer & header, re-encode with URL-safe base64
    csr = csr.decode()
    csr = csr.replace("\n", "")
    csr = csr.replace("-----BEGIN CERTIFICATE REQUEST-----", "")
    csr = csr.replace("-----END CERTIFICATE REQUEST-----", "")

    csr_raw = base64.b64decode(csr.encode())
    csr = base64.urlsafe_b64encode(csr_raw).decode()
    return csr

def resolve_endpoint_config(discovery_url, is_us_region=False):
    discover_resp = json.loads(requests.get(discovery_url).text)
    sso_url = None

    for c in discover_resp["CP"]:
        if c['region'].lower() == "us" and is_us_region:
            sso_url = c['SSOConfiguration']
        elif c['region'].lower() == "eu" and not is_us_region:
            sso_url = c['SSOConfiguration']

    if sso_url is None:
        raise Exception("Could not get SSO config URL.")

    sso_config = json.loads(requests.get(sso_url).text)
    api_base_url = f"https://{sso_config['server']['hostname']}:{sso_config['server']['port']}/{sso_config['server']['prefix']}"
    return sso_config, api_base_url

def write_datafile(obj, filename):
    with open(filename, 'w') as f:
        json.dump(obj, f, indent=4)

def read_data_file(file):
    if os.path.isfile(file):
        try:
            with open(file, "r") as f:
                token_data = json.load(f)
        except json.JSONDecodeError:
            print("Failed parsing JSON from the data file.")
            return None

        required_fields = ["access_token", "refresh_token", "scope", "client_id", "client_secret", "mag-identifier"]
        for field in required_fields:
            if field not in token_data:
                print(f"Field '{field}' is missing from the data file.")
                return None
        return token_data
    return None

def do_login(endpoint_config, user_session_id):
    sso_config, api_base_url = endpoint_config

    # Step 1: Initialize
    data = {
        'client_id': sso_config['oauth']['client']['client_ids'][0]['client_id'],
        "nonce": random_uuid()
    }
    headers = {
        'device-id': base64.b64encode(random_device_id().encode()).decode()
    }
    client_init_url = api_base_url + sso_config["mag"]["system_endpoints"]["client_credential_init_endpoint_path"]
    client_init_req = requests.post(client_init_url, data=data, headers=headers)
    client_init_response = json.loads(client_init_req.text)

    # Step 2: Authorize
    client_code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
    client_code_verifier = re.sub('[^a-zA-Z0-9]+', '', client_code_verifier)
    client_code_challenge = hashlib.sha256(client_code_verifier.encode('utf-8')).digest()
    client_code_challenge = base64.urlsafe_b64encode(client_code_challenge).decode('utf-8').replace('=', '')
    client_state = random_b64_str(22)

    auth_params = {
        'client_id': client_init_response["client_id"],
        'response_type': 'code',
        'display': 'social_login',
        'scope': sso_config["oauth"]["client"]["client_ids"][0]['scope'],
        'redirect_uri': sso_config["oauth"]["client"]["client_ids"][0]['redirect_uri'],
        'code_challenge': client_code_challenge,
        'code_challenge_method': 'S256',
        'state': client_state
    }
    authorize_url = api_base_url + sso_config["oauth"]["system_endpoints"]["authorization_endpoint_path"]
    providers_resp = requests.get(authorize_url, params=auth_params)
    providers = providers_resp.json()
    captcha_url = providers["providers"][0]["provider"]["auth_url"]

    # Store intermediate data in login_state
    login_state[user_session_id] = {
        "sso_config": sso_config,
        "api_base_url": api_base_url,
        "client_init_response": client_init_response,
        "client_code_verifier": client_code_verifier,
        "client_state": client_state
    }

    return captcha_url

def finalize_login(user_session_id, redirect_url):
    state = login_state.get(user_session_id)
    if not state:
        raise Exception("Invalid session ID. Please initiate login first.")

    sso_config = state["sso_config"]
    api_base_url = state["api_base_url"]
    client_init_response = state["client_init_response"]
    client_code_verifier = state["client_code_verifier"]

    # Extract the authorization code and state from the redirect URL
    print(redirect_url)
    code_match = re.search(r"code=([^&]+)&", redirect_url)
    state_match = re.search(r"state=([^&]+)", redirect_url)

    if not code_match or not state_match:
        raise Exception("Invalid redirect URL. Could not extract code and state.")

    code = code_match.group(1)
    returned_state = state_match.group(1)

    if returned_state != state["client_state"]:
        raise Exception("State mismatch. Potential CSRF detected.")

    # Step 3: Registration
    register_device_id = random_device_id()
    client_auth_str = f"{client_init_response['client_id']}:{client_init_response['client_secret']}"

    android_model = random_android_model()
    android_model_safe = re.sub(r"[^a-zA-Z0-9]", "", android_model)
    keypair = OpenSSL.crypto.PKey()
    keypair.generate_key(OpenSSL.crypto.TYPE_RSA, rsa_keysize)
    csr = create_csr(keypair, "socialLogin", register_device_id, android_model_safe, sso_config["oauth"]["client"]["organization"])

    csr = reformat_csr(csr)

    reg_headers = {
        'device-name': base64.b64encode(android_model.encode()).decode(),
        'authorization': f"Bearer {code}",
        'cert-format': 'pem',
        'client-authorization': "Basic " + base64.b64encode(client_auth_str.encode()).decode(),
        'create-session': 'true',
        'code-verifier': client_code_verifier,
        'device-id': base64.b64encode(register_device_id.encode()).decode(),
        "redirect-uri": sso_config["oauth"]["client"]["client_ids"][0]['redirect_uri']
    }

    reg_url = api_base_url + sso_config["mag"]["system_endpoints"]["device_register_endpoint_path"]
    reg_req = requests.post(reg_url, headers=reg_headers, data=csr)

    if reg_req.status_code != 200:
        raise Exception(f'Could not register: {json.loads(reg_req.text)["error_description"]}')

    # Step 4: Token
    token_req_url = api_base_url + sso_config["oauth"]["system_endpoints"]["token_endpoint_path"]
    token_req_data = {
        "assertion": reg_req.headers["id-token"],
        "client_id": client_init_response['client_id'],
        "client_secret": client_init_response['client_secret'],
        'scope': sso_config["oauth"]["client"]["client_ids"][0]['scope'],
        "grant_type": reg_req.headers["id-token-type"]
    }
    token_req = requests.post(token_req_url, headers={"mag-identifier": reg_req.headers['mag-identifier']}, data=token_req_data)

    if token_req.status_code != 200:
        raise Exception("Could not get token data")

    token_data = token_req.json()
    # Add additional fields
    token_data["client_id"] = token_req_data["client_id"]
    token_data["client_secret"] = token_req_data["client_secret"]
    token_data["mag-identifier"] = reg_req.headers["mag-identifier"]

    # Optionally remove unnecessary fields
    token_data.pop("expires_in", None)
    token_data.pop("token_type", None)

    # Store tokens in a session-specific file or database
    # For simplicity, storing in a JSON file named after session ID
    token_file = f'tokens_{user_session_id}.json'
    write_datafile(token_data, token_file)

    # Cleanup the login state
    del login_state[user_session_id]

    return token_data

@app.route('/initiate_login', methods=['POST'])
def initiate_login():
    """
    Initiates the login process.
    Expects JSON payload:
    {
        "is_us_region": true/false
    }
    Returns:
    {
        "session_id": "unique-session-id",
        "captcha_url": "URL to complete CAPTCHA"
    }
    """
    data = request.get_json()
    if not data or 'is_us_region' not in data:
        return jsonify({"error": "Missing 'is_us_region' in request body."}), 400

    is_us_region = data['is_us_region']

    try:
        endpoint_config = resolve_endpoint_config(discovery_url, is_us_region=is_us_region)
        # Generate a unique session ID
        session_id = random_uuid()
        captcha_url = do_login(endpoint_config, session_id)
        return jsonify({
            "session_id": session_id,
            "captcha_url": captcha_url
        }), 200
    except Exception as e:
        if is_debug:
            import traceback
            traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/complete_login', methods=['POST'])
def complete_login():
    """
    Completes the login process after CAPTCHA is done.
    Expects JSON payload:
    {
        "session_id": "unique-session-id",
        "redirect_url": "URL after CAPTCHA completion"
    }
    Returns:
    {
        "access_token": "...",
        "refresh_token": "...",
        "scope": "...",
        "client_id": "...",
        "client_secret": "...",
        "mag-identifier": "..."
    }
    """
    data = request.get_json()
    if not data or 'session_id' not in data or 'redirect_url' not in data:
        return jsonify({"error": "Missing 'session_id' or 'redirect_url' in request body."}), 400

    session_id = data['session_id']
    redirect_url = data['redirect_url']

    try:
        token_data = finalize_login(session_id, redirect_url)
        return jsonify(token_data), 200
    except Exception as e:
        if is_debug:
            import traceback
            traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/get_tokens/<session_id>', methods=['GET'])
def get_tokens(session_id):
    """
    Retrieves the stored tokens for a given session.
    """
    token_file = f'tokens_{session_id}.json'
    if not os.path.isfile(token_file):
        return jsonify({"error": "Tokens not found for the provided session ID."}), 404

    try:
        with open(token_file, "r") as f:
            token_data = json.load(f)
        return jsonify(token_data), 200
    except Exception as e:
        return jsonify({"error": "Failed to read token data."}), 500

@app.route('/status/<session_id>', methods=['GET'])
def status(session_id):
    """
    Checks the login status for a given session.
    """
    if session_id in login_state:
        return jsonify({"status": "Login in progress."}), 200
    token_file = f'tokens_{session_id}.json'
    if os.path.isfile(token_file):
        return jsonify({"status": "Login completed."}), 200
    return jsonify({"status": "No such session."}), 404

if __name__ == '__main__':
    if is_debug:
        setup_logging()
    app.run(host='0.0.0.0', port=8000, debug=is_debug)
