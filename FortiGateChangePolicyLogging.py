import requests
import argparse
from getpass import getpass

# Disable warnings for SSL Certificate for simplicity in this script
requests.packages.urllib3.disable_warnings()

def authenticate(api_url, username, password):
    """Authenticate and obtain an API token."""
    auth_url = f"{api_url}/logincheck"
    session = requests.session()
    response = session.post(auth_url, data={'username': username, 'secretkey': password}, verify=False)
    
    if "Set-Cookie" in response.headers:
        session.headers['X-CSRFTOKEN'] = session.cookies.get('ccsrftoken').replace('"', '')
        return session
    else:
        raise ValueError("Authentication failed, check your credentials.")

def get_vdoms(session, api_url):
    """Retrieve a list of VDOMs."""
    response = session.get(f"{api_url}/api/v2/cmdb/system/vdom", verify=False)
    return response.json()['results']

def get_policies(session, api_url, vdom):
    """Retrieve policies for a given VDOM."""
    response = session.get(f"{api_url}/api/v2/cmdb/firewall/policy", params={'vdom': vdom}, verify=False)
    return response.json()['results']

def enable_logging(session, api_url, vdom, policy_id):
    """Enable logging on a specific policy."""
    url = f"{api_url}/api/v2/cmdb/firewall/policy/{policy_id}"
    data = {"logtraffic": "all"}
    session.put(url, json=data, params={'vdom': vdom}, verify=False)

def main(api_url, username, password):
    session = authenticate(api_url, username, password)
    
    vdoms = get_vdoms(session, api_url)
    for vdom in vdoms:
        policies = get_policies(session, api_url, vdom['name'])
        for policy in policies:
            enable_logging(session, api_url, vdom['name'], policy['policyid'])
            print(f"Enabled logging on policy {policy['policyid']} in VDOM {vdom['name']}.")

    # Logout
    session.get(f"{api_url}/logout", verify=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enable logging on all policies across VDOMs on a FortiGate device.")
    parser.add_argument("ip", help="FortiGate IP address")
    parser.add_argument("username", help="Username for FortiGate device")
    args = parser.parse_args()

    password = getpass("Password for FortiGate device: ")

    main(f"https://{args.ip}", args.username, password)
