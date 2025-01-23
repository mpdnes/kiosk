# utils/snipe_it_api.py

import requests
import logging
from flask import current_app

logger = logging.getLogger(__name__)

def get_api_headers():
    return {
        'Authorization': f'Bearer {current_app.config["API_TOKEN"]}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

def get_user_info(employee_num):
    """Fetches the user information from Snipe-IT using the employee number."""
    api_url = current_app.config['API_URL']
    headers = get_api_headers()
    params = {'search': employee_num}  # Use 'search' with 'employee_num'

    try:
        response = requests.get(f"{api_url}/users", headers=headers, params=params, verify=False)
        response.raise_for_status()
        
        # Use logger for output instead of print
        logger.debug(f"Snipe-IT API Response: {response.json()}")
        
        data = response.json()
        
        # Check if there are any matching users
        if 'rows' in data and len(data['rows']) > 0:
            logger.debug(f"Found user with employee number: {employee_num}")
            return data['rows'][0]  # Return the first matching user
        else:
            logger.warning(f"No user found for employee number: {employee_num}")
            return None
    except requests.RequestException as e:
        logger.error(f"Error fetching user info: {e}")
        return None


def handle_user_signin(barcode_data):
    """Handles user sign-in by scanning a barcode."""
    user_info = get_user_info(employee_num=barcode_data)
    if user_info:
        return {'id': user_info['id'], 'name': user_info['name'], 'employee_num': user_info['employee_num']}
    else:
        return {'error': "Failed to sign in. User not found."}

def extract_asset_id_from_barcode(barcode_data):
    """Extracts the asset ID from the barcode data."""
    # Assuming the barcode_data is the asset tag or serial number
    return barcode_data

def get_asset_info(asset_identifier):
    """Fetches the asset information from Snipe-IT."""
    api_url = current_app.config['API_URL']
    headers = get_api_headers()
    params = {'search': asset_identifier}

    try:
        response = requests.get(f"{api_url}/hardware", headers=headers, params=params, verify=False)
        response.raise_for_status()
        data = response.json()
        if 'rows' in data and len(data['rows']) > 0:
            return data['rows'][0]
        else:
            return None
    except requests.RequestException as e:
        logger.error(f"Error fetching asset info: {e}")
        return None

def is_asset_checked_out(asset_info):
    """Checks if the asset is currently checked out."""
    return asset_info['status_label']['status_meta'] == 'deployed'

def is_asset_assigned_to_user(asset_info, user_id):
    """Checks if the asset is currently assigned to the given user."""
    assigned_user = asset_info.get('assigned_to')
    if assigned_user and assigned_user.get('id') == user_id:
        return True
    else:
        return False

def checkout_asset(barcode_data, user_id):
    """Handles asset checkout."""
    api_url = current_app.config['API_URL']
    headers = get_api_headers()
    asset_id = extract_asset_id_from_barcode(barcode_data)
    
    # Check if asset exists and is available
    asset_info = get_asset_info(asset_id)
    if not asset_info:
        return {'error': "Asset not found."}

    if is_asset_checked_out(asset_info):
        return {'error': "Asset is already checked out or not available for checkout."}

    payload = {
        "checkout_to_type": "user",
        "assigned_user": user_id,
        "status_id": 2  # Adjust status ID as per your Snipe-IT configuration
    }

    checkout_url = f"{api_url}/hardware/{asset_info['id']}/checkout"

    try:
        response = requests.post(checkout_url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        return {'message': "Asset checked out successfully."}
    except requests.RequestException as e:
        logger.error(f"Failed to check out asset: {e}")
        return {'error': f"Failed to check out asset: {e}"}

def checkin_asset(barcode_data, user_id):
    """Handles asset check-in."""
    api_url = current_app.config['API_URL']
    headers = get_api_headers()
    asset_id = extract_asset_id_from_barcode(barcode_data)
    
    # Check if asset exists and is assigned to the user
    asset_info = get_asset_info(asset_id)
    if not asset_info:
        return {'error': "Asset not found."}

    if not is_asset_assigned_to_user(asset_info, user_id):
        return {'error': "You cannot check in an asset that is not assigned to you."}

    payload = {
        "status_id": 1,  # Adjust status ID for 'Ready to Deploy' or similar
        "note": "Checked in via kiosk"
    }

    checkin_url = f"{api_url}/hardware/{asset_info['id']}/checkin"

    try:
        response = requests.post(checkin_url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        return {'message': "Asset checked in successfully."}
    except requests.RequestException as e:
        logger.error(f"Failed to check in asset: {e}")
        return {'error': f"Failed to check in asset: {e}"}

def get_user_assigned_assets(user_id):
    """Fetch all assets assigned to a user from Snipe-IT."""
    api_url = current_app.config['API_URL']
    headers = get_api_headers()
    params = {'assigned_user': user_id}

    try:
        response = requests.get(f"{api_url}/hardware", headers=headers, params=params, verify=False)
        response.raise_for_status()
        data = response.json()
        return data.get('rows', [])
    except requests.RequestException as e:
        logger.error(f"Error fetching assets for user {user_id}: {e}")
        return []
