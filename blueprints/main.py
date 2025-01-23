from flask import Blueprint, render_template, jsonify, request, session, redirect, url_for
import logging
import cv2
import base64
import numpy as np
from pyzbar.pyzbar import decode
from utils.snipe_it_api import (
    handle_user_signin,
    checkout_asset,
    checkin_asset,
    get_asset_info,
    is_asset_assigned_to_user,
    get_user_assigned_assets
)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

main_bp = Blueprint('main_bp', __name__)
logger = logging.getLogger(__name__)

@main_bp.route('/')
def home():
    logger.debug('Landing page accessed.')
    return render_template('landing.html')

@main_bp.route('/sign-in')
def sign_in():
    if 'user_id' in session:
        return redirect(url_for('main_bp.dashboard'))
    return render_template('sign_in.html')


@main_bp.route('/asset-info/<barcode>', methods=['GET'])
def asset_info_route(barcode):
    if 'user_id' not in session:
        logger.warning('Unauthorized access to asset info route.')
        return jsonify({'success': False, 'error': 'Unauthorized access.'}), 401

    logger.debug(f"Fetching asset info for barcode: {barcode}")
    result = get_asset_info(barcode)

    if not result:
        logger.error('Asset not found.')
        return jsonify({'success': False, 'error': 'Asset not found.'})

    logger.info(f"Asset info retrieved: {result}")
    return jsonify({'success': True, 'data': result})

@main_bp.route('/checkin', methods=['POST'])
def checkin_asset_route():
    if 'user_id' not in session:
        logger.warning('Unauthorized access to checkin route.')
        return jsonify({'success': False, 'error': 'Unauthorized access.'}), 401

    data = request.get_json()
    if not data or 'barcode' not in data:
        logger.error('No barcode provided for checkin.')
        return jsonify({'success': False, 'error': 'No barcode provided.'})

    barcode = data['barcode']
    user_id = session['user_id']
    logger.debug(f"User {user_id} attempting to check in asset with barcode: {barcode}")

    result = checkin_asset(barcode, user_id)
    if 'error' in result:
        logger.error(f"Checkin failed: {result['error']}")
        return jsonify({'success': False, 'error': result['error']})

    logger.info(f"Asset checked in successfully: {result}")
    return jsonify({'success': True, 'message': 'Asset checked in successfully.', 'data': result})

@main_bp.route('/checkout', methods=['POST'])
def checkout_asset_route():
    if 'user_id' not in session:
        logger.warning('Unauthorized access to checkout route.')
        return jsonify({'success': False, 'error': 'Unauthorized access.'}), 401

    data = request.get_json()
    if not data or 'barcode' not in data:
        logger.error('No barcode provided for checkout.')
        return jsonify({'success': False, 'error': 'No barcode provided.'})

    barcode = data['barcode']
    user_id = session['user_id']
    logger.debug(f"User {user_id} attempting to check out asset with barcode: {barcode}")

    result = checkout_asset(barcode, user_id)
    if 'error' in result:
        logger.error(f"Checkout failed: {result['error']}")
        return jsonify({'success': False, 'error': result['error']})

    logger.info(f"Asset checked out successfully: {result}")
    return jsonify({'success': True, 'message': 'Asset checked out successfully.', 'data': result})


@main_bp.route('/process_image', methods=['POST'])
def process_image():
    logger.debug('Processing image from client.')

    # Parse JSON payload
    data = request.get_json()
    if not data or 'image' not in data:
        logger.error('No image data received.')
        return jsonify({'success': False, 'error': 'No image data received.'})

    # Decode the base64 image
    try:
        image_data = data['image'].split(',')[1]  # Remove the 'data:image/jpeg;base64,' prefix
        image_bytes = base64.b64decode(image_data)
        np_arr = np.frombuffer(image_bytes, np.uint8)
        frame = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

        if frame is None:
            logger.error('Failed to decode the image.')
            return jsonify({'success': False, 'error': 'Failed to decode the image. Please try again.'})
    except Exception as e:
        logger.error(f"Error processing image data: {e}")
        return jsonify({'success': False, 'error': 'Invalid image data. Please try again.'})

    logger.debug('Image successfully decoded.')

    # Retry mechanism for barcode detection
    barcodes = None
    for attempt in range(3):  # Retry up to 3 times
        barcodes = decode(frame)
        if barcodes:
            logger.debug(f"Barcode(s) detected on attempt {attempt + 1}: {[b.data.decode('utf-8') for b in barcodes]}")
            break
        logger.warning(f"No barcode detected on attempt {attempt + 1}. Retrying...")

    if not barcodes:
        logger.warning('No barcode found in the image after retries.')
        return jsonify({'success': False, 'error': 'No barcode found in the image. Please ensure the barcode is visible and try again.'})

    # Process the first detected barcode
    barcode_data = barcodes[0].data.decode('utf-8')
    logger.debug(f'Processing barcode: {barcode_data}')

    # Simulate user authentication
    try:
        user_info = handle_user_signin(barcode_data)  # Verify barcode with backend logic
        if user_info.get('error'):
            logger.error(f"Sign-in failed for barcode {barcode_data}: {user_info['error']}")
            return jsonify({'success': False, 'error': user_info['error']})

        # Save user session
        session['user_id'] = user_info['id']
        session['user_name'] = user_info['name']
        logger.info(f"User signed in: {user_info['name']} (ID: {user_info['id']})")

        return jsonify({
            'success': True,
            'message': f"Welcome, {user_info['name']}!",
            'redirect': url_for('main_bp.dashboard')
        })
    except Exception as e:
        logger.error(f"Unexpected error during sign-in: {e}")
        return jsonify({'success': False, 'error': 'An unexpected error occurred during sign-in. Please try again.'})

@main_bp.route('/dashboard')
def dashboard():
    logger.debug(f"Session Data at Dashboard: {dict(session)}")
    if 'user_name' not in session:
        return redirect(url_for('main_bp.sign_in'))

    user_id = session['user_id']
    assigned_assets = get_user_assigned_assets(user_id)  # Add this function in your Snipe-IT API utility

    return render_template(
        'dashboard.html',
        user_name=session.get('user_name', 'Unknown'),
        assigned_assets=assigned_assets
    )

@main_bp.route('/checkin-page')
def checkin_page():
    if 'user_id' not in session:
        return redirect(url_for('main_bp.sign_in'))
    return render_template('checkin.html')

@main_bp.route('/checkout-page')
def checkout_page():
    if 'user_id' not in session:
        return redirect(url_for('main_bp.sign_in'))
    return render_template('checkout.html')

@main_bp.route('/asset-info-page')
def asset_info_page():
    if 'user_id' not in session:
        return redirect(url_for('main_bp.sign_in'))
    return render_template('asset_info.html')

@main_bp.route('/logout')
def logout():
    logger.info(f"User logged out: {session.get('user_name')}")
    session.clear()
    return redirect(url_for('main_bp.sign_in'))
