import hmac
import hashlib
import time
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/verify-keys', methods=['POST'])
def verify_keys():
    data = request.get_json()
    api_key = data.get('apiKey')
    api_secret = data.get('apiSecret')

    if not api_key or not api_secret:
        return jsonify({'success': False, 'message': 'Missing API Key or Secret'}), 400

    try:
        timestamp = int(time.time() * 1000)
        
        # Construct query string with apiKey and timestamp
        query_string = f'apiKey={api_key}&timestamp={timestamp}'

        # Generate the signature using apiSecret
        signature = hmac.new(
            api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        # Construct the full API URL with the signature
        url = f'https://api.mexc.com/api/v3/account?{query_string}&signature={signature}'
        
        # Include apiKey in the headers for authentication
        headers = {
            'X-MEXC-APIKEY': api_key
        }

        # Send the GET request to MEXC
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            if response.json().get('code') == 200:  # Assuming MEXC returns 'code' for success
                return jsonify({'success': True, 'message': 'MEXC keys are valid.'}), 200
            else:
                return jsonify({
                    'success': False,
                    'message': f'MEXC key validation failed: {response.json()}'
                }), 400
        else:
            return jsonify({
                'success': False,
                'message': f'MEXC key validation failed. Status: {response.status_code}',
                'response': response.json()
            }), response.status_code

    except requests.exceptions.RequestException as e:
        return jsonify({'success': False, 'message': 'Network error: ' + str(e)}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': 'Unexpected error: ' + str(e)}), 500
if __name__ == "__main__":
    handler = VercelHandler(app)
    handler.run()
