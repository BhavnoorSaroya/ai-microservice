from flask import Flask, request, jsonify, send_file
from ultralytics import YOLO
import cv2
import numpy as np
from io import BytesIO
from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64
import jwt
import requests
private_key = None
public_key = None

if private_key is None:
    with open('private.pem', 'r') as f:
        private_key = f.read()
if public_key is None:
    with open('public.pem', 'r') as f:
        public_key = f.read()
        
FRONTEND_URL = 'https://isa-singh.azurewebsites.net'
# USER_SERVICE_URL = 'http://localhost:5001'
USER_SERVICE_URL = 'https://isa-database-microservice.onrender.com'
SIGNATURE_KEY = serialization.load_pem_public_key(public_key.encode('utf-8'))
SIGNER_KEY = serialization.load_pem_private_key(private_key.encode('utf-8'), password=None)# Utility function to create a JWT token using RS256

# Initialize the Flask app and YOLOv8 model
app = Flask(__name__)
model = YOLO('yolov8n.pt')  # Ensure you have the YOLOv8n weights available



def create_signature(payload, private_key):
    # Create a new SHA-256 hash of the payload
    h = payload.encode('utf-8')
    
    # Create a signer with the private key
    # signer = PKCS1_v1_5.new(private_key)
    signature = private_key.sign(
            h, 
            padding.PKCS1v15(),
            hashes.SHA256()
    )
    
    # Sign the payload
    # signature = signer.sign(h)
    
    # Return the base64-encoded signature
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(payload, signature):
    return True # For now, always return True to bypass signature verification
    """
    Verifies the signature of the given payload using the public key.

    :param payload: The original payload as a string.
    :param signature: The signature to verify, base64-encoded.
    :return: True if the signature is valid, False otherwise.
    """
    try:
        # Create a new SHA-256 hash of the payload
        # h = SHA256.new(payload.encode('utf-8'))
        
        # Decode the base64-encoded signature
        decoded_signature = base64.b64decode(signature)
        
        # Create a verifier with the public key
        # verifier = PKCS1_v1_5.new(public_key)
        print(decoded_signature)

        SIGNATURE_KEY.verify(
            decoded_signature,
            payload.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Verify the signature
        print("Signature verified")
        return True  # verifier.verify(h, decoded_signature)
    except Exception as e:
        print(f"Verification failed: {e}")

        return False


# Alternatively, for the entire app, add a global options handler
# @app.before_request
# def before_request():
#     # response.headers['Access-Control-Allow-Origin'] = 'https://isa-singh.azurewebsites.net'
#     # response.headers['Access-Control-Allow-Origin'] = 'localhost:8080'
#     if request.method == 'OPTIONS':
#         response = jsonify({"message": "Preflight OK"})
#         response.headers['Access-Control-Allow-Origin'] = 'https://isa-singh.azurewebsites.net'
#         # response.headers['Access-Control-Allow-Origin'] = 'localhost:8080'
#         response.headers['Access-Control-Allow-Credentials'] = 'true'
#         response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
#         response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
#         response.status_code = 200
#         return response
#     signature_header = request.headers.get('x-gateway-signature')
    
    
#     if signature_header is None:
#         return jsonify({'message': 'Invalid request, needs to be signed'}), 401
    
#     # Extract the payload (in this example, we use the raw request data)
#     # Adjust this as needed to match how the payload is constructed on your side
#     # payload = request.method + request.url + request.data.decode('utf-8')
#     payload = request.method + request.path
#     # print("url", request.url)
#     # print("payload", payload)
#     print("signature", request.method + request.path)


#     # Verify the signature
#     if verify_signature(payload, signature_header):
#         pass  # Continue processing the request

#     else:
#         return jsonify({'message': 'Invalid signature'}), 403


@app.route('/detect', methods=['POST'])
def detect_objects():
    # email = request.json.email
    token = request.cookies.get('jwt')
    if not token:
        return jsonify({'message':'we couldn\'t figure out who you were'}), 401
    
    try:
        decoded_token = jwt.decode(token, private_key, algorithms=["RS256"])
        email = decoded_token.get('email')
        if not email:
            return jsonify({'message':'we couldn\'t figure out who you were'}), 401
            
    except Exception as e:
        return jsonify({"err": "no good"}), 400
    
    
    
        
    if 'image' not in request.files:
        return jsonify({"error": "No image uploaded"}), 400

    if email:
        response = requests.post(
            USER_SERVICE_URL+"/increase/"+email, 
            headers={'x-gateway-signature': create_signature(request.method + request.path, SIGNER_KEY)}
        )

    file = request.files['image']
    image = Image.open(file.stream).convert('RGB')
    image = np.array(image)

    # Run object detection
    results = model.predict(source=image, save=False, verbose=False)

    # Get annotated image
    annotated_image = results[0].plot()

    # Convert image to bytes for response
    _, buffer = cv2.imencode('.jpg', annotated_image)
    image_bytes = BytesIO(buffer)

    return send_file(image_bytes, mimetype='image/jpeg')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
