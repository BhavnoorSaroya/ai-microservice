from flask import Flask, request, jsonify, send_file, Response, render_template
from ultralytics import YOLO
import cv2
import numpy as np
from io import BytesIO
from PIL import Image
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import jwt
import requests

# Load private and public keys
with open('private.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )
with open('public.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(
        f.read()
    )

FRONTEND_URL = 'https://isa-singh.azurewebsites.net'
USER_SERVICE_URL = 'https://isa-database-microservice.onrender.com'

app = Flask(__name__)
model = YOLO('yolo11n.pt')

def create_signature(payload, private_key):
    """
    Creates a base64-encoded signature for the given payload using the provided private key.
    """
    signature = private_key.sign(
        payload.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(payload, signature):
    """
    Verifies the base64-encoded signature of the given payload using the public key.

    :param payload: The original payload as a string.
    :param signature: The signature to verify, base64-encoded.
    :return: True if the signature is valid, False otherwise.
    """
    try:
        decoded_signature = base64.b64decode(signature)
        public_key.verify(
            decoded_signature,
            payload.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature verified")
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

@app.before_request
def before_request():
    """
    Global request handler to verify signatures for protected routes.
    Exempts the 'video_feed' and 'index' routes from signature verification.
    """
    # Exempt certain routes from signature verification
    if request.endpoint in ['video_feed', 'index']:
        return

    if request.method == 'OPTIONS':
        response = jsonify({"message": "Preflight OK"})
        response.headers.update({
            'Access-Control-Allow-Origin': 'https://isa-singh.azurewebsites.net',
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        })
        return response

    signature_header = request.headers.get('x-gateway-signature')
    if not signature_header:
        return jsonify({'message': 'Invalid request, needs to be signed'}), 401

    payload = request.method + request.path
    print("Signature payload:", payload)

    if not verify_signature(payload, signature_header):
        return jsonify({'message': 'Invalid signature'}), 403

NEW_URL = "https://e64f-2604-3d08-607f-b5c0-5ff-f691-d66-e487.ngrok-free.app"
@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy(path):
    # Build the target URL
    target_url = f"{NEW_URL}/{path}"
    
    # Forward headers and explicitly set the Host header to match the target
    headers = {key: value for key, value in request.headers}
    headers['Host'] = 'e64f-2604-3d08-607f-b5c0-5ff-f691-d66-e487.ngrok-free.app'  # Replace with the actual host of your target URL
    
    # Forward the request to the new URL
    response = requests.request(
        method=request.method,
        url=target_url,
        headers=headers,
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False,
    )
    
    # Return the response from the new server
    return Response(
        response.content,
        status=response.status_code,
        headers=dict(response.headers),
    )



@app.route('/detect', methods=['POST'])
def detect_objects():
    """
    Handles image uploads, performs object detection, overlays the API call counter,
    and returns the annotated image.
    """
    token = request.cookies.get('jwt')
    if not token:
        return jsonify({'message': "We couldn't figure out who you are"}), 401
    
    try:
        decoded_token = jwt.decode(token, public_key, algorithms=["RS256"])
        email = decoded_token.get('email')
        if not email:
            return jsonify({'message': "We couldn't figure out who you are"}), 401
    except Exception:
        return jsonify({"err": "Invalid token"}), 400

    if 'image' not in request.files:
        return jsonify({"error": "No image uploaded"}), 400

    # Increment the user's API call counter
    response = requests.post(
        f"{USER_SERVICE_URL}/increase/{email}",
        headers={'x-gateway-signature': create_signature(f'/increase/{email}', private_key)}
    )
    
    if response.status_code == 200:
        counter = response.json().get('counter', 0)
    else:
        return jsonify({"error": "Failed to update user counter"}), 500
    
    counter_message = f"Warning: API calls exceeded: {counter}" if counter > 20 else f"API calls: {counter}"

    # Process the uploaded image
    file = request.files['image']
    image = Image.open(file.stream).convert('RGB')
    image_np = np.array(image)

    # Run object detection
    results = model.predict(source=image_np, save=False, verbose=False)

    # Get annotated image
    annotated_image = results[0].plot()
    annotated_image_cv = cv2.cvtColor(annotated_image, cv2.COLOR_RGB2BGR)

    # # Add the counter value to the image
    cv2.putText(
        annotated_image_cv,
        counter_message,
        (10, 30),
        cv2.FONT_HERSHEY_SIMPLEX,
        1,
        (255, 0, 0),
        2,
        cv2.LINE_AA
    )

    # Convert image to bytes for response
    _, buffer = cv2.imencode('.jpg', annotated_image_cv)
    image_bytes = BytesIO(buffer)

    return send_file(image_bytes, mimetype='image/jpeg')

@app.route('/video-feed')
def video():
    """
    Streams live video frames from the RTMP source, overlays the user's API call counter,
    and increments the counter each time the stream is accessed.
    # """
    token = request.cookies.get('jwt')
    if not token:
        return jsonify({'message': "We couldn't figure out who you are"}), 401
    
    try:
        decoded_token = jwt.decode(token, public_key, algorithms=["RS256"])
        email = decoded_token.get('email')
        if not email:
            return jsonify({'message': "We couldn't figure out who you are"}), 401
    except Exception:
        return jsonify({"err": "Invalid token"}), 400
    
    # Increment the user's API call counter
    response = requests.post(
        f"{USER_SERVICE_URL}/increase/{email}",
        headers={'x-gateway-signature': create_signature(f'/increase/{email}', private_key)}
    )
    
    if response.status_code == 200:
        counter = response.json().get('counter', 0)
    else:
        return jsonify({"error": "Failed to update user counter"}), 500

    def generate_frames():
        """
        Generator function that streams video frames with the API call counter overlaid.
        """
        source = "rtmp://52.233.85.210/live/drone_stream"
        results = model(source, stream=True)
        for result in results:
            annotated_frame = result.plot()

            # Encode frame as JPEG
            ret, buffer = cv2.imencode('.jpg', annotated_frame)
            frame = buffer.tobytes()

            # Yield the frame in byte format
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

    return Response(generate_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002)
