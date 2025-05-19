from flask import Flask
from routes import register_routes
import os

def create_app():
    app = Flask(__name__)
    app.secret_key = "IAMTHESECRETKEY"
    
    # Create upload folder
    UPLOAD_FOLDER = "uploaded_files"
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    # Register routes
    register_routes(app)
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host=os.getenv("MY_IP"), port=5000)