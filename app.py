Python

from flask import Flask, request, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from flask_cors import CORS 

# --- 1. CẤU HÌNH ỨNG DỤNG FLASK VÀ MONGODB ---
app = Flask(__name__)
# Cho phép các yêu cầu từ Frontend (chạy trên domain khác)
CORS(app) 

# Lấy các biến từ môi trường (RENDER sẽ cung cấp, hoặc từ .env nếu chạy cục bộ)
app.config['MONGO_URI'] = os.environ.get('MONGO_URI')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

# Kết nối với MongoDB Atlas
try:
    client = MongoClient(app.config['MONGO_URI'])
    db = client.get_database('UserAuthDB') 
    users_collection = db['users'] 
except Exception as e:
    # Báo lỗi nếu không kết nối được (thường xảy ra nếu chuỗi MONGO_URI sai)
    print(f"LỖI KẾT NỐI MONGODB: Vui lòng kiểm tra lại MONGO_URI trong Render: {e}")


# --- 2. ĐIỂM CUỐI API: ĐĂNG KÝ (REGISTER) ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"message": "Thiếu thông tin Đăng ký (username, email, password)."}), 400

    # Kiểm tra tồn tại
    if users_collection.find_one({"$or": [{"email": email}, {"username": username}]}):
        return jsonify({"message": "Email hoặc Username đã được sử dụng."}), 409

    # Mã hóa mật khẩu 
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    new_user = {
        "username": username,
        "email": email,
        "password_hash": hashed_password,
        "created_at": datetime.utcnow()
    }

    try:
        users_collection.insert_one(new_user)
        return jsonify({"message": "Đăng ký thành công!"}), 201
    except Exception as e:
        return jsonify({"message": f"Lỗi Server: {str(e)}"}), 500


# --- 3. ĐIỂM CUỐI API: ĐĂNG NHẬP (LOGIN) ---
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Thiếu Email hoặc Mật khẩu."}), 400

    user = users_collection.find_one({"email": email})

    # Xác thực mật khẩu
    if user and check_password_hash(user['password_hash'], password):
        return jsonify({
            "message": "Đăng nhập thành công!",
            "username": user['username']
        }), 200
    else:
        return jsonify({"message": "Email hoặc Mật khẩu không chính xác."}), 401


# --- 4. CHẠY ỨNG DỤNG ---
if __name__ == '__main__':
    # Chỉ dùng cho test cục bộ. Khi deploy Render sẽ dùng gunicorn.
    app.run(host='0.0.0.0', port=5000, debug=True)