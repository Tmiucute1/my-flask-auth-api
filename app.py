from flask import Flask, request, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from flask_cors import CORS

# --- 1. CẤU HÌNH ỨNG DỤNG FLASK VÀ MONGODB ---
app = Flask(__name__)

# Cho phép các yêu cầu từ Frontend (chạy trên domain khác)
FRONTEND_URL = "https://flask-login-ui.onrender.com"
CORS(app, resources={r"/api/*": {"origins": FRONTEND_URL}})

# Lấy các biến từ môi trường (RENDER sẽ cung cấp, hoặc tự setup .env nếu chạy cục bộ)
app.config['MONGO_URI'] = os.environ.get('MONGO_URI')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
mongo_client_status = True # (DÒNG MỚI ĐƯỢC THÊM)
# Kết nối với MongoDB Atlas
try:
    client = MongoClient(app.config['MONGO_URI'])
    db = client.get_database('UserAuthDB') 
    users_collection = db['users']
except Exception as e:
    # Báo lỗi nếu không kết nối được (thường xảy ra nếu chuỗi MONGO_URI sai)
    print(f"LỖI KẾT NỐI MONGODB: {e}") 
    mongo_client_status = False # (DÒNG MỚI ĐƯỢC THÊM)
# KHÔNG CÓ DÒNG CODE NÀO Ở ĐÂY NỮA
# --- 2. ĐIỂM CUỐI API: ĐĂNG KÝ (REGISTER) ---
@app.route('/api/register', methods=['POST'])
def register():
    try:
        # Sửa lỗi JSON: Đảm bảo nhận JSON an toàn
        data = request.get_json(force=True) 
    except Exception as e:
        print(f"LỖI PHÂN TÍCH JSON: {e}")
        return jsonify({"message": "Dữ liệu gửi lên không phải JSON hợp lệ."}), 400

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"message": "Thiếu thông tin Đăng ký (username, email, password)."}), 400

    # Sửa lỗi cú pháp truy vấn MongoDB ($or) và lỗi thụt đầu dòng
    if users_collection.find_one({'$or': [{'email': email}, {'username': username}]}):
        return jsonify({"message": "Email hoặc Username đã được sử dụng."}), 409

    # Mã hóa mật khẩu
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    new_user = {
        "username": username,
        "email": email,
        "password_hash": hashed_password,
        "created_at": datetime.now() # Đã sửa lỗi datetime
    }

    try:
        users_collection.insert_one(new_user)
        return jsonify({"message": "Đăng ký thành công!"}), 201
    except Exception as e:
        # BÁO LỖI SERVER TRONG LOGS: Nếu lỗi 500 xảy ra, log này sẽ giúp ta tìm ra nguyên nhân
        print(f"LỖI SERVER KHI INSERT VÀO DB: {e}")
        return jsonify({"message": f"Lỗi Server (DB): {str(e)}"}), 500


# --- 3. ĐIỂM CUỐI API: ĐĂNG NHẬP (LOGIN) ---
@app.route('/api/login', methods=['POST'])
def login():
    try:
        # Sửa lỗi JSON: Đảm bảo nhận JSON an toàn
        data = request.get_json(force=True)
    except Exception as e:
        print(f'LỖI PHÂN TÍCH JSON ĐĂNG NHẬP: {e}')
        return jsonify({"message": "Dữ liệu gửi lên không phải JSON hợp lệ."}, 400)

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Thiếu Email hoặc Mật khẩu."}, 400)

    # Logic tìm kiếm và xác thực phải ngang hàng với if/return ở trên
    # 1. Tìm người dùng bằng email
    user = users_collection.find_one({"email": email})

    # 2. Xác thực mật khẩu
    if user and check_password_hash(user['password_hash'], password):
        return jsonify({
            "message": "Đăng nhập thành công!",
            "username": user['username']
        }), 200
    else:
        # Lỗi: Email không tồn tại hoặc Mật khẩu sai
        return jsonify({"message": "Email hoặc Mật khẩu không chính xác."}, 401)
# --- 4. CHẠY ỨNG DỤNG ---
if __name__ == '__main__':
    # Chỉ dùng cho test cục bộ. Khi deploy Render sẽ dùng gunicorn.
    app.run(host='0.0.0.0', port=5000, debug=True)