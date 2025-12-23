# Telegram Authentication Website

A professional Flask-based website that allows users to login using their Telegram phone number and OTP verification. The application generates and saves Telethon session strings in MongoDB to provide users with special features not available in the official Telegram app.

## Features

- **Secure Telegram Authentication**: Login using phone number and OTP verification
- **Session Management**: Generates and stores Telethon session strings in MongoDB
- **Professional UI**: Modern, responsive design with Bootstrap 5
- **Premium Features**: Access to special features not available in official Telegram app
- **MongoDB Integration**: Secure user data storage
- **Real-time Notifications**: Success messages and error handling

## Prerequisites

- Python 3.7+
- MongoDB Atlas account (or local MongoDB)
- Telegram API credentials (API ID and API Hash)

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd telegram-auth-website
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure your credentials**:
   - Update the `API_ID` and `API_HASH` in `app.py` with your Telegram API credentials
   - Update the `MONGO_URI` with your MongoDB connection string

4. **Run the application**:
   ```bash
   python app.py
   ```

5. **Access the website**:
   Open your browser and go to `http://localhost:5000`

## Configuration

### Telegram API Credentials
To get your Telegram API credentials:
1. Go to https://my.telegram.org
2. Login with your phone number
3. Go to "API Development Tools"
4. Create a new application
5. Copy your `api_id` and `api_hash`

### MongoDB Setup
The application uses MongoDB Atlas with the provided connection string. The database will be automatically created when the first user registers.

## Usage

1. **Home Page**: Welcome page with feature overview
2. **Login**: Enter your Telegram phone number (with country code)
3. **OTP Verification**: Enter the OTP received in your Telegram app
4. **Dashboard**: Success page showing user information and premium features

## Database Schema

The application stores user data in MongoDB with the following structure:

```json
{
  "user_id": "telegram_user_id",
  "phone": "+1234567890",
  "first_name": "John",
  "last_name": "Doe",
  "username": "johndoe",
  "session_string": "encrypted_session_string",
  "created_at": "2023-12-23T10:00:00Z",
  "last_login": "2023-12-23T10:00:00Z"
}
```

## Security Features

- Session strings are securely stored in MongoDB
- Temporary client sessions are cleaned up after authentication
- OTP-based verification for secure login
- Session management with Flask sessions

## File Structure

```
telegram-auth-website/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # Project documentation
├── static/
│   └── css/
│       └── style.css     # Custom CSS styles
└── templates/
    ├── base.html         # Base template
    ├── index.html        # Home page
    ├── login.html        # Login page
    └── dashboard.html    # Dashboard page
```

## API Endpoints

- `GET /` - Home page
- `GET /login` - Login page
- `POST /login` - Send OTP to phone number
- `POST /verify_otp` - Verify OTP and complete login
- `GET /dashboard` - User dashboard (requires authentication)
- `GET /logout` - Logout user

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Disclaimer

This application is for educational purposes. Make sure to comply with Telegram's Terms of Service when using their API.