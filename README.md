# Flask Web Application

A comprehensive web application built with Flask that includes various features for user management, communication, and utilities.

## Features

### User Management

- **Registration**: Users can create new accounts with username, email, and password
- **Authentication**: Secure login system with password hashing
- **Profile Management**: Users can view their profile information

### Communication

- **Message Board**: Community message board where users can post and read messages
- **Message Management**: Users can delete their own messages

### Utilities

- **Network Ping Tool**: Check connectivity to hosts by IP address or domain name
- **File Management**:
  - File Upload: Upload .pkl (Python pickle) files to restore analysis data
  - File Download: Browse and download available files
  - Security Features: Validation of pickle files to prevent malicious code execution

### Security Features

- Password hashing using Werkzeug security
- CSRF protection with Flask sessions
- Pickle file validation:
  - File size limits (1MB max)
  - Content scanning for potentially malicious code
  - Type validation for deserialized objects
  - Blacklist for dangerous operations/modules

## Technical Details

### Technologies Used

- **Backend**: Flask (Python web framework)
- **Database**: SQLite3
- **Frontend**: HTML, CSS, JavaScript
- **Security**: Werkzeug security for password handling
- **Data Serialization**: Python's pickle module

### Database Schema

- **Users Table**: Stores user accounts (id, username, email, password)
- **Messages Table**: Stores message board posts (id, user_id, username, content, created_at)

### File Structure

- `/static/`: Static files (CSS, JavaScript, uploaded files)
- `/templates/`: HTML templates
- `app.py`: Main application file
- `users.db`: SQLite database

## Setup and Installation

1. Install required packages:

   ```
   pip install -r requirements.txt
   ```

2. Initialize the database:

   ```
   python db_init.py
   ```

3. Run the application:

   ```
   python app.py
   ```

4. Access the application at: `http://localhost:5000`

## Security Notice

This version demonstrates secure coding practices. The repository will be published as part of academic research showing how Copilot can potentially generate insecure code patterns. This research is strictly for educational purposes to help developers and researchers understand and prevent security vulnerabilities. The findings will be published in an upcoming academic paper.In a production environment, additional security measures would be necessary.
