# Cloud Storage System

A comprehensive cloud-based file storage system similar to OneDrive with email login and access control.

## Features

- **User Authentication**
  - OAuth 2.0 integration for Google and Microsoft accounts
  - Traditional email/password registration
  - Email verification for security

- **File Management**
  - Upload, download, delete, and organize files/folders
  - Drag-and-drop support
  - File preview for images, PDFs, and documents

- **Access Control & Sharing**
  - Role-based permissions (Admin, User, Guest)
  - Share files via public/private links
  - Set permissions (View/Edit/Download)

- **Cloud Storage**
  - MongoDB Atlas integration
  - Automatic sync across devices

- **Security**
  - AES-256 encryption for stored files
  - Session management & brute-force protection

- **Versioning & Recovery**
  - Track file versions (restore previous versions)
  - Recycle bin for deleted files (30-day retention)

- **Search & Organization**
  - Search files by name, type, or tags
  - Folder structure & favorites system

- **UI/UX**
  - Responsive design for all devices
  - Light and dark theme switching

## Installation

1. Clone the repository
2. Create a virtual environment:
   ```
   python -m venv venv
   ```
3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - macOS/Linux: `source venv/bin/activate`
4. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
5. Create a `.env` file with the following variables:
   ```
   SECRET_KEY=your_secret_key
   JWT_SECRET_KEY=your_jwt_secret_key
   MONGO_URI=mongodb+srv://niyazpathan:sUOHMeG7VrBTYR7T@cluster0.ahhhgmz.mongodb.net/mystore_db?retryWrites=true&w=majority
   ```

## Usage

1. Run the application:
   ```
   python app.py
   ```
2. Open your browser and navigate to `http://localhost:5000`
3. Register a new account or log in with existing credentials

## Project Structure

```
cloud_storage_system/
├── static/               # Static assets
│   ├── css/              # CSS stylesheets
│   │   └── main.css      # Main stylesheet
│   ├── js/               # JavaScript files
│   │   └── app.js        # Main JavaScript
│   └── images/           # Images and icons
├── templates/            # HTML templates
│   ├── layout.html       # Base template
│   ├── index.html        # Landing page
│   ├── login.html        # Login page
│   ├── register.html     # Registration page
│   ├── dashboard.html    # User dashboard
│   └── files.html        # File management
├── app.py                # Main application
├── requirements.txt      # Python dependencies
└── README.md             # Project documentation
```

## Technologies Used

- **Backend**: Python Flask
- **Frontend**: HTML, CSS, JavaScript, Bootstrap
- **Database**: MongoDB Atlas
- **Authentication**: JWT, OAuth 2.0
- **Encryption**: AES-256

## License

This project is licensed under the MIT License - see the LICENSE file for details.
