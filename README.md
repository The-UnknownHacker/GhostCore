# GhostCore

Uniting Your Services for a seamless development experience. Built with ❤️ for developers.

## Features

- Organization Management
- Service Integration with GitHub
- Automatic README Parsing
- GitHub Statistics Tracking
- API Access with Token Authentication
- User Management System
- Admin Dashboard

## Quick Start

1. Clone the repository:
```
git clone https://github.com/The-UnknownHacker/ghostcore
cd ghostcore
```

2. Install dependencies:
```
pip install -r requirements.txt
```

3. Run the Application:
```
python app.py
```

## Getting Started using the App

1. **Create an Organization**  
   - Sign up for an account and create an organization.

2. **Create a Service**  
   - Click on the "Create Service" button on your organization's dashboard.

3. **View Your Organization**  
   - Go to the "Organizations" section on the main page to check out your organization.

4. **Share Your Organization**  
   - Share the link to your organization with others to showcase your services.

## API Reference

Authentication required for all endpoints. Include token in header:
```
Authorization: Bearer your_token_here
```

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /api/auth | POST | Get authentication token |
| /api/services | GET | List all services |
| /api/services/{id} | GET | Get service details |
| /api/organizations | GET | List all organizations |

## Database Schema

### Organizations
```
CREATE TABLE organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

### Users
```
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    org_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizations(id)
)
```

### Services
```
CREATE TABLE services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    github_url TEXT,
    demo_url TEXT,
    org_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizations(id)
)
```

### Statistics
```
CREATE TABLE statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER,
    views INTEGER DEFAULT 0,
    stars INTEGER DEFAULT 0,
    last_updated TIMESTAMP,
    FOREIGN KEY (service_id) REFERENCES services(id)
)
```

## Environment Variables

Create a `.env` file in the root directory:

```
SECRET_KEY=your_secret_key_here
GITHUB_TOKEN=your_github_token
DEBUG=True
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License 

## Acknowledgments

- Flask for the web framework
- Bootstrap for the UI components
- Font Awesome for icons
