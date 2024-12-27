# SSH Key Management System

A FastAPI-based application designed for SSH key management with category handling, backed by a MariaDB database for secure and efficient data storage. The system includes user authentication to ensure secure access and offers comprehensive key management capabilities such as uploading, listing, and deleting SSH keys. It introduces a dynamic category assignment feature, allowing users to organize keys into categories that can be activated or deactivated as needed. Real-time updates are applied to the authorized_keys file, ensuring that only keys in active categories are included.

## Features

- **User Management**: Create and authenticate users.
- **SSH Key Management**:
  - Create, list, and delete SSH keys.
  - Assign categories to keys.
- **Category Management**:
  - Create and update categories.
  - Activate or deactivate categories.
- **Real-time Key Updates**:
  - Automatically update the `authorized_keys` file based on active categories.
- **Authentication**: Secure endpoints with OAuth2 and JWT-based authentication.

---

## Getting Started

### Prerequisites

- Docker & Docker Compose
- Python 3.10+
- MariaDB

### Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/ahrarbinaslam/SSH-Key-Management-System.git
   cd SSH-Key-Management-System
   ```

2. **Install Dependencies**:
   If running locally:
   ```bash
   pip install -r requirements.txt
   ```

3. **Build and Run with Docker**:
   ```bash
   docker-compose up --build
   ```

4. **Access the Application**:
   Visit `http://localhost:8000` in your browser. 

   The FastAPI Swagger documentation is available at `http://localhost:8000/docs`.

## Directory Structure

```
SSH-Key-Management-System/
├── main.py           # FastAPI application entry point
├── models.py         # Database models
├── database.py       # Database configuration
├── requirements.txt  # Python dependencies
├── Dockerfile        # Docker configuration
├── docker-compose.yml# Docker Compose configuration
├── details.env       # Environment variables
└── README.md         # Project documentation

