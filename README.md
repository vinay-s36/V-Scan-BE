# Web Vulnerability Scanner - Backend

This is the Python-based backend for the Web Vulnerability Scanner. It provides APIs to scan web applications for vulnerabilities and generate reports.

## Features
- Scans target URLs for common vulnerabilities (e.g., SQL Injection, XSS, insecure cookies).
- Generates downloadable reports for scan results.

## Prerequisites
- **Python 3.8+**
- **pip** (Python package installer)
- **MySQL** (for the database)

## Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/vinay-s36/V-Scan-BE.git
cd V-Scan-BE
```

### 2. Create a Virtual Environment
It’s recommended to use a virtual environment to manage dependencies:
```bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
Install the required Python libraries:
```bash
pip install -r requirements.txt
```

### 5. Run the Server
Start the development server:
```bash
python app.py
```

By default, the backend will be available at `http://localhost:8080`.

---

### API Endpoints
#### 1. **Start a Scan**
   - **Endpoint:** `POST /scan`
   - **Request Body:**
     ```json
     {
       "target_url": "http://example.com"
     }
     ```
   - **Response:**
     ```json
     {
       "status": "success",
       "report": "report_filename.txt",
       "total_vulnerabilities": 5
     }
     ```

#### 2. **Download Report**
   - **Endpoint:** `GET /reports/{filename}`
   - **Response:** File download for the report.
