# CleanCity – Waste Management System (Flask + SQLAlchemy + Bootstrap 5)
## Setup
```bash
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000 – the database and demo users are created automatically on first run.
## Demo credentials (demo only)
| Role | Email | Password |
|---|---|---|
| Admin | admin@cleancity.com | Admin@123 |
| Collector | collector@cleancity.com | Collector@123 |
| Citizen | citizen@cleancity.com | Citizen@123 |
## Features
Registration with validation, hashed passwords, role-based dashboards, waste reporting with image upload, collector assignment, status updates, search/filter, Chart.js admin charts, user management, JSON APIs (`/api/reports`, `/api/dashboard/stats`), custom 403/404/500 pages.
## Future enhancements
Complaints & notifications modules, monthly trend charts, email alerts, password reset.
