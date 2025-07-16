Course Management API

A lightweight course management REST API designed as a modern alternative to platforms like Canvas. Built as the final project for Oregon State University’s CS 493 course, 
utilizing cloud deployment for authentication, role-based access control, and secure file handling.

⸻

Features
	•	Authentication & Authorization
Uses Auth0 with JWT Bearer tokens for secure access. Enforces strict role-based access for admin, instructor, and student users.
	•	🗃User Management
Supports login, viewing user data (with role-based permissions), and avatar upload/delete via Google Cloud Storage.
	•	Course Management
Admins can create, edit, and delete courses. Instructors and admins can manage enrollment. Pagination and ordering supported.
	•	Google Cloud Integration
Deployed on Google App Engine. Stores avatar images securely in Google Cloud Storage and uses Google Datastore for all structured data.
	•	Testable, RESTful Design
Implements 13 REST endpoints following standard HTTP methods and status codes.

⸻

Technologies Used
	•	Python 3 (Flask)
	•	Google App Engine
	•	Google Cloud Datastore
	•	Google Cloud Storage
	•	Auth0 (JWT Authentication)
	•	Postman (for endpoint testing)

⸻

API Endpoints Overview

Method	Endpoint	Description	Protected	Access
POST	/users/login	Auth0 login + JWT issuance	No	All users
GET	/users	Get all users (basic info)	Yes	Admin
GET	/users/:id	Get single user info, including avatar & courses	Yes	Admin / Self
POST	/users/:id/avatar	Upload avatar to GCS	Yes	Self
GET	/users/:id/avatar	Get avatar from GCS	Yes	Self
DELETE	/users/:id/avatar	Delete avatar from GCS	Yes	Self
POST	/courses	Create a new course	Yes	Admin
GET	/courses	List all courses (paginated, ordered)	No	Public
GET	/courses/:id	Get single course details	No	Public
PATCH	/courses/:id	Update course info	Yes	Admin
DELETE	/courses/:id	Delete course + enrollment	Yes	Admin
PATCH	/courses/:id/students	Enroll/unenroll students	Yes	Admin/Instructor
GET	/courses/:id/students	List enrolled students	Yes	Admin/Instructor

⸻

🔧 Setup & Deployment

Prerequisites:
	•	Python 3
	•	Google Cloud SDK
	•	Auth0 account

Clone & Install:

git clone https://github.com/yourusername/course_management_api.git
cd course_management_api
pip install -r requirements.txt

Deploy to Google App Engine:

gcloud app deploy

Environment Configuration:
	•	Store Auth0 and GCP credentials in a .env file
	•	Set GOOGLE_APPLICATION_CREDENTIALS to point to your service account JSON

⸻

License

This project is open for review and sharing as a portfolio artifact. Feel free to fork or reference it with attribution.
