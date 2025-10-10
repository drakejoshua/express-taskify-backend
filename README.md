# 🧩 Welcome to the Tasks Backend

Welcome to the official backend of the **Tasks App**, a modern task management system built with **Node.js**, **Express**, and **MongoDB**.  
This backend powers all authentication, authorization, and task management functionalities used by the Tasks frontend client.

---

## 🚀 Overview

The **Tasks Backend** provides a clean and secure RESTful API for user authentication and task management.  
It’s designed to demonstrate best practices in backend architecture — including modular route organization, JWT authentication, OAuth integration, and robust error handling.

This repository is divided into two main sections:

1. **Authentication & User Management**  
   Handles everything related to user accounts, including registration, login, password resets, email verification, and Google OAuth.

2. **Task Management API**  
   Handles CRUD operations for user tasks, complete with rate limiting, validation, and authorization checks.

---

## 🧱 Core Features

- **JWT Authentication & Refresh Tokens**  
  Securely manage access and refresh tokens for each user session.

- **Email Verification & Password Reset Flows**  
  Built-in verification and reset links sent via email.

- **Magic Link & Google OAuth Login**  
  Login without a password or with your Google account.

- **Rate Limiting**  
  Prevents abuse by restricting request frequency per user/IP.

- **Clean REST Architecture**  
  Predictable endpoints with clear request/response structures.

- **CORS, Helmet & Secure Headers**  
  Ensures cross-origin safety and general backend security.

---

## ⚙️ Tech Stack

| Category | Technology |
|-----------|-------------|
| **Runtime** | Node.js |
| **Framework** | Express.js |
| **Database** | MongoDB with Mongoose |
| **Authentication** | Passport.js & JWT |
| **Email Service** | Nodemailer |
| **Hosting** | Render |
| **Rate Limiting** | express-rate-limit |
| **Validation** | express-validator |
| **File Uploads** | Multer |

---

## 📖 Documentation Structure

This README is organized into the following parts:

1. **Auth Endpoints Documentation** – Covers all authentication routes such as registration, verification, login, and OAuth.
2. **Tasks Endpoints Documentation** – Covers all CRUD routes for task management.

Each section provides:
- Endpoint URL and method  
- Description and parameters  
- Expected request body  
- Example responses and status codes  

---

## 🔐 Base URLs

All routes in this backend are hosted live on **Render**:

- **Auth Endpoints:**  
  `https://express-taskify-backend.onrender.com/auth`

- **Task Endpoints:**  
  `https://express-taskify-backend.onrender.com/api/tasks`

Each endpoint follows REST conventions and requires authentication where specified.

---

## 🧭 Getting Started (For Developers)

To run this project locally:

```bash
# 1. Clone the repository
git clone https://github.com/your-username/express-taskify-backend.git
cd express-taskify-backend

# 2. Install dependencies
npm install

# 3. Create an .env file
touch .env

# env contents
# 🔑 Database Configuration
MONGO_URI=<your-mongodb-connection-string>

# 🔒 JWT Configuration
JWT_SECRET=<your-jwt-secret>
ACCESS_TOKEN_EXPIRY=<access-token-expiry>     # e.g., 15m
REFRESH_TOKEN_EXPIRY=<refresh-token-expiry>   # e.g., 7d

# 📧 Email Configuration
GMAIL_AUTH_PASS=<your-google-app-password>

# ☁️ Cloudinary Configuration
CLOUDINARY_CLOUD_NAME=<your-cloudinary-cloud-name>
CLOUDINARY_API_KEY=<your-cloudinary-api-key>
CLOUDINARY_API_SECRET=<your-cloudinary-api-secret>
CLOUDINARY_URL=<your-cloudinary-url>

# 🌐 Google OAuth Configuration
GOOGLE_CLIENT_ID=<your-google-client-id>
GOOGLE_CLIENT_SECRET=<your-google-client-secret>
GOOGLE_CALLBACK_URL=<your-google-callback-url>

# 4. start the server
npm run dev
```



# Tasks Backend Auth Endpoints Documentation

This section of the documentation provides a summary of all available auth endpoints in the authentication and user management code of the backend.

## **Rate Limiting**
All auth endpoints are rate-limited: **5 requests per 15 minutes per user/IP**.

---

**Base URL:** `https://express-taskify-backend.onrender.com/auth`  
**Authentication:** JWT Bearer tokens for protected routes.  
**Response Format:** JSON

---

## **1. Register User**
**Endpoint:** `POST /register-user`  
**Description:** Registers a new user with name, email, password, and optional profile photo.  
**Query Params:**  
- `emailredirect` – URL to redirect after email verification.  
**Body( formdata ):**  
- `name` (string, required)  
- `email` (string, required)  
- `password` (string, required, min: 6)  
- `photo` (file, optional)  
**Response:**  
- `201 Created` – User account created successfully.

---

## **2. Update User**
**Endpoint:** `PUT /update-user`  
**Description:** Updates user profile information such as email, password, and profile photo.  
**Auth:** Bearer JWT required.  
**Body( formdata ):**  
- `email` (string, optional)  
- `password` (string, optional, min: 6)  
- `photo` (file, optional)  
**Response:**  
- `200 OK` – User data updated successfully.

---

## **3. Verify Email (Request)**
**Endpoint:** `POST /verify`  
**Description:** Sends a verification email to the user with a verification token.  
**Query Params:**  
- `emailredirect` – URL to redirect after verification.  
**Body:**  
- `email` (string, required)  
**Response:**  
- `200 OK` – Verification email sent.

---

## **4. Verify Email (Token Validation)**
**Endpoint:** `GET /verify/:token`  
**Description:** Validates the email verification token, activates user account, and returns auth tokens.  
**Params:**  
- `token` (string, required)  
**Response:**  
- `200 OK` – User verified successfully.

---

## **5. Forgot Password (Request Reset)**
**Endpoint:** `POST /forgot-password`  
**Description:** Sends a password reset link to user email.  
**Query Params:**  
- `emailredirect` – URL to redirect after reset.  
**Body:**  
- `email` (string, required)  
**Response:**  
- `200 OK` – Password reset email sent.

---

## **6. Reset Password**
**Endpoint:** `POST /forgot-password/:token`  
**Description:** Resets the password using the provided token.  
**Params:**  
- `token` (string, required)  
**Body:**  
- `password` (string, required, min: 6)  
**Response:**  
- `200 OK` – Password reset successful.

---

## **7. Login User**
**Endpoint:** `POST /login-user`  
**Description:** Authenticates a user using email and password.  
**Body:**  
- `email` (string, required)  
- `password` (string, required, min: 6)  
**Response:**  
- `200 OK` – Returns access and refresh tokens.

---

## **8. Magic Link Login (Request)**
**Endpoint:** `POST /magiclink`  
**Description:** Sends a magic login link to user's email.  
**Query Params:**  
- `emailredirect` (string, required)  
**Body:**  
- `email` (string, required)  
**Response:**  
- `200 OK` – Magic link sent.

---

## **9. Magic Link Login (Token)**
**Endpoint:** `GET /magiclink/:token`  
**Description:** Logs in the user using a valid magic link token.  
**Params:**  
- `token` (string, required)  
**Response:**  
- `200 OK` – Returns access and refresh tokens.

---

## **10. Google OAuth (Initiate)**
**Endpoint:** `GET /google`  
**Description:** Initiates Google OAuth flow for login/signup.  
**Query Params:**  
- `redirect` (string, required) – Frontend redirect URL.  
**Response:**  
- Redirects to Google OAuth page.

---

## **11. Google OAuth (Callback)**
**Endpoint:** `GET /google/callback`  
**Description:** Handles Google OAuth callback, creates or logs in user, and redirects with tokens.  
**Query Params:**  
- `state` – Encoded redirect URL.  
**Response:**  
- Redirects with access and refresh tokens.

---

## **12. Refresh Token**
**Endpoint:** `POST /refresh-token`  
**Description:** Generates a new access token using the refresh token.  
**Body:**  
- `refreshToken` (JWT, required)  
**Response:**  
- `201 Created` – Returns new access token.

---

## **13. Logout User**
**Endpoint:** `POST /logout`  
**Description:** Logs out the user by invalidating the refresh token.  
**Body:**  
- `refreshToken` (JWT, required)  
**Response:**  
- `200 OK` – Successfully logged out.

---

## **14. Get Current User**
**Endpoint:** `GET /me`  
**Description:** Retrieves currently authenticated user’s details.  
**Headers:**  
- `Authorization: Bearer <accessToken>`  
**Response:**  
- `200 OK` – Returns user data.

---

# Tasks Backend API Endpoints Documentation

This section of the documentation provides a summary of all available api endpoints in the tasks management code of the backend.

## **Rate Limiting**
All task endpoints are rate-limited: **10 requests per 15 minutes per user/IP**.

---

**Base URL:** `https://express-taskify-backend.onrender.com/api/tasks`  
**Authentication:** JWT Bearer tokens for all routes.  
**Response Format:** JSON  

---

## **1. Get All Tasks**
**Endpoint:** `GET /api/tasks`  
**Description:** Retrieves all tasks created by the authenticated user with optional query filters and sorting options.  
**Auth:** JWT Bearer token required.  
**Query Parameters:**  
- `limit` *(optional, int, default: 10)* — Maximum number of tasks to return (1–100).  
- `sort` *(optional, string, default: "text")* — Field to sort by (`text` or `date`).  
- `order` *(optional, string, default: "DESC")* — Sorting order (`ASC` or `DESC`).  
- `filter` *(optional, string)* — Search term for filtering tasks by text.  
**Response:**  
- `200 OK` — Returns paginated list of user tasks and total task count.  

---

## **2. Get Task by ID**
**Endpoint:** `GET /api/tasks/:id`  
**Description:** Retrieves a single task by its ID if it belongs to the authenticated user.  
**Auth:** JWT Bearer token required.  
**Params:**  
- `id` *(string, required)* — Task ID (MongoDB ObjectId).  
**Response:**  
- `200 OK` — Returns the task object (`_id`, `text`, `date`).  
- `404 Not Found` — Task not found.  

---

## **3. Create New Task**
**Endpoint:** `POST /api/tasks`  
**Description:** Creates a new task for the authenticated user.  
**Auth:** JWT Bearer token required.  
**Body:**  
- `text` *(string, required)* — Description or objective of the task.  
- `date` *(optional, ISO8601 date)* — Due date or creation date of the task.  
**Response:**  
- `201 Created` — Returns created task with `text`, `date`, and `_id`.  

---

## **4. Update Task**
**Endpoint:** `PUT /api/tasks/:id`  
**Description:** Updates an existing task belonging to the authenticated user.  
**Auth:** JWT Bearer token required.  
**Params:**  
- `id` *(string, required)* — Task ID (MongoDB ObjectId).  
**Body:**  
- `text` *(optional, string)* — New text for the task.  
- `date` *(optional, ISO8601 date)* — New date for the task.  
**Response:**  
- `200 OK` — Returns updated task data.  
- `404 Not Found` — Task not found.  

---

## **5. Delete Task**
**Endpoint:** `DELETE /api/tasks/:id`  
**Description:** Deletes a task belonging to the authenticated user.  
**Auth:** JWT Bearer token required.  
**Params:**  
- `id` *(string, required)* — Task ID (MongoDB ObjectId).  
**Response:**  
- `204 No Content` — Task deleted successfully.  
- `404 Not Found` — Task not found.  

---