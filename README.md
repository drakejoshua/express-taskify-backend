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