# Disposable Email Validator API

![API Status](https://img.shields.io/badge/status-active-success)
![Version](https://img.shields.io/badge/version-1.0.0-blue)

A simple, lightweight, and free API to check if an email address belongs to a disposable or temporary email domain provider. This service is designed to help developers prevent spam, fake sign-ups, and abuse of free trials by validating user email addresses at the source.

---

## Features

-   **Disposable Domain Check:** Validates against a comprehensive list of known disposable email domains.
-   **IP-Based Rate Limiting:** A built-in limit of 100 requests per IP per day to prevent abuse.
-   **Simple JSON Response:** Clear, concise, and easy-to-parse responses.
-   **Lightweight & Fast:** Built with Node.js and Express for high performance.
-   **Free to Use:** Hosted on Render's free tier.

---

## Live API Endpoint

The base URL for all API requests is:

https://email-validator-api-uk66.onrender.com

---

## API Documentation

The API has a single endpoint for validating emails.

### Verify Email Address

This endpoint checks a single email address and returns its status, including whether the domain is disposable.

-   **URL:** `/v1/verify`
-   **Method:** `POST`
-   **Authentication:** None required.

#### Request Body

The request body must be a JSON object containing the email to be verified.

| Field | Type   | Description               | Required |
| :---- | :----- | :------------------------ | :------- |
| `email` | String | The email address to check. | Yes      |

#### How to Send a Request

You can use any HTTP client to send a request. Here are examples using `cURL` and the JavaScript `fetch` API.

**cURL Example:**

```bash
curl -X POST \
  https://email-validator-api-uk66.onrender.com/v1/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "test@mailinator.com"}'
```

**JavaScript Fetch Example:**

```javascript
async function validateEmail(emailAddress) {
  const url = 'https://email-validator-api-uk66.onrender.com/v1/verify';
  const options = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ email: emailAddress })
  };

  try {
    const response = await fetch(url, options);
    const data = await response.json();
    console.log(data);
    return data;
  } catch (error) {
    console.error('Error:', error);
  }
}

// Example usage:
validateEmail('hello@gmail.com');
validateEmail('test@mailinator.com');
```

#### Response Payloads

Below are the possible JSON responses you can receive from the API.

> **Note:** All successful requests will return an HTTP status code of `200 OK`.

**Response for a Valid Domain:**
```json
{
    "status": "valid",
    "message": "Email domain appears to be valid.",
    "email": "hello@gmail.com",
    "domain": "gmail.com",
    "is_disposable": false
}
```

**Response for a Disposable Domain:**
```json
{
    "status": "invalid",
    "message": "Disposable or temporary email domain found.",
    "email": "test@mailinator.com",
    "domain": "mailinator.com",
    "is_disposable": true
}
```

#### Error Responses

**Bad Request (Invalid Input):**
- **Status Code:** `400 Bad Request`
- **Trigger:** The `email` field is missing, empty, or not a string.
```json
{
    "status": "error",
    "message": "Invalid input. Please provide an email in the request body."
}
```

**Rate Limit Exceeded:**
- **Status Code:** `429 Too Many Requests`
- **Trigger:** An IP address exceeds the 100 requests/day limit.
```json
{
    "status": "error",
    "message": "Too many requests. Please try again after 24 hours."
}
```

---

## Running the Project Locally

If you wish to run your own instance of this API, follow these steps.

#### Prerequisites

-   [Node.js](https://nodejs.org/) (v16 or higher)
-   npm

#### Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/elvishpatel/disposable-email-checker-api.git
    cd disposable-email-checker-api
    ```

2.  **Install dependencies:**
    ```bash
    npm install
    ```

3.  **Configure your domain list:**
    Ensure you have a `disposable_domains.json` file in the root directory containing an array of domain strings.

4.  **Run the server:**
    ```bash
    node index.js
    ```
    The server will start locally on `http://localhost:3000`.

---

## Technology Stack

-   **Backend:** Node.js
-   **Framework:** Express.js
-   **Hosting:** Render
-   **Language:** JavaScript

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

---

## License

This project is licensed under the MIT License.
---
Developed with ❤ by Elvish Patel
