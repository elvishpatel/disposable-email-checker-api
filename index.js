// Import the Express library
const express = require('express');
// Import the file system library to read/write our data
const fs = require('fs');

// Initialize the Express app
const app = express();
// Use a port provided by the hosting service, or 3000 for local development
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON request bodies
app.use(express.json());

// --- IMPORTANT: Trust proxy to get correct IP on hosting platforms ---
// Services like Render or Heroku use a proxy. This line ensures req.ip gives the real user IP.
app.set('trust proxy', 1);

// --- Load Domains into a High-Speed Set ---
let disposableDomains = new Set();
const domainsFilePath = 'disposable_domains.json';
if (fs.existsSync(domainsFilePath)) {
    try {
        const data = fs.readFileSync(domainsFilePath, 'utf8');
        const domainArray = JSON.parse(data);
        disposableDomains = new Set(domainArray);
        console.log(`Successfully loaded ${disposableDomains.size} disposable domains.`);
    } catch (err) {
        console.error("Error reading or parsing the domain list file:", err);
        process.exit(1); // Exit if we can't load the domains
    }
} else {
    console.error(`Error: ${domainsFilePath} not found.`);
    process.exit(1);
}

// --- Rate Limiting Middleware ---
const RATE_LIMIT_FILE = './rate_limit_data.json';
const MAX_REQUESTS_PER_DAY = 100;

const rateLimiter = (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    let records = {};

    // Read the existing records from the file
    try {
        if (fs.existsSync(RATE_LIMIT_FILE)) {
            const data = fs.readFileSync(RATE_LIMIT_FILE, 'utf8');
            records = JSON.parse(data);
        }
    } catch (err) {
        console.error("Error reading rate limit file:", err);
    }

    const userRecord = records[ip];

    // If user has a record and it's not expired
    if (userRecord && now < userRecord.resetTime) {
        if (userRecord.count >= MAX_REQUESTS_PER_DAY) {
            // Limit exceeded
            return res.status(429).json({
                status: "error",
                message: "Too many requests. Please try again after 24 hours."
            });
        }
        // Increment count
        userRecord.count++;
    } else {
        // First request of the day for this user
        records[ip] = {
            count: 1,
            resetTime: now + (24 * 60 * 60 * 1000) // Set reset time 24 hours from now
        };
    }

    // Save the updated records back to the file
    try {
        fs.writeFileSync(RATE_LIMIT_FILE, JSON.stringify(records, null, 2));
    } catch (err) {
        console.error("Error writing to rate limit file:", err);
    }

    // Proceed to the API endpoint
    next();
};


// --- API Endpoint Definition ---
// We add our 'rateLimiter' middleware right before our main endpoint logic
app.post('/v1/verify', rateLimiter, (req, res) => {
    const { email } = req.body;

    if (!email || typeof email !== 'string') {
        return res.status(400).json({
            status: "error",
            message: "Invalid input. Please provide an email in the request body."
        });
    }

    const domain = email.split('@')[1];
    if (!domain) {
        return res.status(400).json({
            status: "error",
            message: "Invalid email format."
        });
    }

    const isDisposable = disposableDomains.has(domain.toLowerCase());

    if (isDisposable) {
        res.status(200).json({
            status: "invalid",
            message: "Disposable or temporary email domain found.",
            email: email,
            domain: domain,
            is_disposable: true
        });
    } else {
        res.status(200).json({
            status: "valid",
            message: "Email domain appears to be valid.",
            email: email,
            domain: domain,
            is_disposable: false
        });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});