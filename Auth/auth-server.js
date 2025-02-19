import express from "express";
import bcrypt from "bcrypt";
import JWT from "jsonwebtoken";
import { config } from "dotenv";

// Load environment variables
config();

// Validate required environment variables
if (!process.env.ACCESS_TOKEN_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
    console.error("Missing required environment variables.");
    process.exit(1);
}

const app = express();
app.use(express.json()); // Middleware to parse JSON request bodies

// Middleware to log request duration
app.use((req, res, next) => {
    const start = Date.now();
    res.on("finish", () => {
        const duration = Date.now() - start;
        console.log(`${req.method} ${req.url} - ${duration}ms`);
    });
    next();
});

// In-memory data stores (replace with a database in production)
const users = [
    { uid: "hashi", pwd: "$2b$10$exampleHashedPassword1" }, // Example hashed passwords
    { uid: "han", pwd: "$2b$10$exampleHashedPassword2" },
    { uid: "tom", pwd: "$2b$10$exampleHashedPassword3" },
];

const orders = [
    {
        id: "1023",
        uid: "tom",
        items: [
            {
                name: "HFS lightweight Road Running",
                single_price: "105.20",
                currency: "USD",
                count: "2",
            },
        ],
    },
];

// Helper function to mint access tokens
function mintAccessToken(user) {
    return JWT.sign({ uid: user.uid }, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "15s",
    });
}

let refresh_tokens = [];

// User login endpoint
app.post("/login", async (req, res) => {
    const { uid, pwd } = req.body;

    if (!uid || !pwd) {
        return res.status(400).json({ message: "Username and password required." });
    }

    const user = users.find((u) => u.uid === uid);
    if (!user) {
        return res.status(400).json({ message: "User not found." });
    }

    try {
        const isMatch = await bcrypt.compare(pwd, user.pwd);
        if (!isMatch) {
            return res.status(401).json({ message: "Invalid credentials." });
        }

        const accessToken = mintAccessToken(user);
        const refreshToken = JWT.sign({ uid: user.uid }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "20s" });

        refresh_tokens.push(refreshToken);
        res.json({ accessToken, refreshToken });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Internal server error." });
    }
});

// Token refresh endpoint
app.post("/token", (req, res) => {
    const { token: refresh_token } = req.body;

    if (!refresh_token) {
        return res.status(401).json({ message: "Refresh token required." });
    }

    if (!refresh_tokens.includes(refresh_token)) {
        return res.status(403).json({ message: "Invalid refresh token." });
    }

    JWT.verify(refresh_token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: "Expired or invalid refresh token." });
        }

        const accessToken = mintAccessToken({ uid: user.uid });
        res.json({ accessToken });
    });
});

// User registration endpoint
app.post("/users", async (req, res) => {
    const { uid, pwd } = req.body;

    if (!uid || !pwd) {
        return res.status(400).json({ message: "Username and password required." });
    }

    if (users.some((u) => u.uid === uid)) {
        return res.status(400).json({ message: "User already exists." });
    }

    try {
        const hashedPwd = await bcrypt.hash(pwd, 10);
        users.push({ uid, pwd: hashedPwd });
        res.status(201).json({ message: "User registered successfully." });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ message: "Internal server error." });
    }
});

// Get all users (for testing purposes)
app.get("/users", (req, res) => {
    res.json(users.map((u) => ({ uid: u.uid }))); // Exclude passwords
});

// Middleware to authenticate JWT tokens
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ message: "Access token required." });
    }

    JWT.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            console.error("Token verification error:", err);
            return res.status(403).json({ message: "Invalid or expired token." });
        }

        req.user = user;
        next();
    });
}

// Protected orders endpoint
app.get("/orders", authenticateToken, (req, res) => {
    const userOrders = orders.filter((order) => order.uid === req.user.uid);
    res.json(userOrders);
});

// Start the server
app.listen(3001, () => {
    console.log("Server is running on http://localhost:3001");
});
