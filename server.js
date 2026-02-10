const express = require('express');
const mysql = require('mysql2/promise'); 
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'your_secret_key_change_this_later'; 
const app = express();
const PORT = 5000;

app.use(express.json());


const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',  
    database: 'authentication',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});




const authenticateToken = (req, res, next) => {
    try {
        
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; 
        
        if (!token) {
            return res.status(401).json({
                success: false,
                error: 'Access denied. No token provided.'
            });
        }
        
        
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json({
                    success: false,
                    error: 'Invalid or expired token'
                });
            }
            
           
            req.user = user;
            next(); 
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Authentication error'
        });
    }
};



const checkRole = (...allowedRoles) => {
    return (req, res, next) => {
        try {
            // User should already be attached by authenticateToken middleware
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    error: 'Authentication required'
                });
            }
            
            // Check if user's role is in the allowed roles list
            if (!allowedRoles.includes(req.user.role)) {
                return res.status(403).json({
                    success: false,
                    error: `Access denied. Required roles: ${allowedRoles.join(', ')}`,
                    yourRole: req.user.role
                });
            }
            
            next(); // User has required role
        } catch (error) {
            res.status(500).json({
                success: false,
                error: 'Authorization error'
            });
        }
    };
};



const checkDepartment = (...allowedDepartments) => {
    return (req, res, next) => {
        try {
            // User should already be attached by authenticateToken middleware
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    error: 'Authentication required'
                });
            }
            
            // Check if user's department is in allowed list
            if (!allowedDepartments.includes(req.user.department)) {
                return res.status(403).json({
                    success: false,
                    error: `Access denied. Required departments: ${allowedDepartments.join(', ')}`,
                    yourDepartment: req.user.department
                });
            }
            
            next(); // User has required department
        } catch (error) {
            res.status(500).json({
                success: false,
                error: 'Authorization error'
            });
        }
    };
};



const checkOwnershipOrAdmin = (req, res, next) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                error: 'Authentication required'
            });
        }
        
        // Get the requested user ID from URL parameter
        const requestedUserId = parseInt(req.params.userId);
        
        // Check if it's a valid number
        if (isNaN(requestedUserId)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid user ID'
            });
        }
        
        // Allow if: user is admin OR user is accessing their own data
        if (req.user.role === 'admin' || req.user.userId === requestedUserId) {
            return next();
        }
        
        // Otherwise, deny access
        return res.status(403).json({
            success: false,
            error: 'Access denied. You can only access your own data.',
            yourUserId: req.user.userId,
            requestedUserId: requestedUserId
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Authorization error'
        });
    }
};


const checkWorkingHours = (req, res, next) => {
    try {
        const now = new Date();
        const currentHour = now.getHours(); 
        const currentDay = now.getDay(); 
        
       
        const isWeekday = currentDay >= 1 && currentDay <= 5;
        
       
        const isWorkingHour = currentHour >= 9 && currentHour < 17;
        
        if (!isWeekday || !isWorkingHour) {
            return res.status(403).json({
                success: false,
                error: 'Access allowed only during working hours (Mon-Fri, 9 AM - 5 PM)',
                currentTime: now.toLocaleString(),
                currentHour: currentHour,
                currentDay: currentDay
            });
        }
        
        next(); 
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Authorization error'
        });
    }
};


app.get('/my-profile', authenticateToken, (req, res) => {
    res.json({
        success: true,
        message: 'Your profile',
        user: req.user
    });
});




app.get('/users/:userId', authenticateToken, checkOwnershipOrAdmin, async (req, res) => {
    try {
        const userId = parseInt(req.params.userId);
        
        const [users] = await pool.query(
            'SELECT id, username, role, department, created_at FROM users WHERE id = ?',
            [userId]
        );
        
        if (users.length === 0) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }
        
        res.json({
            success: true,
            user: users[0]
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Database error'
        });
    }
});


app.get('/reports/daily', authenticateToken, checkWorkingHours, (req, res) => {
    res.json({
        success: true,
        message: 'Daily Report (available only during working hours)',
        report: {
            date: new Date().toISOString().split('T')[0],
            data: { sales: 15000, expenses: 8000, profit: 7000 }
        },
        user: req.user
    });
});



app.get('/reports/executive', 
    authenticateToken,                   
    checkRole('admin', 'manager'),       
    checkDepartment('Management', 'IT', 'Finance'),
    checkWorkingHours,                    
    (req, res) => {
        res.json({
            success: true,
            message: 'Executive Report (multiple rules passed!)',
            report: {
                confidential: true,
                summary: 'Quarterly performance metrics',
                accessLevel: 'Executive'
            },
            user: req.user
        });
    }
);




app.get('/profile', authenticateToken, (req, res) => {
    res.json({
        success: true,
        message: 'This is your protected profile',
        user: req.user // From middleware
    });
});


app.get('/', (req, res) => {
    res.send('Server is working!');
});


app.get('/test-db', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT "Database connected!" AS message');
        res.json({ success: true, data: rows });
    } catch (error) {
        res.status(500).json({ 
            success: false, 
            error: 'Database connection failed',
            details: error.message 
        });
    }
});



app.get('/setup-table', async (req, res) => {
    try {
        const createTableSQL = `
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('admin', 'user', 'manager') NOT NULL,
                department VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `;
        
        await pool.query(createTableSQL);
        res.json({ success: true, message: 'Users table created or already exists' });
    } catch (error) {
        res.status(500).json({ 
            success: false, 
            error: 'Table creation failed',
            details: error.message 
        });
    }
});


app.get('/check-table', async (req, res) => {
    try {
        const [rows] = await pool.query('DESCRIBE users');
        res.json({ success: true, tableStructure: rows });
    } catch (error) {
        res.status(500).json({ 
            success: false, 
            error: 'Table check failed',
            details: error.message 
        });
    }
});

app.get('/admin/dashboard', authenticateToken, checkRole('admin'), (req, res) => {
    res.json({
        success: true,
        message: 'Welcome to Admin Dashboard',
        user: req.user
    });
});

app.get('/management/reports', authenticateToken, checkRole('admin', 'manager'), (req, res) => {
    res.json({
        success: true,
        message: 'Management Reports',
        user: req.user
    });
});

app.get('/user/dashboard', authenticateToken, (req, res) => {
    res.json({
        success: true,
        message: 'Welcome to User Dashboard',
        user: req.user
    });
});

app.get('/finance/reports', authenticateToken, checkDepartment('Finance'), (req, res) => {
    res.json({
        success: true,
        message: 'Finance Department Reports',
        user: req.user
    });
});

app.get('/it/tools', authenticateToken, checkDepartment('IT'), (req, res) => {
    res.json({
        success: true,
        message: 'IT Tools Dashboard',
        user: req.user
    });
});

app.get('/hr/portal', authenticateToken, checkDepartment('HR', 'Management', 'Admin'), (req, res) => {
    res.json({
        success: true,
        message: 'HR Portal',
        user: req.user
    });
});

app.post('/register', async (req, res) => {
    try {
        // 1. Get data from request body
        const { username, password, role, department } = req.body;
        
        // 2. Check if all required fields are present
        if (!username || !password || !role || !department) {
            return res.status(400).json({
                success: false,
                error: 'All fields are required: username, password, role, department'
            });
        }
        
        // 3. Check if role is valid
        const validRoles = ['admin', 'user', 'manager'];
        if (!validRoles.includes(role)) {
            return res.status(400).json({
                success: false,
                error: 'Role must be: admin, user, or manager'
            });
        }
        
        // 4. Hash the password
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        
        // 5. Save to database
        const [result] = await pool.query(
            'INSERT INTO users (username, password_hash, role, department) VALUES (?, ?, ?, ?)',
            [username, passwordHash, role, department]
        );
        
        // 6. Success response
        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            userId: result.insertId
        });

        
    } catch (error) {
        // 7. Handle duplicate username error
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({
                success: false,
                error: 'Username already exists'
            });
        }
        res.status(500).json({ error: error.message });
    }
});



app.post('/login', async (req, res) => {
    try {
        
        const { username, password } = req.body;
        
        
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                error: 'Username and password are required'
            });
        }
        
        
        const [users] = await pool.query(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );
        
        
        if (users.length === 0) {
            return res.status(401).json({
                success: false,
                error: 'Invalid username or password'
            });
        }
        
        const user = users[0];
        
        
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                error: 'Invalid username or password'
            });
        }
        
        
        const token = jwt.sign(
            {
                userId: user.id,
                username: user.username,
                role: user.role,
                department: user.department
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
                res.json({
            success: true,
            message: 'Login successful',
            token: token,
          
        });
        
    } catch (error) {
        console.error("Login error:", error.message);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error'
        });
    }
}); 

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
