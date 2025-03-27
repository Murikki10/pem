require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';


// 創建數據庫連接池
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'fyp.ch2yo0q2w1xc.ap-southeast-2.rds.amazonaws.com',
    user: process.env.DB_USER || 'admin',
    password: process.env.DB_PASSWORD || 'Iveisrubbish',
    database: process.env.DB_NAME || 'fyp',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});


// 導出 pool 同 JWT_SECRET 俾其他檔案用
exports.pool = pool;
exports.JWT_SECRET = JWT_SECRET;

// Middleware
app.use(helmet());
app.use(cors());
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Auth Middleware
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ message: 'Authentication token required' });
        }

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json({ message: 'Invalid or expired token' });
            }
            req.user = user;
            next();
        });
    } catch (error) {
        res.status(401).json({ message: 'Authentication failed' });
    }
};

// 導出 authenticateToken
exports.authenticateToken = authenticateToken;

// 引入路由
const postsRouter = require('./routes/posts'); // 確保文件名和路徑正確
app.use('/api', postsRouter);

// 註冊 API
app.post('/api/auth/register', async (req, res) => {
    try {
        const { userName, firstName, lastName, email, phone, userPw } = req.body;

        if (!userName || !firstName || !lastName || !email || !userPw) {
            return res.status(400).json({ 
                message: 'Username, first name, last name, email and password are required.' 
            });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json('Invalid email format.');
        }

        const connection = await pool.getConnection();

        try {
            const [existingUsers] = await connection.query(
                'SELECT * FROM user WHERE email = ? OR userName = ?',
                [email, userName]
            );

            if (existingUsers.length > 0) {
                if (existingUsers[0].email === email) {
                    return res.status(409).json('Email already registered.');
                }
                if (existingUsers[0].userName === userName) {
                    return res.status(409).json('Username already taken.');
                }
            }

            const hashedPassword = await bcrypt.hash(userPw, 10);

            const [result] = await connection.query(
                `INSERT INTO user (
                    userName, firstName, lastName, email, phone, userPw,
                    role, canManageUsers, canManageBoards, canManagePosts, canBanUsers,
                    visibility, followersCount, followingCount, postsCount, isActive,
                    createdAt, updatedAt
                ) VALUES (
                    ?, ?, ?, ?, ?, ?,
                    'user', FALSE, FALSE, FALSE, FALSE,
                    'public', 0, 0, 0, TRUE,
                    NOW(), NOW()
                )`,
                [userName, firstName, lastName, email, phone, hashedPassword]
            );

            const token = jwt.sign(
                { 
                    userId: result.insertId,
                    userName: userName,
                    email: email,
                    role: 'user',
                    permissions: {
                        canManageUsers: false,
                        canManageBoards: false,
                        canManagePosts: false,
                        canBanUsers: false
                    }
                },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.status(201).json({
                message: 'Registration successful',
                token: token,
                user: {
                    userId: result.insertId,
                    userName: userName,
                    firstName: firstName,
                    email: email,
                    role: 'user',
                    visibility: 'public'
                }
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error occurred.' });
    }
});

// 登入 API
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, userPw } = req.body;

        if (!email || !userPw) {
            return res.status(400).json({ message: 'Email and password are required.' });
        }

        const connection = await pool.getConnection();

        try {
            const [users] = await connection.query(
                `SELECT 
                    userId, userName, firstName, lastName, email, userPw,
                    role, canManageUsers, canManageBoards, canManagePosts, canBanUsers,
                    visibility, isActive
                FROM user 
                WHERE email = ? AND isActive = TRUE`,
                [email]
            );

            if (users.length === 0) {
                return res.status(401).json({ message: 'Invalid credentials.' });
            }

            const user = users[0];

            const validPassword = await bcrypt.compare(userPw, user.userPw);
            if (!validPassword) {
                return res.status(401).json({ message: 'Invalid credentials.' });
            }

            await connection.query(
                'UPDATE user SET lastLoginAt = NOW(), updatedAt = NOW() WHERE userId = ?',
                [user.userId]
            );

            const token = jwt.sign(
                {
                    userId: user.userId,
                    userName: user.userName,
                    email: user.email,
                    role: user.role,
                    permissions: {
                        canManageUsers: user.canManageUsers,
                        canManageBoards: user.canManageBoards,
                        canManagePosts: user.canManagePosts,
                        canBanUsers: user.canBanUsers
                    }
                },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.status(200).json({
                message: 'Login successful',
                token: token,
                user: {
                    userId: user.userId,
                    userName: user.userName,
                    firstName: user.firstName,
                    email: user.email,
                    role: user.role,
                    visibility: user.visibility
                }
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error occurred.' });
    }
});

// 獲取用戶資料 API
app.get('/api/users/profile', authenticateToken, async (req, res) => {
    try {
        const connection = await pool.getConnection();
        
        try {
            const [users] = await connection.query(
                `SELECT 
                    userId, userName, firstName, lastName, email, phone,
                    role, visibility, avatarUrl, backgroundUrl, bio,
                    location, followersCount, followingCount, postsCount,
                    createdAt
                FROM user 
                WHERE userId = ? AND isActive = TRUE`,
                [req.user.userId]
            );

            if (users.length === 0) {
                return res.status(404).json({ message: 'User not found.' });
            }

            res.status(200).json({ user: users[0] });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ message: 'Server error occurred.' });
    }
});

// 更新用戶資料 API
app.put('/api/users/profile', authenticateToken, async (req, res) => {
    try {
        const { firstName, lastName, email, phone, visibility, bio, location } = req.body;

        const connection = await pool.getConnection();
        
        try {
            if (email) {
                const [existingUsers] = await connection.query(
                    'SELECT userId FROM user WHERE email = ? AND userId != ?',
                    [email, req.user.userId]
                );

                if (existingUsers.length > 0) {
                    return res.status(409).json({ message: 'Email already in use.' });
                }
            }

            const [result] = await connection.query(
                `UPDATE user 
                SET 
                    firstName = COALESCE(?, firstName),
                    lastName = COALESCE(?, lastName),
                    email = COALESCE(?, email),
                    phone = COALESCE(?, phone),
                    visibility = COALESCE(?, visibility),
                    bio = COALESCE(?, bio),
                    location = COALESCE(?, location),
                    updatedAt = NOW()
                WHERE userId = ?`,
                [firstName, lastName, email, phone, visibility, bio, location, req.user.userId]
            );

            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'User not found.' });
            }

            const [updatedUsers] = await connection.query(
                `SELECT 
                    userId, userName, firstName, lastName, email, phone,
                    role, visibility, bio, location
                FROM user 
                WHERE userId = ?`,
                [req.user.userId]
            );

            res.status(200).json({
                message: 'Profile updated successfully',
                user: updatedUsers[0]
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ message: 'Server error occurred.' });
    }
});

// 優雅處理錯誤
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

// 啟動服務器
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

// 優雅關閉
process.on('SIGTERM', async () => {
    try {
        await pool.end();
        console.log('Database pool closed.');
        process.exit(0);
    } catch (error) {
        console.error('Error closing database pool:', error);
        process.exit(1);
    }
});

// 更改密碼 API
app.post('/api/user/update-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword, confirmPassword } = req.body;

        // 基本驗證
        if (!currentPassword || !newPassword || !confirmPassword) {
            return res.status(400).json({ 
                success: false,
                message: 'All password fields are required.' 
            });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ 
                success: false,
                message: 'New passwords do not match.' 
            });
        }

        const connection = await pool.getConnection();
        
        try {
            // 檢查現有密碼
            const [users] = await connection.query(
                'SELECT userPw FROM user WHERE userId = ? AND isActive = TRUE',
                [req.user.userId]
            );

            if (users.length === 0) {
                return res.status(404).json({ 
                    success: false,
                    message: 'User not found.' 
                });
            }

            const validPassword = await bcrypt.compare(currentPassword, users[0].userPw);
            if (!validPassword) {
                return res.status(401).json({ 
                    success: false,
                    message: 'Current password is incorrect.' 
                });
            }

            // 加密新密碼
            const hashedNewPassword = await bcrypt.hash(newPassword, 10);

            // 更新密碼
            const [result] = await connection.query(
                `UPDATE user 
                SET userPw = ?, updatedAt = NOW()
                WHERE userId = ?`,
                [hashedNewPassword, req.user.userId]
            );

            if (result.affectedRows === 0) {
                return res.status(404).json({ 
                    success: false,
                    message: 'Failed to update password.' 
                });
            }

            res.status(200).json({
                success: true,
                message: 'Password updated successfully'
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Password update error:', error);
        res.status(500).json({ 
            success: false,
            message: 'Server error occurred.' 
        });
    }
});

// 獲取用戶資料 API (GET /api/user/profile)
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        // 從資料庫獲取連接
        const connection = await pool.getConnection();
        
        try {
            // SQL 查詢語句
            const [users] = await connection.query(
                `SELECT 
                    userId, userName, firstName, lastName, email, phone,
                    role, canManageUsers, canManageBoards, canManagePosts, canBanUsers,
                    visibility, avatarUrl, backgroundUrl, bio,
                    location, followersCount, followingCount, postsCount,
                    isActive, createdAt
                FROM user 
                WHERE userId = ? AND isActive = TRUE`,
                [req.user.userId] // 使用身份驗證 Token 獲取 userId
            );

            // 如果未找到用戶，返回 404
            if (users.length === 0) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'User not found.' 
                });
            }

            // 返回用戶資料
            res.status(200).json({ 
                success: true, 
                data: users[0] 
            });
        } finally {
            connection.release(); // 確保釋放資料庫連接
        }
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error occurred.' 
        });
    }
});

app.post('/api/createPlan', async (req, res) => {
    const { name, type, level } = req.body;

    // 檢查請求頭中的 Token
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        console.warn('Missing authorization token.');
        return res.status(401).json({ message: 'Authorization token is required.' });
    }

    // 從 Token 中解析用戶 ID
    const userId = getUserIdFromToken(token);
    if (!userId) {
        console.warn('Invalid token or user ID not found.');
        return res.status(401).json({ message: 'Invalid token or user ID not found.' });
    }

    // 檢查請求體參數
    if (!name || !type || !level) {
        console.warn('Missing required parameters. Name, type, and level are required.');
        return res.status(400).json({ message: 'Name, type, and level are required.' });
    }

    const connection = await pool.getConnection();
    try {
        // 插入計劃名稱
        const [result] = await connection.query('INSERT INTO plans (name) VALUES (?)', [name]);
        const planId = result.insertId;

        console.log('Plan created with ID:', planId);

        // 忽略大小寫進行查詢視頻
        const [videos] = await connection.query(
            'SELECT id FROM videos WHERE LOWER(type) = LOWER(?) AND LOWER(level) = LOWER(?) LIMIT 100',
            [type, level]
        );

        if (videos.length === 0) {
            console.warn('No videos found for type:', type, 'and level:', level);
            return res.status(404).json({ message: 'No videos found for the selected type and level.' });
        }

        // 插入計劃與視頻的關聯
        const planVideos = videos.map(video => [planId, video.id]);
        await connection.query('INSERT INTO plan_videos (plan_id, video_id) VALUES ?', [planVideos]);

        // 插入用戶與計劃的關聯
        await connection.query('INSERT INTO user_plans (user_id, plan_id) VALUES (?, ?)', [userId, planId]);

        console.log('Plan successfully created and linked to videos and user.');
        res.status(201).json({ message: 'Plan created and assigned successfully!', planId });
    } catch (error) {
        console.error('Error creating plan:', error);
        res.status(500).json({ message: 'Failed to create plan.' });
    } finally {
        connection.release();
    }
});


app.post('/api/assignPlan', async (req, res) => {
    const { planId } = req.body;

    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Authorization token is required.' });
    }

    const userId = getUserIdFromToken(token);
    if (!userId) {
        console.error('Failed to extract userId from token:', token);
        return res.status(401).json({ message: 'Invalid token or user ID not found.' });
    }

    if (!planId || typeof planId !== 'number') {
        return res.status(400).json({ message: 'Valid Plan ID is required.' });
    }

    const connection = await pool.getConnection();
    try {
        const [planExists] = await connection.query('SELECT id FROM plans WHERE id = ?', [planId]);
        if (planExists.length === 0) {
            return res.status(404).json({ message: 'Plan not found.' });
        }

        try {
            await connection.query('INSERT INTO user_plans (user_id, plan_id) VALUES (?, ?)', [userId, planId]);
            res.status(201).json({ message: 'Plan assigned to user successfully!' });
        } catch (error) {
            if (error.code === 'ER_DUP_ENTRY') {
                console.warn('Plan already assigned to user:', { userId, planId });
                return res.status(409).json({ message: 'This plan is already assigned to the user.' });
            }
            throw error;
        }
    } catch (error) {
        console.error('Error assigning plan to user:', { userId, planId, error });
        res.status(500).json({ message: 'Failed to assign plan to user.' });
    } finally {
        connection.release();
    }
});


app.post('/api/user/plans', async (req, res) => {
    // 檢查請求頭中的 Token
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        console.warn('Missing authorization token.');
        return res.status(401).json({ message: 'Authorization token is required.' });
    }

    // 從 Token 中解析用戶 ID
    const userId = getUserIdFromToken(token);
    if (!userId) {
        console.warn('Invalid token or user ID not found.');
        return res.status(401).json({ message: 'Invalid token or user ID not found.' });
    }

    const connection = await pool.getConnection();
    try {
        // 查詢用戶的計劃
        const [results] = await connection.query(
            `SELECT p.id AS planId, p.name AS planName
             FROM plans p
             INNER JOIN user_plans up ON p.id = up.plan_id
             WHERE up.user_id = ? LIMIT 100`,
            [userId]
        );

        if (results.length === 0) {
            console.warn('No plans found for user ID:', userId);
            return res.status(404).json({ message: 'No plans found for this user.' });
        }

        console.log('Plans retrieved for user ID:', userId, 'Count:', results.length);
        res.status(200).json(results);
    } catch (error) {
        console.error('Error retrieving user plans:', error);
        res.status(500).json({ message: 'Failed to retrieve user plans.' });
    } finally {
        connection.release();
    }
});


app.post('/api/plan/videos', async (req, res) => {
    const { planId } = req.body;

    // 添加更詳細的日誌
    console.log("Received Plan ID:", planId);

    if (!planId || planId <= 0) {
        console.log("Invalid Plan ID:", planId); // 記錄無效的 planId
        return res.status(400).json({ message: 'Invalid Plan ID.' });
    }

    const connection = await pool.getConnection();
    try {
        // 確保 planId 存在
        const [plan] = await connection.query('SELECT id FROM plans WHERE id = ?', [planId]);
        if (plan.length === 0) {
            console.log("Plan not found for Plan ID:", planId);
            return res.status(404).json({ message: 'Plan not found.' });
        }

        // 查詢視頻數據
        const [videos] = await connection.query(
        `SELECT v.id, v.title, v.type, v.duration, v.description, v.url, v.thumbnail, v.level
        FROM videos v
        INNER JOIN plan_videos pv ON v.id = pv.video_id
        WHERE pv.plan_id = ?`,
            [planId]
        );

        if (videos.length === 0) {
            console.log("No videos found for Plan ID:", planId);
            return res.status(404).json({ message: 'No videos found for this plan.' });
        }

        res.status(200).json(videos);
    } catch (error) {
        console.error('Error fetching plan videos:', error);
        res.status(500).json({ message: 'Failed to fetch plan videos.' });
    } finally {
        connection.release();
    }
});


// 定義解析 Token 的方法
function getUserIdFromToken(token) {
    try {
        const decoded = jwt.verify(token, JWT_SECRET); // 使用環境變量中的密鑰
        return decoded.userId;
    } catch (error) {
        console.error('Token parsing failed:', error.message);
        return null;
    }
}

// Get all workout videos
app.get('/api/videos', async (req, res) => {
    const limit = parseInt(req.query.limit) || 20;
    const offset = parseInt(req.query.offset) || 0;
    const type = req.query.type || null;

    const connection = await pool.getConnection();
    try {
        let query = 'SELECT id, title, type, duration, description, url, thumbnail, level FROM videos';
        const params = [];

        if (type) {
            query += ' WHERE type = ?';
            params.push(type);
        }

        query += ' LIMIT ? OFFSET ?';
        params.push(limit, offset);

        const [results] = await connection.query(query, params);

        if (results.length === 0) {
            return res.status(404).json({ message: 'No videos found.' });
        }

        res.status(200).json(results);
    } catch (error) {
        console.error('Error retrieving videos:', error);
        res.status(500).json({ message: 'Failed to retrieve videos.' });
    } finally {
        connection.release();
    }
});

// Like a video
app.post('/api/videos/like', async (req, res) => {
    const { userId, videoId } = req.body;

    if (!userId || !videoId) {
        return res.status(400).json({ message: 'userId and videoId are required.' });
    }

    const connection = await pool.getConnection();
    try {
        await connection.query('INSERT INTO videoLikes (user_id, video_id) VALUES (?, ?)', [userId, videoId]);
        res.status(201).json({ message: 'Video liked successfully.' });
    } catch (error) {
        console.error('Error liking video:', error);
        res.status(500).json({ message: 'Failed to like video.' });
    } finally {
        connection.release();
    }
});

// Unlike a video
app.post('/api/videos/unlike', async (req, res) => {
    const { userId, videoId } = req.body;

    if (!userId || !videoId) {
        return res.status(400).json({ message: 'userId and videoId are required.' });
    }

    const connection = await pool.getConnection();
    try {
        const [results] = await connection.query(
            'DELETE FROM videoLikes WHERE user_id = ? AND video_id = ?',
            [userId, videoId]
        );

        if (results.affectedRows === 0) {
            return res.status(404).json({ message: 'No like record found to delete.' });
        }

        res.status(200).json({ message: 'Video unliked successfully.' });
    } catch (error) {
        console.error('Error unliking video:', error);
        res.status(500).json({ message: 'Failed to unlike video.' });
    } finally {
        connection.release();
    }
});

// Get liked videos for a user
app.get('/api/videos/liked', async (req, res) => {
    const { userId } = req.query;

    if (!userId) {
        return res.status(400).json({ message: 'userId is required.' });
    }

    const connection = await pool.getConnection();
    try {
        const [results] = await connection.query(
            `SELECT 
                videos.id, videos.title, videos.type, videos.duration, 
                videos.description, videos.url, videos.thumbnail, videos.level
             FROM videos
             INNER JOIN videoLikes ON videos.id = videoLikes.video_id
             WHERE videoLikes.user_id = ?`,
            [userId]
        );

        res.status(200).json(results);
    } catch (error) {
        console.error('Error retrieving liked videos:', error);
        res.status(500).json({ message: 'Failed to retrieve liked videos.' });
    } finally {
        connection.release();
    }
});