const express = require('express');
const router = express.Router();
const { pool, authenticateToken } = require('../server');

// 創建帖子
router.post('/posts', authenticateToken, async (req, res) => {
    try {
        const { boardId, title, content, type = 'text', visibility = 'public', images = [] } = req.body;

        if (!boardId || !title || !content) {
            return res.status(400).json({ message: 'Board ID, title and content are required.' });
        }

        const connection = await pool.getConnection();
        try {
            await connection.beginTransaction();

            const [board] = await connection.query(
                `SELECT isPrivate FROM board WHERE boardId = ? AND isActive = TRUE`,
                [boardId]
            );
            if (board.length === 0) {
                return res.status(404).json({ message: 'Board not found.' });
            }

            if (board[0].isPrivate) {
                const [hasAccess] = await connection.query(
                    `SELECT 1 FROM boardModerators WHERE boardId = ? AND userId = ?`,
                    [boardId, req.user.userId]
                );
                if (hasAccess.length === 0) {
                    return res.status(403).json({ message: 'No permission to post in this board.' });
                }
            }

            const [postResult] = await connection.query(
                `INSERT INTO post (boardId, userId, title, content, type, visibility, status) 
                 VALUES (?, ?, ?, ?, ?, ?, 'published')`,
                [boardId, req.user.userId, title, content, type, visibility]
            );
            const postId = postResult.insertId;

            if (images.length > 0) {
                const imageValues = images.map((url, index) => [postId, url, index]);
                await connection.query(
                    `INSERT INTO postImages (postId, imageUrl, sortOrder) VALUES ?`,
                    [imageValues]
                );
            }

            await connection.query(`UPDATE board SET postsCount = postsCount + 1 WHERE boardId = ?`, [boardId]);
            await connection.query(`UPDATE user SET postsCount = postsCount + 1 WHERE userId = ?`, [req.user.userId]);

            await connection.commit();
            res.status(201).json({
                message: 'Post created successfully.',
                post: {
                    postId,
                    title,
                    content,
                    type,
                    visibility,
                    createdAt: new Date().toISOString(),
                    images
                }
            });
        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Create post error:', error);
        res.status(500).json({ message: 'Server error occurred.' });
    }
});

// 獲取帖子列表
router.get('/posts', async (req, res) => {
    try {
        const { boardId, userId, q, page = 1, limit = 10 } = req.query;
        const offset = (page - 1) * limit;

        const connection = await pool.getConnection();
        try {
            let query = `
                SELECT 
                    p.postId, p.title, p.content, p.type, p.visibility, 
                    p.viewCount, p.likeCount, p.commentCount, p.createdAt,
                    u.userId AS authorId, u.userName AS authorName, u.avatarUrl AS authorAvatar,
                    b.boardId, b.boardName 
                FROM post p
                INNER JOIN user u ON p.userId = u.userId
                INNER JOIN board b ON p.boardId = b.boardId
                WHERE p.isDeleted = FALSE
            `;
            const params = [];

            if (boardId) {
                query += ' AND p.boardId = ?';
                params.push(boardId);
            }
            if (userId) {
                query += ' AND p.userId = ?';
                params.push(userId);
            }
            if (q) {
                query += ' AND MATCH(p.title, p.content) AGAINST(? IN BOOLEAN MODE)';
                params.push(q);
            }

            query += ' ORDER BY p.createdAt DESC LIMIT ? OFFSET ?';
            params.push(parseInt(limit), parseInt(offset));

            const [posts] = await connection.query(query, params);

            const [countResult] = await connection.query(
                `SELECT COUNT(*) AS total FROM post WHERE isDeleted = FALSE`
            );

            res.json({
                posts,
                pagination: {
                    current: parseInt(page),
                    pageSize: parseInt(limit),
                    total: Math.ceil(countResult[0].total / limit),
                    totalPosts: countResult[0].total
                }
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Fetch posts error:', error);
        res.status(500).json({ message: 'Server error occurred.' });
    }
});

// 獲取帖子詳情
router.get('/posts/:postId', async (req, res) => {
    try {
        const { postId } = req.params;

        const connection = await pool.getConnection();
        try {
            const [posts] = await connection.query(
                `SELECT 
                    p.postId, p.title, p.content, p.type, p.visibility,
                    p.viewCount + 1 AS viewCount, p.likeCount, p.commentCount, p.createdAt,
                    u.userId AS authorId, u.userName AS authorName, u.avatarUrl AS authorAvatar,
                    b.boardId, b.boardName,
                    GROUP_CONCAT(pi.imageUrl) AS imageUrls
                FROM post p
                INNER JOIN user u ON p.userId = u.userId
                INNER JOIN board b ON p.boardId = b.boardId
                LEFT JOIN postImages pi ON p.postId = pi.postId
                WHERE p.postId = ? AND p.isDeleted = FALSE
                GROUP BY p.postId`,
                [postId]
            );

            if (posts.length === 0) {
                return res.status(404).json({ message: 'Post not found.' });
            }

            const post = posts[0];
            post.imageUrls = post.imageUrls ? post.imageUrls.split(',') : [];

            // 更新瀏覽數
            await connection.query(`UPDATE post SET viewCount = viewCount + 1 WHERE postId = ?`, [postId]);

            res.json(post);
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Fetch post details error:', error);
        res.status(500).json({ message: 'Server error occurred.' });
    }
});

// 編輯帖子
router.put('/posts/:postId', authenticateToken, async (req, res) => {
    try {
        const { postId } = req.params;
        const { title, content, visibility, images = [] } = req.body;

        const connection = await pool.getConnection();
        try {
            await connection.beginTransaction();

            // 檢查帖子是否存在
            const [post] = await connection.query(
                `SELECT userId, boardId FROM post WHERE postId = ? AND isDeleted = FALSE`,
                [postId]
            );
            if (post.length === 0) {
                return res.status(404).json({ message: 'Post not found.' });
            }

            const postOwnerId = post[0].userId;

            // 檢查權限
            if (postOwnerId !== req.user.userId && req.user.role !== 'admin') {
                return res.status(403).json({ message: 'No permission to edit this post.' });
            }

            // 更新帖子
            await connection.query(
                `UPDATE post SET 
                    title = COALESCE(?, title), 
                    content = COALESCE(?, content), 
                    visibility = COALESCE(?, visibility), 
                    updatedAt = NOW() 
                 WHERE postId = ?`,
                [title, content, visibility, postId]
            );

            // 更新圖片
            await connection.query(`DELETE FROM postImages WHERE postId = ?`, [postId]);
            if (images.length > 0) {
                const imageValues = images.map((url, index) => [postId, url, index]);
                await connection.query(
                    `INSERT INTO postImages (postId, imageUrl, sortOrder) VALUES ?`,
                    [imageValues]
                );
            }

            await connection.commit();
            res.json({ message: 'Post updated successfully.' });
        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Update post error:', error);
        res.status(500).json({ message: 'Server error occurred.' });
    }
});

// 刪除帖子
router.delete('/posts/:postId', authenticateToken, async (req, res) => {
    try {
        const { postId } = req.params;

        const connection = await pool.getConnection();
        try {
            await connection.beginTransaction();

            // 檢查帖子是否存在
            const [post] = await connection.query(
                `SELECT userId, boardId FROM post WHERE postId = ? AND isDeleted = FALSE`,
                [postId]
            );
            if (post.length === 0) {
                return res.status(404).json({ message: 'Post not found.' });
            }

            const postOwnerId = post[0].userId;

            // 檢查權限
            if (postOwnerId !== req.user.userId && req.user.role !== 'admin') {
                return res.status(403).json({ message: 'No permission to delete this post.' });
            }

            // 軟刪除帖子
            await connection.query(
                `UPDATE post SET isDeleted = TRUE, updatedAt = NOW() WHERE postId = ?`,
                [postId]
            );

            // 更新統計數據
            await connection.query(
                `UPDATE user SET postsCount = postsCount - 1 WHERE userId = ?`,
                [postOwnerId]
            );
            await connection.query(
                `UPDATE board SET postsCount = postsCount - 1 WHERE boardId = ?`,
                [post[0].boardId]
            );

            await connection.commit();
            res.json({ message: 'Post deleted successfully.' });
        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Delete post error:', error);
        res.status(500).json({ message: 'Server error occurred.' });
    }
});

// 點贊/取消點贊帖子
router.post('/posts/:postId/toggle-like', authenticateToken, async (req, res) => {
    try {
        const { postId } = req.params;

        const connection = await pool.getConnection();
        try {
            await connection.beginTransaction();

            // 檢查帖子是否存在
            const [post] = await connection.query(
                `SELECT userId FROM post WHERE postId = ? AND isDeleted = FALSE`,
                [postId]
            );
            if (post.length === 0) {
                return res.status(404).json({ message: 'Post not found.' });
            }

            const postOwnerId = post[0].userId;

            // 檢查是否已點贊
            const [likes] = await connection.query(
                `SELECT likeId FROM postLikes WHERE postId = ? AND userId = ?`,
                [postId, req.user.userId]
            );

            let liked = false;
            if (likes.length > 0) {
                // 取消點贊
                await connection.query(
                    `DELETE FROM postLikes WHERE postId = ? AND userId = ?`,
                    [postId, req.user.userId]
                );
                await connection.query(
                    `UPDATE post SET likeCount = likeCount - 1 WHERE postId = ?`,
                    [postId]
                );
            } else {
                // 點贊
                await connection.query(
                    `INSERT INTO postLikes (postId, userId) VALUES (?, ?)`,
                    [postId, req.user.userId]
                );
                await connection.query(
                    `UPDATE post SET likeCount = likeCount + 1 WHERE postId = ?`,
                    [postId]
                );
                liked = true;

                // 發送通知給帖子作者
                if (postOwnerId !== req.user.userId) {
                    await connection.query(
                        `INSERT INTO notification (userId, type, actorId, targetId, content) 
                         VALUES (?, 'like_post', ?, ?, ?)`,
                        [
                            postOwnerId,
                            req.user.userId,
                            postId,
                            `${req.user.userName} liked your post`
                        ]
                    );
                }
            }

            await connection.commit();
            res.json({ message: liked ? 'Post liked.' : 'Post unliked.' });
        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Toggle like error:', error);
        res.status(500).json({ message: 'Server error occurred.' });
    }
});

// 關注/取消關注帖子
router.post('/posts/:postId/toggle-follow', authenticateToken, async (req, res) => {
    try {
        const { postId } = req.params;

        const connection = await pool.getConnection();
        try {
            await connection.beginTransaction();

            // 檢查帖子是否存在
            const [post] = await connection.query(
                `SELECT postId FROM post WHERE postId = ? AND isDeleted = FALSE`,
                [postId]
            );
            if (post.length === 0) {
                return res.status(404).json({ message: 'Post not found.' });
            }

            // 檢查是否已關注
            const [follows] = await connection.query(
                `SELECT followId FROM postFollows WHERE postId = ? AND userId = ?`,
                [postId, req.user.userId]
            );

            let followed = false;
            if (follows.length > 0) {
                // 取消關注
                await connection.query(
                    `DELETE FROM postFollows WHERE postId = ? AND userId = ?`,
                    [postId, req.user.userId]
                );
            } else {
                // 關注
                await connection.query(
                    `INSERT INTO postFollows (postId, userId) VALUES (?, ?)`,
                    [postId, req.user.userId]
                );
                followed = true;
            }

            await connection.commit();
            res.json({ message: followed ? 'Post followed.' : 'Post unfollowed.' });
        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Toggle follow error:', error);
        res.status(500).json({ message: 'Server error occurred.' });
    }
});

// 搜尋帖子
router.get('/posts/search', async (req, res) => {
    try {
        const { q, page = 1, limit = 10 } = req.query;
        const offset = (page - 1) * limit;

        if (!q || q.trim() === '') {
            return res.status(400).json({ message: 'Search query is required.' });
        }

        const connection = await pool.getConnection();
        try {
            // 使用全文檢索匹配標題和內容
            const query = `
                SELECT 
                    p.postId, p.title, p.content, p.type, p.visibility, 
                    p.viewCount, p.likeCount, p.commentCount, p.createdAt,
                    u.userId AS authorId, u.userName AS authorName, u.avatarUrl AS authorAvatar,
                    b.boardId, b.boardName
                FROM post p
                INNER JOIN user u ON p.userId = u.userId
                INNER JOIN board b ON p.boardId = b.boardId
                WHERE p.isDeleted = FALSE
                  AND MATCH(p.title, p.content) AGAINST(? IN BOOLEAN MODE)
                ORDER BY p.createdAt DESC
                LIMIT ? OFFSET ?;
            `;
            const params = [q, parseInt(limit), parseInt(offset)];
            const [posts] = await connection.query(query, params);

            // 獲取符合條件的總數
            const [countResult] = await connection.query(
                `SELECT COUNT(*) AS total 
                 FROM post 
                 WHERE isDeleted = FALSE 
                   AND MATCH(title, content) AGAINST(? IN BOOLEAN MODE);`,
                [q]
            );

            res.json({
                posts,
                pagination: {
                    current: parseInt(page),
                    total: Math.ceil(countResult[0].total / limit),
                    totalPosts: countResult[0].total
                }
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Search posts error:', error);
        res.status(500).json({ message: 'Server error occurred.' });
    }
});

// 獲取所有分區
router.get('/boards', async (req, res) => {
    try {
        const connection = await pool.getConnection();
        try {
            const [boards] = await connection.query(
                `SELECT boardId, boardName FROM board WHERE isActive = TRUE`
            );

            res.json(boards);
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Fetch boards error:', error);
        res.status(500).json({ message: 'Server error occurred.' });
    }
});

module.exports = router;