var app = require('express')();
var server = require('http').createServer(app);
var io = require('socket.io')(server);
var server_time = require('moment');
require('moment-timezone');
server_time.tz.setDefault('Asia/Seoul');

const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(path.join(__dirname, 'data.sqlite'));

db.serialize(function () {
    db.run('PRAGMA journal_mode = WAL');
    db.run(
        'CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, passwordHash TEXT NOT NULL, name TEXT NOT NULL, school TEXT NOT NULL, studentNumber TEXT, createdAt INTEGER NOT NULL)'
    );
    db.run(
        'CREATE TABLE IF NOT EXISTS rooms (id TEXT PRIMARY KEY, name TEXT NOT NULL, ownerEmail TEXT NOT NULL, passwordHash TEXT NOT NULL, youtubeUrl TEXT, startTime INTEGER, endTime INTEGER, isRepeating INTEGER DEFAULT 0, repeatSchedule TEXT, createdAt INTEGER NOT NULL)'
    );
});

app.get('/', function (req, res) {
    res.redirect('/rooms');
});

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(
    session({
        secret: 'dev-secret',
        resave: false,
        saveUninitialized: false,
    })
);

let messageReactions = {};
let comments = {};
const roomJoinCounters = {}; // { [roomId]: number }
const roomParticipants = {}; // { [roomId]: Set<socketId> }

// Auto-close rooms when timer expires
setInterval(function() {
    const now = Date.now();
    db.all('SELECT id, endTime FROM rooms WHERE endTime IS NOT NULL AND endTime <= ?', [now], function(err, rooms) {
        if (err) return;
        rooms.forEach(room => {
            // Notify all participants that room has ended
            io.to(room.id).emit('roomExpired', { message: '방이 종료되었습니다.' });
            
            // Remove room from memory
            delete roomJoinCounters[room.id];
            delete roomParticipants[room.id];
            
            console.log('Room expired and closed:', room.id);
        });
    });
}, 60000); // Check every minute

function requireLogin(req, res, next) {
    if (req.session && req.session.userEmail) return next();
    res.redirect('/login');
}

// Auth pages
app.get('/signup', (req, res) => {
    res.sendFile(__dirname + '/signup.html');
});

app.post('/signup', async (req, res) => {
    const { email, password, name, school, studentNumber } = req.body || {};
    if (!email || !password || !name || !school || !studentNumber) return res.status(400).send('필수 항목 누락');
    
    // 학번 검증
    const fullStudentNumber = '20' + studentNumber;
    if (fullStudentNumber.length !== 7) {
        return res.status(400).send('학번이 잘못 입력되었습니다.');
    }
    
    db.get('SELECT email FROM users WHERE email = ?', [email], async function (err, row) {
        if (err) return res.status(500).send('서버 오류');
        if (row) return res.status(400).send('이미 존재하는 이메일');
        const passwordHash = await bcrypt.hash(password, 10);
        const createdAt = Date.now();
        db.run(
            'INSERT INTO users(email, passwordHash, name, school, studentNumber, createdAt) VALUES(?,?,?,?,?,?)',
            [email, passwordHash, name, school, fullStudentNumber, createdAt],
            function (err2) {
                if (err2) return res.status(500).send('서버 오류');
                res.redirect('/login');
            }
        );
    });
});

app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/login.html');
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body || {};
    db.get('SELECT * FROM users WHERE email = ?', [email], async function (err, user) {
        if (err) return res.status(500).send('서버 오류');
        if (!user) return res.status(401).send('이메일 또는 비밀번호 오류');
        const ok = await bcrypt.compare(password, user.passwordHash);
        if (!ok) return res.status(401).send('이메일 또는 비밀번호 오류');
        req.session.userEmail = user.email;
        res.redirect('/rooms');
    });
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login'));
});

// Rooms pages/APIs
app.get('/rooms', (req, res) => {
    res.sendFile(__dirname + '/rooms.html');
});

app.get('/api/rooms', (req, res) => {
    const isLoggedIn = !!(req.session && req.session.userEmail);
    
    if (isLoggedIn) {
        // Logged-in users can see all rooms
        db.all(`
            SELECT r.id, r.name, r.ownerEmail, r.youtubeUrl, r.startTime, r.endTime, r.isRepeating, r.repeatSchedule, r.createdAt, u.name as ownerName
            FROM rooms r
            LEFT JOIN users u ON r.ownerEmail = u.email
            ORDER BY r.createdAt DESC
        `, [], function (err, rows) {
            if (err) return res.status(500).json([]);
            
            // Add participant count to each room
            const roomsWithCount = (rows || []).map(room => ({
                ...room,
                participantCount: roomParticipants[room.id] ? roomParticipants[room.id].size : 0
            }));
            
            res.json(roomsWithCount);
        });
    } else {
        // Non-logged-in users can only see rooms that are currently active (within timer range)
        const now = Date.now();
        db.all(`
            SELECT r.id, r.name, r.ownerEmail, r.youtubeUrl, r.startTime, r.endTime, r.isRepeating, r.repeatSchedule, r.createdAt, u.name as ownerName
            FROM rooms r
            LEFT JOIN users u ON r.ownerEmail = u.email
            WHERE (r.startTime IS NULL AND r.endTime IS NULL) 
               OR (r.startTime IS NOT NULL AND r.endTime IS NOT NULL AND r.startTime <= ? AND r.endTime >= ?)
               OR (r.isRepeating = 1 AND r.repeatSchedule IS NOT NULL)
            ORDER BY r.createdAt DESC
        `, [now, now], function (err, rows) {
            if (err) return res.status(500).json([]);
            
            // Filter repeat schedule rooms based on current day and time
            const filteredRows = (rows || []).filter(room => {
                if (room.isRepeating && room.repeatSchedule) {
                    try {
                        const schedule = JSON.parse(room.repeatSchedule);
                        const now = new Date();
                        const currentDay = now.getDay(); // 0 = Sunday, 1 = Monday, etc.
                        const currentTime = now.getHours() * 100 + now.getMinutes(); // HHMM format
                        
                        return schedule.some(day => {
                            if (day.dayOfWeek == currentDay) {
                                // Parse time strings like "14:30" to HHMM format
                                const [startHour, startMin] = day.startTime.split(':').map(Number);
                                const [endHour, endMin] = day.endTime.split(':').map(Number);
                                const dayStartTime = startHour * 100 + startMin;
                                const dayEndTime = endHour * 100 + endMin;
                                
                                return currentTime >= dayStartTime && currentTime <= dayEndTime;
                            }
                            return false;
                        });
                    } catch (e) {
                        return true; // Show room if schedule parsing fails
                    }
                }
                return true; // Show non-repeat rooms
            });
            
            // Add participant count to each room
            const roomsWithCount = filteredRows.map(room => ({
                ...room,
                participantCount: roomParticipants[room.id] ? roomParticipants[room.id].size : 0
            }));
            
            res.json(roomsWithCount);
        });
    }
});

// Session info
app.get('/api/me', (req, res) => {
    res.json({ loggedIn: !!(req.session && req.session.userEmail), email: req.session && req.session.userEmail });
});

// Delete room (owner only)
app.post('/api/rooms/:id/delete', requireLogin, (req, res) => {
    const roomId = req.params.id;
    db.get('SELECT * FROM rooms WHERE id = ?', [roomId], function (err, room) {
        if (err) return res.status(500).send('서버 오류');
        if (!room) return res.status(404).send('존재하지 않는 방');
        if (room.ownerEmail !== req.session.userEmail) return res.status(403).send('삭제 권한이 없습니다');
        db.run('DELETE FROM rooms WHERE id = ?', [roomId], function (err2) {
            if (err2) return res.status(500).send('서버 오류');
            try {
                const p = require('path');
                const fsp = require('fs');
                const logPath = p.join(__dirname, 'uploads', 'rooms', roomId + '.jsonl');
                if (fsp.existsSync(logPath)) fsp.unlinkSync(logPath);
            } catch (e) {}
            delete roomJoinCounters[roomId];
            res.redirect('/rooms');
        });
    });
});

app.post('/api/rooms', requireLogin, async (req, res) => {
    const { name, password, useYoutube, useTimer, startTime, endTime, isRepeating, repeatSchedule } = req.body || {};
    if (!name || !password) return res.status(400).send('방 이름/비밀번호 필요');
    
    // Validate timer times if timer is enabled
    if (useTimer) {
        if (isRepeating) {
            // Validate repeat schedule
            try {
                const schedule = JSON.parse(repeatSchedule);
                if (!Array.isArray(schedule) || schedule.length === 0) {
                    return res.status(400).send('반복 일정을 올바르게 설정해주세요');
                }
                for (const day of schedule) {
                    if (!day.dayOfWeek || !day.startTime || !day.endTime) {
                        return res.status(400).send('각 요일의 시작/종료 시간을 모두 설정해주세요');
                    }
                    // Validate time format (HH:MM)
                    const timeRegex = /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/;
                    if (!timeRegex.test(day.startTime) || !timeRegex.test(day.endTime)) {
                        return res.status(400).send('올바른 시간 형식을 입력해주세요 (HH:MM)');
                    }
                    // Compare time strings directly
                    if (day.endTime <= day.startTime) {
                        return res.status(400).send('종료 시간은 시작 시간보다 늦어야 합니다');
                    }
                }
            } catch (e) {
                return res.status(400).send('반복 일정 형식이 올바르지 않습니다');
            }
        } else {
            // Single timer validation
            const now = Date.now();
            const start = new Date(startTime).getTime();
            const end = new Date(endTime).getTime();
            
            if (isNaN(start) || isNaN(end)) {
                return res.status(400).send('올바른 시간을 입력해주세요');
            }
            if (start < now) {
                return res.status(400).send('시작 시간은 현재 시간보다 늦어야 합니다');
            }
            if (end <= start) {
                return res.status(400).send('종료 시간은 시작 시간보다 늦어야 합니다');
            }
        }
    }
    
    const id = 'r' + Date.now();
    const passwordHash = await bcrypt.hash(password, 10);
    const createdAt = Date.now();
    
    // Process YouTube - use default video if enabled
    let processedYoutubeUrl = null;
    if (useYoutube) {
        // Always use default video when YouTube is enabled
        processedYoutubeUrl = 'BMYkBErEazM';
    }
    
    let startTimeValue = null;
    let endTimeValue = null;
    
    if (useTimer && !isRepeating && startTime && endTime) {
        // Convert datetime-local to timestamp
        startTimeValue = new Date(startTime).getTime();
        endTimeValue = new Date(endTime).getTime();
    }
    
    const isRepeatingValue = useTimer && isRepeating ? 1 : 0;
    const repeatScheduleValue = useTimer && isRepeating ? repeatSchedule : null;
    
    console.log('Creating room with timer data:', {
        useTimer,
        isRepeating,
        startTimeValue,
        endTimeValue,
        isRepeatingValue,
        repeatScheduleValue
    });
    
    db.run(
        'INSERT INTO rooms(id, name, ownerEmail, passwordHash, youtubeUrl, startTime, endTime, isRepeating, repeatSchedule, createdAt) VALUES(?,?,?,?,?,?,?,?,?,?)',
        [id, name, req.session.userEmail, passwordHash, processedYoutubeUrl, startTimeValue, endTimeValue, isRepeatingValue, repeatScheduleValue, createdAt],
        function (err) {
            if (err) {
                console.error('Database error when creating room:', err);
                return res.status(500).send('서버 오류: ' + err.message);
            }
            console.log('Room created successfully:', id);
            roomJoinCounters[id] = 0;
            res.redirect('/rooms');
        }
    );
});

// Public room page (anyone can open; joining requires password)
app.get('/room/:roomId', (req, res) => {
    db.get('SELECT id, name, youtubeUrl, startTime, endTime, isRepeating, repeatSchedule FROM rooms WHERE id = ?', [req.params.roomId], function (err, row) {
        if (err) return res.status(500).send('서버 오류');
        if (!row) return res.status(404).send('방이 존재하지 않습니다');
        res.sendFile(__dirname + '/room.html');
    });
});

// Get room details API
app.get('/api/rooms/:roomId', (req, res) => {
    db.get('SELECT * FROM rooms WHERE id = ?', [req.params.roomId], function (err, row) {
        if (err) return res.status(500).json({});
        if (!row) return res.status(404).json({});
        res.json(row);
    });
});

// Update room timer settings (owner only)
app.post('/api/rooms/:roomId/timer', requireLogin, async (req, res) => {
    const roomId = req.params.roomId;
    const { useTimer, startTime, endTime, isRepeating, repeatSchedule } = req.body || {};
    
    // Check if user is room owner
    db.get('SELECT * FROM rooms WHERE id = ?', [roomId], async function (err, room) {
        if (err) return res.status(500).send('서버 오류');
        if (!room) return res.status(404).send('존재하지 않는 방');
        if (room.ownerEmail !== req.session.userEmail) return res.status(403).send('수정 권한이 없습니다');
        
        // Validate timer settings
        if (useTimer) {
            if (isRepeating) {
                try {
                    const schedule = JSON.parse(repeatSchedule);
                    if (!Array.isArray(schedule) || schedule.length === 0) {
                        return res.status(400).send('반복 일정을 올바르게 설정해주세요');
                    }
                    for (const day of schedule) {
                        if (!day.dayOfWeek || !day.startTime || !day.endTime) {
                            return res.status(400).send('각 요일의 시작/종료 시간을 모두 설정해주세요');
                        }
                        // Validate time format (HH:MM)
                        const timeRegex = /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/;
                        if (!timeRegex.test(day.startTime) || !timeRegex.test(day.endTime)) {
                            return res.status(400).send('올바른 시간 형식을 입력해주세요 (HH:MM)');
                        }
                        // Compare time strings directly
                        if (day.endTime <= day.startTime) {
                            return res.status(400).send('종료 시간은 시작 시간보다 늦어야 합니다');
                        }
                    }
                } catch (e) {
                    return res.status(400).send('반복 일정 형식이 올바르지 않습니다');
                }
            } else {
                const now = Date.now();
                const start = new Date(startTime).getTime();
                const end = new Date(endTime).getTime();
                
                if (isNaN(start) || isNaN(end)) {
                    return res.status(400).send('올바른 시간을 입력해주세요');
                }
                if (start < now) {
                    return res.status(400).send('시작 시간은 현재 시간보다 늦어야 합니다');
                }
                if (end <= start) {
                    return res.status(400).send('종료 시간은 시작 시간보다 늦어야 합니다');
                }
            }
        }
        
        // Update database
        let startTimeValue = null;
        let endTimeValue = null;
        
        if (useTimer && !isRepeating && startTime && endTime) {
            // Convert datetime-local to timestamp
            startTimeValue = new Date(startTime).getTime();
            endTimeValue = new Date(endTime).getTime();
        }
        
        const isRepeatingValue = useTimer && isRepeating ? 1 : 0;
        const repeatScheduleValue = useTimer && isRepeating ? repeatSchedule : null;
        
        console.log('Updating room timer:', {
            roomId,
            useTimer,
            isRepeating,
            startTimeValue,
            endTimeValue,
            isRepeatingValue,
            repeatScheduleValue
        });
        
        db.run(
            'UPDATE rooms SET startTime = ?, endTime = ?, isRepeating = ?, repeatSchedule = ? WHERE id = ?',
            [startTimeValue, endTimeValue, isRepeatingValue, repeatScheduleValue, roomId],
            function (err) {
                if (err) {
                    console.error('Database error when updating room timer:', err);
                    return res.status(500).send('서버 오류: ' + err.message);
                }
                console.log('Room timer updated successfully:', roomId);
                res.json({ success: true });
            }
        );
    });
});

// Get recent chat history (last 12 hours)
app.get('/api/rooms/:roomId/history', (req, res) => {
    const roomId = req.params.roomId;
    const twelveHoursAgo = Date.now() - (12 * 60 * 60 * 1000);
    
    try {
        const logPath = path.join(__dirname, 'uploads', 'rooms', roomId + '.jsonl');
        if (!fs.existsSync(logPath)) {
            return res.json([]);
        }
        
        const content = fs.readFileSync(logPath, 'utf8');
        const lines = content.trim().split('\n').filter(line => line.trim());
        const recentMessages = [];
        
        lines.forEach(line => {
            try {
                const entry = JSON.parse(line);
                if (entry.time && entry.time >= twelveHoursAgo) {
                    recentMessages.push(entry);
                }
            } catch (e) {
                // Skip invalid JSON lines
            }
        });
        
        res.json(recentMessages);
    } catch (e) {
        res.status(500).json({ error: 'Failed to load chat history' });
    }
});

// Public room access without password (for easy sharing)
app.get('/room/:roomId/join', (req, res) => {
    db.get('SELECT id, name FROM rooms WHERE id = ?', [req.params.roomId], function (err, row) {
        if (err) return res.status(500).send('서버 오류');
        if (!row) return res.status(404).send('방이 존재하지 않습니다');
        res.sendFile(__dirname + '/room.html');
    });
});

io.on('connection', (socket) => {
    console.log('a user connected');
    
    // Handle disconnect
    socket.on('disconnect', () => {
        console.log('user disconnected');
        // Remove from all rooms
        Object.keys(roomParticipants).forEach(roomId => {
            if (roomParticipants[roomId].has(socket.id)) {
                roomParticipants[roomId].delete(socket.id);
                // Emit updated participant count
                io.to(roomId).emit('participantCount', { count: roomParticipants[roomId].size });
                // Clean up empty room
                if (roomParticipants[roomId].size === 0) {
                    delete roomParticipants[roomId];
                }
            }
        });
    });

    socket.on('login', function (data) {
        console.log(
            'Client logged-in:\n name:' +
                data.name +
                '\n userid: ' +
                data.userid +
                '\n time:' +
                server_time().format('YYYY-MM-DD HH:mm:ss')
        );

        socket.name = data.name;
        socket.userid = data.userid;
        socket.enter_time = server_time().format('YYYY-MM-DD HH:mm:ss');

        io.emit('login', { name: socket.name, enter_time: socket.enter_time });
    });

    socket.on('chat', (data) => {
        console.log(
            'Message from %s: %s (%s)',
            socket.name,
            data.msg,
            server_time().format('YYYY-MM-DD HH:mm:ss')
        );
        const payload = {
            msg: data.msg,
            name: socket.name,
            msg_time: data.msg_time,
            count: 0,
            isQuestion: data.isQuestion || false,
        };
        if (data.roomId) {
            socket.to(data.roomId).emit('chat', payload);
            appendRoomLog(data.roomId, { type: 'chat', from: socket.name, time: data.msg_time, msg: data.msg, isQuestion: data.isQuestion || false });
        } else {
            socket.broadcast.emit('chat', payload);
        }
    });

    socket.on('base64', (data) => {
        console.log('base64 image received from', socket.name, 'in room:', data.roomId);
        const payload = {
            msg: data.base64,
            name: socket.name,
            msg_time: data.msg_time,
            count: 0,
        };
        if (data.roomId) {
            console.log('Broadcasting to room:', data.roomId);
            socket.to(data.roomId).emit('base64', payload);
            appendRoomLog(data.roomId, { type: 'image', from: socket.name, time: data.msg_time, base64: data.base64 });
        } else {
            socket.broadcast.emit('base64', payload);
        }
    });

    socket.on('like', (data) => {
        console.log('like:', data.msg_id);
        const userId = socket.id;
        if (!messageReactions[data.msg_id]) {
            messageReactions[data.msg_id] = { like: new Set(), dislike: new Set() };
        }
        const record = messageReactions[data.msg_id];
        // Allow only one reaction per user per message, and mutually exclusive
        if (record.like.has(userId) || record.dislike.has(userId)) {
            return;
        }
        record.like.add(userId);
        const target = data.roomId ? io.to(data.roomId) : io;
        target.emit('update', {
            msg_id: data.msg_id,
            action: 'like',
            count: record.like.size,
        });
    });

    socket.on('dislike', (data) => {
        console.log('dislike:', data.msg_id);
        const userId = socket.id;
        if (!messageReactions[data.msg_id]) {
            messageReactions[data.msg_id] = { like: new Set(), dislike: new Set() };
        }
        const record = messageReactions[data.msg_id];
        // Allow only one reaction per user per message, and mutually exclusive
        if (record.like.has(userId) || record.dislike.has(userId)) {
            return;
        }
        record.dislike.add(userId);
        const target2 = data.roomId ? io.to(data.roomId) : io;
        target2.emit('update', {
            msg_id: data.msg_id,
            action: 'dislike',
            count: record.dislike.size,
        });
    });

    socket.on('comment', (data) => {
        if (!comments[data.msg_id]) {
            comments[data.msg_id] = [];
        }
        comments[data.msg_id].push({ name: socket.name, comment: data.comment });
        const payload = { msg_id: data.msg_id, name: socket.name, comment: data.comment };
        if (data.roomId) {
            socket.to(data.roomId).emit('newComment', payload);
            appendRoomLog(data.roomId, { type: 'comment', from: socket.name, time: Date.now(), msgId: data.msg_id, comment: data.comment });
        } else {
            socket.broadcast.emit('newComment', payload);
        }
    });

    socket.on('disconnect', () => {
        console.log('user disconnected');
    });

    // Join room with password; assign alias by join order
    socket.on('joinRoom', async (data, cb) => {
        try {
            const { roomId, password, userEmail } = data || {};
            const isLoggedIn = !!userEmail;
            
            db.get('SELECT * FROM rooms WHERE id = ?', [roomId], async function (err, room) {
                if (err) return cb && cb({ ok: false, error: 'SERVER_ERROR' });
                if (!room) return cb && cb({ ok: false, error: 'NOT_FOUND' });
                
                // Check timer restrictions for non-logged-in users
                if (!isLoggedIn && room.startTime && room.endTime) {
                    const now = Date.now();
                    if (now < room.startTime) {
                        return cb && cb({ ok: false, error: 'ROOM_NOT_STARTED' });
                    }
                    if (now > room.endTime) {
                        return cb && cb({ ok: false, error: 'ROOM_EXPIRED' });
                    }
                }
                
                const ok = await bcrypt.compare(password || '', room.passwordHash);
                if (!ok) return cb && cb({ ok: false, error: 'BAD_PASSWORD' });
                await socket.join(roomId);
                if (!roomJoinCounters[roomId]) roomJoinCounters[roomId] = 0;
                const num = ++roomJoinCounters[roomId];
                const alias = '익명' + num;
                socket.name = alias;
                socket.enter_time = server_time().format('YYYY-MM-DD HH:mm:ss');
                
                // Add to room participants
                if (!roomParticipants[roomId]) roomParticipants[roomId] = new Set();
                roomParticipants[roomId].add(socket.id);
                
                io.to(roomId).emit('login', { name: alias, enter_time: socket.enter_time });
                io.to(roomId).emit('participantCount', { count: roomParticipants[roomId].size });
                cb && cb({ ok: true, alias, roomName: room.name, youtubeUrl: room.youtubeUrl, isOwner: userEmail && room.ownerEmail === userEmail, startTime: room.startTime, endTime: room.endTime });
            });
        } catch (e) {
            cb && cb({ ok: false, error: 'SERVER_ERROR' });
        }
    });
});

function appendRoomLog(roomId, entry) {
    try {
        const dir = path.join(__dirname, 'uploads', 'rooms');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        const line = JSON.stringify(entry) + '\n';
        fs.appendFile(path.join(dir, roomId + '.jsonl'), line, function () {});
    } catch (e) {}
}

server.listen(3000, function () {
    console.log('Socket IO server listening on port 3000');
});
