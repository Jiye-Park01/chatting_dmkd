const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const db = new sqlite3.Database(path.join(__dirname, 'data.sqlite'));

console.log('=== 데이터베이스 확인 ===\n');

// 1. 사용자 데이터 확인
console.log('1. 사용자 데이터:');
db.all('SELECT * FROM users', (err, rows) => {
    if (err) {
        console.error('사용자 데이터 조회 오류:', err);
    } else {
        console.log(JSON.stringify(rows, null, 2));
    }
    
    // 2. 방 데이터 확인
    console.log('\n2. 방 데이터:');
    db.all('SELECT * FROM rooms', (err, rows) => {
        if (err) {
            console.error('방 데이터 조회 오류:', err);
        } else {
            console.log(JSON.stringify(rows, null, 2));
        }
        
        // 3. 채팅 로그 확인
        console.log('\n3. 채팅 로그 파일들:');
        const uploadsDir = path.join(__dirname, 'uploads', 'rooms');
        if (fs.existsSync(uploadsDir)) {
            const files = fs.readdirSync(uploadsDir);
            console.log('방 ID별 로그 파일:', files);
            
            files.forEach(file => {
                if (file.endsWith('.jsonl')) {
                    const roomId = file.replace('.jsonl', '');
                    console.log(`\n--- 방 ${roomId}의 채팅 로그 ---`);
                    try {
                        const content = fs.readFileSync(path.join(uploadsDir, file), 'utf8');
                        const lines = content.trim().split('\n').filter(line => line.trim());
                        lines.forEach((line, index) => {
                            try {
                                const logEntry = JSON.parse(line);
                                console.log(`[${index + 1}]`, JSON.stringify(logEntry, null, 2));
                            } catch (e) {
                                console.log(`[${index + 1}] (파싱 오류):`, line);
                            }
                        });
                    } catch (e) {
                        console.log('파일 읽기 오류:', e.message);
                    }
                }
            });
        } else {
            console.log('uploads/rooms 디렉토리가 존재하지 않습니다.');
        }
        
        db.close();
    });
});