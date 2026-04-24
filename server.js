const express = require('express');
const http = require('http');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io'); 
require('dotenv').config();

const db = require('./database');
const { startSniffing } = require('./sniffer'); 

const app = express();
const server = http.createServer(app);
const io = new Server(server); 

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'super_secret_key';

// ==========================================
// 🛠️ 0. ระบบสร้างตารางอัตโนมัติ (Database Init)
// ==========================================
const initDB = async () => {
    try {
        // สร้างตารางประวัติการดักจับ (ถ้ายังไม่มี)
        await db.query(`
            CREATE TABLE IF NOT EXISTS packet_history (
                id SERIAL PRIMARY KEY,
                timestamp VARCHAR(50),
                protocol VARCHAR(50),
                src_ip VARCHAR(50),
                dst_ip VARCHAR(50),
                length INT,
                is_encrypted BOOLEAN,
                encryption_version VARCHAR(50)
            )
        `);
        console.log("✅ [SYS_DB] ตรวจสอบและสร้างตาราง packet_history สำเร็จ!");
    } catch (err) {
        console.error("❌ [SYS_DB] ไม่สามารถสร้างตารางประวัติได้:", err);
    }
};
initDB();

// ==========================================
// 🛡️ Middleware: ด่านตรวจบัตรและสิทธิ์ (Security Guard)
// ==========================================
const verifyAdmin = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'ไม่พบบัตรผ่าน (No Token)' });

    try {
        const decoded = jwt.verify(token.split(" ")[1], SECRET_KEY);
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'ท่านไม่มีสิทธิ์ใช้งานส่วนนี้ (Admin Only)' });
        }
        next();
    } catch (err) {
        return res.status(401).json({ error: 'บัตรผ่านหมดอายุหรือปลอมแปลง (Invalid Token)' });
    }
};

// ==========================================
// 1. API: Login & Register 
// ==========================================
app.post('/api/register', async (req, res) => {
    const { username, password, role } = req.body;
    const userRole = role === 'admin' ? 'admin' : 'user';
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = `INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id`;
        const result = await db.query(query, [username, hashedPassword, userRole]);
        res.json({ message: 'ลงทะเบียนสำเร็จ!', id: result.rows[0].id });
    } catch (error) {
        if (error.code === '23505') return res.status(400).json({ error: 'ชื่อผู้ใช้นี้มีคนใช้แล้ว' });
        res.status(500).json({ error: 'เกิดข้อผิดพลาดที่เซิร์ฟเวอร์' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await db.query(`SELECT * FROM users WHERE username = $1`, [username]);
        const user = result.rows[0];
        if (!user) return res.status(400).json({ error: 'ไม่พบชื่อผู้ใช้นี้' });
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'รหัสผ่านไม่ถูกต้อง' });

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '2h' });
        res.json({ message: 'เข้าสู่ระบบสำเร็จ', token, role: user.role });
    } catch (error) {
        res.status(500).json({ error: 'เกิดข้อผิดพลาดที่เซิร์ฟเวอร์' });
    }
});

// ==========================================
// 2. API: สำหรับ Admin (User Management & History)
// ==========================================
app.get('/api/users', verifyAdmin, async (req, res) => {
    try {
        const result = await db.query(`SELECT id, username, role FROM users ORDER BY id ASC`);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'ไม่สามารถดึงข้อมูลบัญชีได้' });
    }
});

app.delete('/api/users/:id', verifyAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        await db.query('DELETE FROM users WHERE id = $1', [id]);
        res.json({ message: 'ลบผู้ใช้งานออกจากระบบเรียบร้อยแล้ว!' });
    } catch (error) {
        res.status(500).json({ error: 'ไม่สามารถลบข้อมูลได้' });
    }
});

app.put('/api/users/:id/role', verifyAdmin, async (req, res) => {
    const { id } = req.params;
    const { role } = req.body; 
    try {
        await db.query('UPDATE users SET role = $1 WHERE id = $2', [role, id]);
        res.json({ message: `เปลี่ยนระดับสิทธิ์เป็น ${role.toUpperCase()} สำเร็จ` });
    } catch (error) {
        res.status(500).json({ error: 'ไม่สามารถเปลี่ยนสิทธิ์ได้' });
    }
});

// ดึงข้อมูลประวัติการดักจับ (History API)
app.get('/api/history', verifyAdmin, async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM packet_history ORDER BY id DESC LIMIT 500');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'ไม่สามารถดึงประวัติได้' });
    }
});

// ==========================================
// 3. API: อำนาจพิเศษสำหรับ Admin (System Override)
// ==========================================
let isStreaming = true; 

app.post('/api/system/toggle-stream', verifyAdmin, (req, res) => {
    isStreaming = !isStreaming; 
    const statusText = isStreaming ? 'ACTIVE' : 'PAUSED';
    console.log(`> [SYS_OP] Data stream is now ${statusText}`);
    res.json({ status: isStreaming, message: `STREAM_${statusText}` });
});

// ==========================================
// 4. ระบบ Real-time Socket.io & Sniffer & DB Batch Save
// ==========================================
io.on('connection', (socket) => {
    console.log('> [NETWORK] New client connected to radar.');
    socket.on('disconnect', () => {
        console.log('> [NETWORK] Client disconnected.');
    });
});

let packetBufferForDB = []; // ตะกร้าพักข้อมูลก่อนเซฟลงฐานข้อมูล

console.log("> [SYS_INIT] Starting packet capture engine...");
startSniffing((packet) => {
    if (isStreaming) {
        io.emit('new_packet', packet); // ส่งขึ้นจอแบบ Real-time
        packetBufferForDB.push(packet); // เก็บใส่ตะกร้าเตรียม Save
    }
});

// 💾 กลไก Data Batching: เซฟลงฐานข้อมูลทุกๆ 10 วินาที เพื่อป้องกัน Database พัง!
setInterval(async () => {
    if (packetBufferForDB.length > 0 && isStreaming) {
        // ดึง 50 แพ็กเก็ตล่าสุดจากตะกร้าไปเซฟ (ประหยัดพื้นที่ฐานข้อมูล)
        const batchToSave = packetBufferForDB.slice(-50);
        packetBufferForDB = []; // ล้างตะกร้า

        try {
            const queries = batchToSave.map(p => 
                db.query(
                    `INSERT INTO packet_history (timestamp, protocol, src_ip, dst_ip, length, is_encrypted, encryption_version) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                    [p.timestamp, p.protocol, p.src_ip, p.dst_ip, parseInt(p.length) || 0, p.isEncrypted, p.encryptionVersion]
                )
            );
            await Promise.all(queries);
            // console.log(`💾 [SYS_DB] บันทึกประวัติสำเร็จ ${queries.length} รายการ`);
        } catch (err) {
            console.error("❌ [SYS_DB] Save Error:", err.message);
        }
    }
}, 10000); // 10000 ms = 10 วินาที

server.listen(PORT, () => {
    console.log(`> [SYS_OK] Server running on port ${PORT}`);
});