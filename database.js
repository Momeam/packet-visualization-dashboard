const { Pool } = require('pg');
require('dotenv').config(); 

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false 
    }
});

pool.connect()
    .then(client => {
        console.log('📦 เชื่อมต่อฐานข้อมูล Neon Database สำเร็จ!');
        
    const createTableQuery = `
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role VARCHAR(20) NOT NULL
            );
        `;

        return client.query(createTableQuery)
            .then(() => {
                console.log('✅ ตรวจสอบโครงสร้างตารางเรียบร้อย ');
                client.release();
            });
    })
    .catch(err => console.error('❌ เกิดข้อผิดพลาดในการเชื่อมต่อฐานข้อมูล:', err.stack));

module.exports = pool;