const { spawn } = require('child_process');

const tlsVersions = {
    '0x0300': 'SSL 3.0', '768': 'SSL 3.0',
    '0x0301': 'TLS 1.0', '769': 'TLS 1.0',
    '0x0302': 'TLS 1.1', '770': 'TLS 1.1', 'tls 1.2': 'TLS 1.2',
    '0x0303': 'TLS 1.2', '771': 'TLS 1.2', 'tls 1.3': 'TLS 1.3',
    '0x0304': 'TLS 1.3', '772': 'TLS 1.3'
};

function startSniffing(callback) {
    console.log("🔍 กำลังเปิดใช้งานโหมดดักจับการเข้ารหัสระดับสูง...");

    // เอาคำสั่ง ssl รุ่นเก่าออก เพื่อป้องกัน TShark รวน
    const tsharkArgs = [
        '-i', 'Ethernet', // 🚨 
        '-i', 'Wi-Fi', // 🚨 สำคัญ: ถ้าท่านเสียบสายแลนอยู่ ต้องแก้เป็น 'Ethernet' นะครับ!
        '-l', 
        '-T', 'fields',
        '-e', 'frame.time_epoch',
        '-e', 'frame.protocols',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'frame.len',
        '-e', 'tls.record.version',
        '-e', 'tls.handshake.version'
    ];

    const tshark = spawn('C:\\Program Files\\Wireshark\\tshark.exe', tsharkArgs);

    tshark.stdout.on('data', (data) => {
        const lines = data.toString().split('\n');
        
        lines.forEach(line => {
            if (!line.trim()) return;
            
            const parts = line.split('\t');
            if (parts.length >= 5) {
                const protocols = parts[1];
                const src_ip = parts[2];
                const dst_ip = parts[3];
                const length = parts[4];
                
                const tls_rec = parts[5] ? parts[5].split(',')[0].trim().toLowerCase() : null;
                const tls_hand = parts[6] ? parts[6].split(',')[0].trim().toLowerCase() : null;
                
                const raw_version = tls_hand || tls_rec;

                let protocolName = 'UNKNOWN';
                let isEncrypted = false;
                let encryptionVersion = 'Plaintext'; 

                if (protocols) {
                    const protoList = protocols.split(':');
                    protocolName = protoList[protoList.length - 1].toUpperCase();
                }

                if (raw_version && tlsVersions[raw_version]) {
                    isEncrypted = true;
                    encryptionVersion = tlsVersions[raw_version];
                    if(protocolName === 'TCP') protocolName = 'HTTPS'; 
                } else if (protocols && (protocols.includes('tls') || protocols.includes('ssl'))) {
                    isEncrypted = true;
                    encryptionVersion = 'TLS (Unknown)';
                }

                const packetInfo = {
                    timestamp: new Date().toLocaleTimeString('en-GB'),
                    protocol: protocolName,
                    src_ip: src_ip || '-',
                    dst_ip: dst_ip || '-',
                    length: length,
                    isEncrypted: isEncrypted,         
                    encryptionVersion: encryptionVersion 
                };

                callback(packetInfo);
            }
        });
    });

    // 🚨 เปิด Error ไว้เช็คอาการ
    tshark.stderr.on('data', (data) => {
        const msg = data.toString();
        // พิมพ์ข้อความทั้งหมดออก Terminal จะได้รู้ว่า TShark บ่นอะไร
        console.log(`[TShark System]: ${msg.trim()}`); 
    });
}

module.exports = { startSniffing };