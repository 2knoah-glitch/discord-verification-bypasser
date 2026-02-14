const modules = webpackReq.m;
const cache = webpackReq.c;

function findByCode(src) {
    for (const [id, mod] of Object.entries(modules)) {
        if (mod.toString().includes(src)) {
            return cache[id].exports;
        }
    }
}

function findObjectFromKey(exports, key) {
    if (!exports) return;
    for (const exportKey in exports) {
        const obj = exports[exportKey];
        if (obj && obj[key]) return obj;
    }
}

// === STAGE 2: GET API CLIENT ===
const api = findObjectFromKey(
    findByCode('.set("X-Audit-Log-Reason",'),
    "patch"
);

// === STAGE 3: HKDF IMPLEMENTATION (SHA-256) ===
async function hkdf(ikm, salt, info, length) {
    const key = await crypto.subtle.importKey(
        'raw',
        ikm,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    
    const prk = await crypto.subtle.sign(
        'HMAC',
        key,
        salt
    );
    
    const T = new Uint8Array(0);
    const okm = new Uint8Array(length);
    let current = new Uint8Array(0);
    
    for (let i = 1; i <= Math.ceil(length / 32); i++) {
        const hmacKey = await crypto.subtle.importKey(
            'raw',
            prk,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        
        const message = new Uint8Array([...current, ...info, i]);
        current = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, message));
        
        okm.set(current, (i - 1) * 32);
    }
    
    return okm;
}

// === STAGE 4: PREDICTION DATA GENERATION ===
function generatePredictions(timestamp) {
    // Box-Muller transform for Gaussian noise (µ=127, σ=40)
    function gaussianRandom() {
        let u = 0, v = 0;
        while(u === 0) u = Math.random();
        while(v === 0) v = Math.random();
        return Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v);
    }
    
    // Generate raw sensor data (127 ± 40)
    const raws = [];
    for (let i = 0; i < 64; i++) {
        let val = 127 + 40 * gaussianRandom();
        raws.push(Math.min(255, Math.max(0, Math.round(val))));
    }
    
    // LUT mapping: sigmoid((raw - 127) / 20)
    function rawToOutput(raw) {
        const x = (raw - 127) / 20;
        return 1 / (1 + Math.exp(-x));
    }
    
    // Z-score outlier removal
    function removeOutliers(arr, passes = 1) {
        let data = [...arr];
        for (let pass = 0; pass < passes; pass++) {
            const mean = data.reduce((a, b) => a + b, 0) / data.length;
            const variance = data.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / data.length;
            const stdDev = Math.sqrt(variance);
            
            data = data.filter(v => Math.abs(v - mean) <= 3 * stdDev);
        }
        return data;
    }
    
    // Generate outputs
    const allOutputs = raws.map(r => rawToOutput(r));
    const outputs = removeOutliers(allOutputs, 2);
    const primaryOutputs = removeOutliers(allOutputs, 1);
    
    // Fixed shift amounts (timestamp seeded)
    const seed = timestamp % 1000;
    const xScaledShiftAmt = seed < 500 ? 0.0005 : -0.0005;
    const yScaledShiftAmt = seed < 500 ? 0.0002 : -0.0002;
    
    return {
        outputs,
        primaryOutputs,
        raws,
        xScaledShiftAmt,
        yScaledShiftAmt
    };
}

// === STAGE 5: MEDIA DEVICE ENUMERATION ===
async function getMediaDeviceInfo() {
    const devices = await navigator.mediaDevices.enumerateDevices();
    const videoInput = devices.find(d => d.kind === 'videoinput');
    
    return {
        deviceId: videoInput?.deviceId || 'default',
        groupId: videoInput?.groupId || '',
        kind: 'videoinput',
        label: videoInput?.label || 'FaceTime HD Camera'
    };
}

// === STAGE 6: STATE TIMELINE GENERATION ===
function generateStateTimeline() {
    const baseTime = performance.now();
    return [
        baseTime,
        baseTime + 45 + Math.random() * 30,
        baseTime + 120 + Math.random() * 50,
        baseTime + 190 + Math.random() * 40,
        baseTime + 250 + Math.random() * 60
    ];
}

// === STAGE 7: BROWSER FINGERPRINT ===
function getBrowserFingerprint() {
    return {
        userAgent: navigator.userAgent,
        language: navigator.language,
        platform: navigator.platform,
        screenWidth: screen.width,
        screenHeight: screen.height,
        colorDepth: screen.colorDepth,
        timezoneOffset: new Date().getTimezoneOffset(),
        cookiesEnabled: navigator.cookieEnabled,
        webdriver: navigator.webdriver,
        hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory: navigator.deviceMemory || 4
    };
}

// === STAGE 8: MAIN EXECUTION ===
try {
    // Generate unique identifiers
    const transaction_id = crypto.randomUUID();
    const timestamp = Date.now();
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // Get predictions and device info
    const predictions = generatePredictions(timestamp);
    const mediaDeviceInfo = await getMediaDeviceInfo();
    const stateTimeline = generateStateTimeline();
    const browserFingerprint = getBrowserFingerprint();
    
    // Construct plaintext payload
    const plaintextPayload = {
        method: 3,
        predictions: {
            ...predictions,
            mediaDeviceInfo,
            stateTimeline
        },
        browserFingerprint
    };
    
    // HKDF key derivation
    const ikm = new Uint8Array([
        ...nonce,
        ...new Uint8Array(new BigUint64Array([BigInt(timestamp)]).buffer),
        ...new TextEncoder().encode(transaction_id)
    ]);
    
    const salt = new TextEncoder().encode('age-verify-salt-v2');
    const info = new TextEncoder().encode('age-verify-context');
    const keyMaterial = await hkdf(ikm, salt, info, 32);
    
    // Import key for AES-GCM
    const key = await crypto.subtle.importKey(
        'raw',
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );
    
    // Encrypt payload
    const encoder = new TextEncoder();
    const plaintextData = encoder.encode(JSON.stringify(plaintextPayload));
    
    const encrypted = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv,
            tagLength: 128
        },
        key,
        plaintextData
    );
    
    // Split ciphertext and auth tag
    const encryptedArray = new Uint8Array(encrypted);
    const auth_tag = encryptedArray.slice(-16);
    const encrypted_payload = encryptedArray.slice(0, -16);
    
    // Base64 encode
    function arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    
    // Send request
    const response = await api.post({
        url: '/age-verification/verify',
        body: {
            encrypted_payload: arrayBufferToBase64(encrypted_payload),
            auth_tag: arrayBufferToBase64(auth_tag),
            iv: arrayBufferToBase64(iv),
            timestamp: Math.floor(timestamp / 1000),
            transaction_id: transaction_id
        }
    });
    
    // Redirect to verification URL
    if (response.body?.verification_webview_url) {
        window.location.href = response.body.verification_webview_url;
    }
    
    console.log('[ABYSSCORE] Request sent successfully', response);
    
} catch (error) {
    console.error('[ABYSSCORE] Error:', error);
}
