const API_BASE = '/api';

const STORAGE_PREFIX = 'timelock_';

document.addEventListener('DOMContentLoaded', () => {
    setupEventListeners();
    updateUnlockTimeDisplay();
});

function setupEventListeners() {
    document.getElementById('encrypt-form').addEventListener('submit', handleEncrypt);
    document.getElementById('decrypt-form').addEventListener('submit', handleDecrypt);
    document.getElementById('seconds-input').addEventListener('input', updateUnlockTimeDisplay);

    document.querySelectorAll('.btn-quick-select').forEach(button => {
        button.addEventListener('click', (e) => {
            const seconds = e.target.getAttribute('data-seconds');
            document.getElementById('seconds-input').value = seconds;
            updateUnlockTimeDisplay();
        });
    });

    const messageInput = document.getElementById('message-input');
    const ciphertextInput = document.getElementById('ciphertext-input');

    messageInput.addEventListener('paste', (e) => {
        console.log('Paste event on message input');
    });

    ciphertextInput.addEventListener('paste', (e) => {
        console.log('Paste event on ciphertext input');
    });
}

function updateUnlockTimeDisplay() {
    const seconds = parseInt(document.getElementById('seconds-input').value) || 0;
    const unlockTime = new Date(Date.now() + seconds * 1000);
    const display = document.getElementById('unlock-time-display');

    if (seconds > 0) {
        display.textContent = `Encrypt message until ${unlockTime.toLocaleString('en-US', {
            month: 'numeric',
            day: 'numeric',
            year: 'numeric',
            hour: 'numeric',
            minute: '2-digit',
            hour12: true
        })}.`;
    } else {
        display.textContent = '';
    }
}

async function handleEncrypt(e) {
    e.preventDefault();

    const seconds = parseInt(document.getElementById('seconds-input').value);
    const message = document.getElementById('message-input').value.trim();
    const resultDiv = document.getElementById('encrypt-result');

    if (!message) {
        showResult(resultDiv, 'error', 'Please enter a message to encrypt.');
        return;
    }

    const unlockTime = new Date(Date.now() + seconds * 1000);

    const submitBtn = e.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Encrypting...';

    try {
        const response = await fetch(`${API_BASE}/capsules`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                message: message,
                unlock_time: unlockTime.toISOString(),
            }),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Encryption failed');
        }

        const data = await response.json();

        const encryptedPackage = {
            v: 1,
            c: data.ciphertext,
            r: data.round_number,
            t: data.unlock_time
        };

        const encryptedString = JSON.stringify(encryptedPackage);

        showResult(resultDiv, 'success', `
            <h3>✅ Message Encrypted</h3>
            <p><strong>Unlock Time:</strong> ${new Date(data.unlock_time).toLocaleString()}</p>
            <p><strong>Beacon Round:</strong> ${data.round_number}</p>

            <div style="background: #fff3cd; border: 2px solid #ffc107; border-radius: 6px; padding: 12px; margin: 15px 0;">
                <p style="margin: 0; color: #856404; font-weight: 500;">
                    ⚠️ <strong>Important:</strong> Save this encrypted message! It's the only way to decrypt your content later. The message is now permanently locked until ${new Date(data.unlock_time).toLocaleString()}.
                </p>
            </div>

            <div style="margin-top: 15px;">
                <label style="display: block; margin-bottom: 8px; font-weight: 500;">Encrypted Message:</label>
                <textarea readonly id="encrypted-output" style="width: 100%; height: 120px; padding: 10px; font-family: monospace; font-size: 0.85em; border: 1px solid #ddd; border-radius: 4px;">${encryptedString}</textarea>
                <button class="btn-copy" onclick="copyEncryptedMessage()">📋 Copy to Clipboard</button>
            </div>
            <p style="margin-top: 15px; font-size: 0.9em; color: #666;">
                💡 Copy the encrypted message and paste it in the Decrypt panel to check if it's unlocked.
            </p>
        `);

        document.getElementById('message-input').value = '';

    } catch (error) {
        showResult(resultDiv, 'error', `<h3>❌ Encryption Failed</h3><p>${error.message}</p>`);
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Encrypt';
    }
}

async function handleDecrypt(e) {
    e.preventDefault();

    const encryptedText = document.getElementById('ciphertext-input').value.trim();
    const resultDiv = document.getElementById('decrypt-result');

    if (!encryptedText) {
        showResult(resultDiv, 'error', 'Please paste an encrypted message.');
        return;
    }

    const submitBtn = e.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Decrypting...';

    try {
        let encryptedPackage;
        try {
            encryptedPackage = JSON.parse(encryptedText);
        } catch (e) {
            throw new Error('Invalid encrypted message format');
        }

        if (!encryptedPackage.c || !encryptedPackage.r) {
            throw new Error('Invalid encrypted message structure');
        }

        const unlockTime = new Date(encryptedPackage.t);
        const now = new Date();

        if (now < unlockTime) {
            const timeRemaining = Math.floor((unlockTime - now) / 1000);
            showResult(resultDiv, 'warning', `
                <h3>🔒 Message Still Locked</h3>
                <p><strong>Unlock Time:</strong> ${unlockTime.toLocaleString()}</p>
                <div class="countdown" id="countdown-timer" style="margin: 20px 0; padding: 20px; background: white; border-radius: 4px; text-align: center; font-size: 1.5em; font-weight: 700; color: #856404;"></div>
                <p style="margin-top: 15px; font-size: 0.95em; text-align: center;">
                    ⏳ This message cannot be decrypted yet.<br>
                    Come back after ${unlockTime.toLocaleString()}
                </p>
            `);

            startCountdown(unlockTime, 'countdown-timer');
            submitBtn.disabled = false;
            submitBtn.textContent = 'Decrypt';
            return;
        }

        const beaconResponse = await fetch(`${API_BASE}/beacon/info`);
        const beaconInfo = await beaconResponse.json();

        if (beaconInfo.latest_round < encryptedPackage.r) {
            showResult(resultDiv, 'warning', `
                <h3>⏳ Waiting for Beacon</h3>
                <p><strong>Required Round:</strong> ${encryptedPackage.r}</p>
                <p><strong>Current Round:</strong> ${beaconInfo.latest_round}</p>
                <p style="margin-top: 15px; font-size: 0.9em;">
                    The beacon hasn't published the required round yet. Please try again in a few moments.
                </p>
            `);
            return;
        }

        const decryptResponse = await fetch(`${API_BASE}/decrypt`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                ciphertext: encryptedPackage.c,
                round: encryptedPackage.r
            }),
        });

        if (!decryptResponse.ok) {
            const error = await decryptResponse.json();
            throw new Error(error.error || 'Decryption failed');
        }

        const decryptData = await decryptResponse.json();

        showResult(resultDiv, 'success', `
            <h3>🎉 Message Unlocked!</h3>
            <div style="background: #fff; padding: 20px; border-radius: 6px; margin: 20px 0; border: 2px solid #28a745;">
                <p style="margin: 0; font-size: 1.2em; line-height: 1.6; white-space: pre-wrap; word-wrap: break-word;">${escapeHtml(decryptData.message)}</p>
            </div>
            <p style="font-size: 0.9em; color: #666; text-align: center;">
                🔓 Unlocked at ${new Date(decryptData.decrypted_at).toLocaleString()}
            </p>
        `);

    } catch (error) {
        showResult(resultDiv, 'error', `<h3>❌ Decryption Failed</h3><p>${error.message}</p>`);
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Decrypt';
    }
}

function showResult(element, type, content) {
    element.className = `result-box ${type}`;
    element.innerHTML = content;
    element.style.display = 'block';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function copyEncryptedMessage() {
    const textarea = document.getElementById('encrypted-output');
    if (textarea) {
        textarea.select();
        navigator.clipboard.writeText(textarea.value).then(() => {
            alert('✅ Copied to clipboard! Now paste it in the Decrypt panel.');
        }).catch(err => {
            console.error('Failed to copy:', err);
            textarea.select();
            document.execCommand('copy');
            alert('✅ Copied to clipboard! Now paste it in the Decrypt panel.');
        });
    }
}

function formatDuration(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;

    const parts = [];
    if (days > 0) parts.push(`${days} day${days > 1 ? 's' : ''}`);
    if (hours > 0) parts.push(`${hours} hour${hours > 1 ? 's' : ''}`);
    if (minutes > 0) parts.push(`${minutes} minute${minutes > 1 ? 's' : ''}`);
    if (secs > 0 || parts.length === 0) parts.push(`${secs} second${secs !== 1 ? 's' : ''}`);

    return parts.join(', ');
}

function startCountdown(targetTime, elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;

    const updateCountdown = () => {
        const now = new Date();
        const distance = targetTime - now;

        if (distance < 0) {
            element.textContent = '⏰ Time has passed! Click Decrypt again.';
            return;
        }

        const days = Math.floor(distance / (1000 * 60 * 60 * 24));
        const hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((distance % (1000 * 60)) / 1000);

        element.textContent = `${days}d ${hours}h ${minutes}m ${seconds}s`;
    };

    updateCountdown();
    const interval = setInterval(updateCountdown, 1000);

    setTimeout(() => clearInterval(interval), targetTime - new Date());
}