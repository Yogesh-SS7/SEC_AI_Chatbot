// ── Guard: redirect to login if no token ─────────────────────────────────────
const accessToken = localStorage.getItem('access_token');
if (!accessToken) {
    window.location.replace('/');
}

// ── UI element references ────────────────────────────────────────────────────
const chatHistory     = document.getElementById('chat-history');
const userInput       = document.getElementById('user-input');
const sendBtn         = document.getElementById('send-btn');
const fileUpload      = document.getElementById('file-upload');
const fileNameDisplay = document.getElementById('file-name');
const logoutBtn       = document.getElementById('logout-btn');

// ── Conversation state ────────────────────────────────────────────────────────
let messages    = [];
let fileContext = '';

// ── Auth helpers ─────────────────────────────────────────────────────────────
function authHeaders() {
    return { 'Authorization': `Bearer ${accessToken}` };
}

function logout() {
    localStorage.removeItem('access_token');
    window.location.replace('/');
}

logoutBtn.addEventListener('click', logout);

// ── Auto-resize textarea ─────────────────────────────────────────────────────
userInput.addEventListener('input', function () {
    this.style.height = 'auto';
    this.style.height = (this.scrollHeight) + 'px';
});

// Handle Enter key to send
userInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});

sendBtn.addEventListener('click', sendMessage);

// ── File upload ───────────────────────────────────────────────────────────────
fileUpload.addEventListener('change', async function (e) {
    const file = e.target.files[0];
    if (!file) return;

    fileNameDisplay.textContent = 'Uploading…';

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/upload', {
            method: 'POST',
            headers: authHeaders(),
            body: formData
        });

        if (response.status === 401 || response.status === 403) {
            logout();
            return;
        }

        if (!response.ok) throw new Error('Upload failed');

        const data = await response.json();
        fileContext = data.extracted_text;
        fileNameDisplay.textContent = data.filename;
    } catch (error) {
        console.error('Upload error:', error);
        fileNameDisplay.textContent = 'Upload failed';
        fileContext = '';
    }
});

// ── Message UI helpers ────────────────────────────────────────────────────────
function addMessageToUI(content, isUser) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isUser ? 'user-message' : 'ai-message'}`;

    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    contentDiv.textContent = content; // textContent prevents XSS

    messageDiv.appendChild(contentDiv);
    chatHistory.appendChild(messageDiv);
    chatHistory.scrollTop = chatHistory.scrollHeight;
}

function showLoading() {
    const loadingDiv = document.createElement('div');
    loadingDiv.className = 'message ai-message';
    loadingDiv.id = 'loading-indicator';

    const indicator = document.createElement('div');
    indicator.className = 'typing-indicator';
    indicator.innerHTML = `
        <div class="dot"></div>
        <div class="dot"></div>
        <div class="dot"></div>
    `;

    loadingDiv.appendChild(indicator);
    chatHistory.appendChild(loadingDiv);
    chatHistory.scrollTop = chatHistory.scrollHeight;
}

function removeLoading() {
    const indicator = document.getElementById('loading-indicator');
    if (indicator) indicator.remove();
}

// ── Send message ──────────────────────────────────────────────────────────────
async function sendMessage() {
    const text = userInput.value.trim();
    if (!text && !fileContext) return;

    let fullContent = text;
    if (fileContext) {
        fullContent += `\n\n[Context from uploaded file:]\n${fileContext}`;
    }

    if (text) {
        addMessageToUI(text, true);
    } else {
        addMessageToUI(`[Sent file: ${fileNameDisplay.textContent}]`, true);
    }

    messages.push({ role: 'user', content: fullContent });

    userInput.value = '';
    userInput.style.height = 'auto';
    fileUpload.value = '';
    fileNameDisplay.textContent = '';
    fileContext = '';

    sendBtn.disabled = true;
    showLoading();

    try {
        const response = await fetch('/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...authHeaders()
            },
            body: JSON.stringify({ messages })
        });

        if (response.status === 401 || response.status === 403) {
            removeLoading();
            logout();
            return;
        }

        if (!response.ok) throw new Error('Network response was not ok');

        const data = await response.json();
        const aiResponse = data.message.content;

        messages.push({ role: 'assistant', content: aiResponse });
        removeLoading();
        addMessageToUI(aiResponse, false);

    } catch (error) {
        console.error('Chat error:', error);
        removeLoading();
        addMessageToUI('Sorry, I encountered an error. Is Ollama running?', false);
        messages.pop();
    } finally {
        sendBtn.disabled = false;
        userInput.focus();
    }
}
