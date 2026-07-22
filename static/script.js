const chatHistory = document.getElementById('chat-history');
const userInput = document.getElementById('user-input');
const sendBtn = document.getElementById('send-btn');
const fileUpload = document.getElementById('file-upload');
const fileNameDisplay = document.getElementById('file-name');

// Conversation history for the current session
let messages = [];

// Context extracted from a file
let fileContext = "";

// Auto-resize textarea
userInput.addEventListener('input', function() {
    this.style.height = 'auto';
    this.style.height = (this.scrollHeight) + 'px';
});

// Handle enter key to send
userInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});

sendBtn.addEventListener('click', sendMessage);

// Handle file upload
fileUpload.addEventListener('change', async function(e) {
    const file = e.target.files[0];
    if (!file) return;

    fileNameDisplay.textContent = 'Uploading...';
    
    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) throw new Error('Upload failed');

        const data = await response.json();
        fileContext = data.extracted_text;
        fileNameDisplay.textContent = data.filename;
    } catch (error) {
        console.error('Error:', error);
        fileNameDisplay.textContent = 'Upload failed';
        fileContext = "";
    }
});

function addMessageToUI(content, isUser) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isUser ? 'user-message' : 'ai-message'}`;
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    contentDiv.textContent = content; // Using textContent to avoid raw HTML injection (XSS)

    messageDiv.appendChild(contentDiv);
    chatHistory.appendChild(messageDiv);
    
    // Auto-scroll
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
    if (indicator) {
        indicator.remove();
    }
}

async function sendMessage() {
    const text = userInput.value.trim();
    if (!text && !fileContext) return;

    // Build the user message content
    let fullContent = text;
    if (fileContext) {
        fullContent += `\n\n[Context from uploaded file:]\n${fileContext}`;
    }

    // Add to UI (only show user text, not the huge context)
    if (text) {
        addMessageToUI(text, true);
    } else {
        addMessageToUI(`[Sent file: ${fileNameDisplay.textContent}]`, true);
    }

    // Add to conversation history
    messages.push({
        role: 'user',
        content: fullContent
    });

    // Clear inputs
    userInput.value = '';
    userInput.style.height = 'auto';
    fileUpload.value = '';
    fileNameDisplay.textContent = '';
    fileContext = '';
    
    // Disable send button while processing
    sendBtn.disabled = true;
    showLoading();

    try {
        const response = await fetch('/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ messages: messages })
        });

        if (!response.ok) throw new Error('Network response was not ok');

        const data = await response.json();
        const aiResponse = data.message.content;

        // Add AI response to history
        messages.push({
            role: 'assistant',
            content: aiResponse
        });

        removeLoading();
        addMessageToUI(aiResponse, false);

    } catch (error) {
        console.error('Error:', error);
        removeLoading();
        addMessageToUI('Sorry, I encountered an error. Is Ollama running?', false);
        
        // Remove the last message from history since it failed
        messages.pop();
    } finally {
        sendBtn.disabled = false;
        userInput.focus();
    }
}
