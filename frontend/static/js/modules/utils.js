export function showMessage(message, type = 'info', context = 'logged-out') {
    let messageArea;
    if (context === 'logged-in') {
        messageArea = document.getElementById('message-area-logged-in');
    } else {
        messageArea = document.getElementById('message-area-logged-out');
    }

    if (messageArea) {
        messageArea.textContent = message;
        messageArea.className = 'mb-4 text-center text-sm font-medium'; // Reset classes
        if (type === 'error') {
            messageArea.classList.add('text-red-600');
        } else if (type === 'success') {
            messageArea.classList.add('text-green-600');
        } else {
            messageArea.classList.add('text-gray-600');
        }
        messageArea.classList.remove('hidden');
    } else {
        console.error('Message area not found for context:', context);
    }
}

export function clearMessage(context = 'logged-out') {
    let messageArea;
    if (context === 'logged-in') {
        messageArea = document.getElementById('message-area-logged-in');
    } else {
        messageArea = document.getElementById('message-area-logged-out');
    }

    if (messageArea) {
        messageArea.textContent = '';
        messageArea.classList.add('hidden');
    }
}