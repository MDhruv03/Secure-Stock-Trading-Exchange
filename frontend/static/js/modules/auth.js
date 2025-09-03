import { loginUserApi, registerUserApi, checkAuthStatusApi } from './api.js';
import { showMessage } from './utils.js';
import { updateUI } from './ui.js';

let currentUser = null;
let accessToken = null;

const crypt = new JSEncrypt({ default_key_size: 2048 });

export async function loginUser(event) {
    event.preventDefault();
    showMessage('', 'info', 'logged-out');
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    try {
        const response = await loginUserApi(username, password);
        const data = await response.json();

        if (response.ok) {
            accessToken = data.access_token;
            localStorage.setItem('access_token', accessToken);
            await checkAuthStatus();
            showMessage('Login successful!', 'success', 'logged-in');
        } else {
            showMessage(data.detail || 'Login failed.', 'error', 'logged-out');
        }
    } catch (error) {
        showMessage('An error occurred during login.', 'error', 'logged-out');
    }
}

export async function registerUser(event) {
    event.preventDefault();
    showMessage('', 'info', 'logged-out');
    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;
    const confirmPassword = document.getElementById('register-confirm-password').value;

    if (password !== confirmPassword) {
        showMessage('Passwords do not match.', 'error', 'logged-out');
        return;
    }

    crypt.getKey();
    const publicKey = crypt.getPublicKey();
    const privateKey = crypt.getPrivateKey();

    localStorage.setItem(`private_key_${username}`, privateKey);

    try {
        const response = await registerUserApi(username, password, publicKey, privateKey);
        const data = await response.json();

        if (response.ok) {
            showMessage('Registration successful! Please log in.', 'success', 'logged-out');
        } else {
            showMessage(data.detail || 'Registration failed.', 'error', 'logged-out');
        }
    } catch (error) {
        showMessage('An error occurred during registration.', 'error', 'logged-out');
    }
}

export function logoutUser() {
    accessToken = null;
    localStorage.removeItem('access_token');
    currentUser = null;
    updateUI(null);
    showMessage('You have been logged out.', 'info', 'logged-out');
}

export async function checkAuthStatus() {
    accessToken = localStorage.getItem('access_token');
    if (accessToken) {
        try {
            const response = await checkAuthStatusApi(accessToken);
            if (response.ok) {
                currentUser = await response.json();
            } else {
                logoutUser();
            }
        } catch (error) {
            logoutUser();
        }
    }
    updateUI(currentUser);
    return currentUser;
}

export function getCurrentUser() {
    return currentUser;
}

export function getAccessToken() {
    return accessToken;
}