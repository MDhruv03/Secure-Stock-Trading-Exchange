import { fetchMyOrdersApi, fetchMyTradesApi, fetchMyBalanceApi, fetchAllUsersApi, fetchAllOrdersApi, fetchAllTradesApi } from './api.js';
import { elements } from './ui.js';
import { getAccessToken } from './auth.js';

export async function updateDashboardData(currentUser) {
    const accessToken = getAccessToken();
    if (!currentUser || !accessToken) return;

    if (currentUser.role === 'customer') {
        fetchMyBalance();
    } else if (currentUser.role === 'admin') {
        // Admin data is now loaded on demand
    }
}

async function fetchMyBalance() {
    const accessToken = getAccessToken();
    try {
        const response = await fetchMyBalanceApi(accessToken);
        const data = await response.json();
        elements.currentUserBalanceSpan.textContent = data.balance.toFixed(2);
    } catch (error) {
        console.error('Error fetching my balance:', error);
    }
}