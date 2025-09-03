const API_BASE_URL = 'http://127.0.0.1:8000';

export async function loginUserApi(username, password) {
    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('password', password);

    const response = await fetch(`${API_BASE_URL}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
    });
    return response;
}

export async function registerUserApi(username, password, publicKey, privateKey) {
    const response = await fetch(`${API_BASE_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, public_key: publicKey, private_key: privateKey })
    });
    return response;
}

export async function checkAuthStatusApi(accessToken) {
    const response = await fetch(`${API_BASE_URL}/users/me`, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    return response;
}

export async function placeOrderApi(signedOrder, accessToken) {
    const response = await fetch(`${API_BASE_URL}/order`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` },
        body: JSON.stringify(signedOrder)
    });
    return response;
}

export async function fetchOrderBookApi(asset) {
    const response = await fetch(`${API_BASE_URL}/orderbook/${asset}`);
    return response;
}

export async function fetchSystemStatusApi() {
    const merkleResponse = await fetch(`${API_BASE_URL}/merkle_root`);
    const vwapResponse = await fetch(`${API_BASE_URL}/vwap`);
    return { merkleResponse, vwapResponse };
}

export async function searchTradesApi(keyword) {
    const response = await fetch(`${API_BASE_URL}/search?keyword=${keyword}`);
    return response;
}

export async function fetchMyOrdersApi(accessToken) {
    const response = await fetch(`${API_BASE_URL}/users/me/orders`, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    return response;
}

export async function fetchMyTradesApi(accessToken) {
    const response = await fetch(`${API_BASE_URL}/users/me/trades`, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    return response;
}

export async function fetchMyBalanceApi(accessToken) {
    const response = await fetch(`${API_BASE_URL}/users/me/balance`, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    return response;
}

export async function fetchAllUsersApi(accessToken) {
    const response = await fetch(`${API_BASE_URL}/admin/users`, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    return response;
}

export async function fetchAllOrdersApi(accessToken) {
    const response = await fetch(`${API_BASE_URL}/admin/orders`, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    return response;
}

export async function fetchAllTradesApi(accessToken) {
    const response = await fetch(`${API_BASE_URL}/admin/trades`, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    return response;
}
