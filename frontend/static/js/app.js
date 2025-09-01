document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const logoutButton = document.getElementById('logout-button');
    const loggedOutView = document.getElementById('logged-out-view');
    const loggedInView = document.getElementById('loggedIn-view'); // Corrected ID
    const currentUsernameSpan = document.getElementById('current-username');
    const currentUserRoleSpan = document.getElementById('current-user-role');
    const currentUserBalanceSpan = document.getElementById('current-user-balance');

    const mainDashboard = document.getElementById('main-dashboard');
    const customerDashboard = document.getElementById('customer-dashboard');
    const adminDashboard = document.getElementById('admin-dashboard');

    const orderForm = document.getElementById('order-form');
    const searchForm = document.getElementById('search-form');
    const assetInput = document.getElementById('asset');

    const showLoginButton = document.getElementById('show-login');
    const showRegisterButton = document.getElementById('show-register');
    const messageArea = document.getElementById('message-area');

    const API_BASE_URL = 'http://localhost:8000';

    let currentUser = null;
    let accessToken = null;

    // Initialize JSEncrypt
    const crypt = new JSEncrypt({ default_key_size: 2048 });

    // --- Helper Functions ---
    function showMessage(message, type = 'info') {
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
    }

    function clearMessage() {
        messageArea.textContent = '';
        messageArea.classList.add('hidden');
    }

    // --- Event Listeners ---
    loginForm.addEventListener('submit', loginUser);
    registerForm.addEventListener('submit', registerUser);
    logoutButton.addEventListener('click', logoutUser);
    orderForm.addEventListener('submit', placeOrder);
    searchForm.addEventListener('submit', searchTrades);

    showLoginButton.addEventListener('click', () => {
        loginForm.classList.remove('hidden');
        registerForm.classList.add('hidden');
        showLoginButton.classList.add('bg-indigo-600', 'hover:bg-indigo-700', 'text-white');
        showLoginButton.classList.remove('bg-gray-200', 'hover:bg-gray-300', 'text-gray-700');
        showRegisterButton.classList.remove('bg-indigo-600', 'hover:bg-indigo-700', 'text-white');
        showRegisterButton.classList.add('bg-gray-200', 'hover:bg-gray-300', 'text-gray-700');
        clearMessage();
    });

    showRegisterButton.addEventListener('click', () => {
        registerForm.classList.remove('hidden');
        loginForm.classList.add('hidden');
        showRegisterButton.classList.add('bg-indigo-600', 'hover:bg-indigo-700', 'text-white');
        showRegisterButton.classList.remove('bg-gray-200', 'hover:bg-gray-300', 'text-gray-700');
        showLoginButton.classList.remove('bg-indigo-600', 'hover:bg-indigo-700', 'text-white');
        showLoginButton.classList.add('bg-gray-200', 'hover:bg-gray-300', 'text-gray-700');
        clearMessage();
    });

    // --- Initial Setup ---
    checkAuthStatus();
    fetchOrderBook();
    fetchSystemStatus();

    // --- Authentication Functions ---
    async function loginUser(event) {
        event.preventDefault();
        clearMessage();
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;

        const formData = new URLSearchParams();
        formData.append('username', username);
        formData.append('password', password);

        try {
            const response = await fetch(`${API_BASE_URL}/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: formData.toString()
            });
            const data = await response.json();

            if (response.ok) {
                accessToken = data.access_token;
                localStorage.setItem('access_token', accessToken);
                await checkAuthStatus();
                showMessage('Login successful!', 'success');
            } else {
                showMessage(data.detail || 'Login failed.', 'error');
            }
        } catch (error) {
            console.error('Login error:', error);
            showMessage('An error occurred during login. Please try again.', 'error');
        }
    }

    async function registerUser(event) {
        event.preventDefault();
        clearMessage();
        const username = document.getElementById('register-username').value;
        const password = document.getElementById('register-password').value;
        const confirmPassword = document.getElementById('register-confirm-password').value;

        if (password !== confirmPassword) {
            showMessage('Passwords do not match.', 'error');
            return;
        }
        if (password.length < 6) { // Basic client-side validation
            showMessage('Password must be at least 6 characters long.', 'error');
            return;
        }

        // Generate key pair
        crypt.getKey(); // Generates a new key pair
        const publicKey = crypt.getPublicKey();
        const privateKey = crypt.getPrivateKey();

        // Store private key securely (for demo, localStorage)
        localStorage.setItem(`private_key_${username}`, privateKey);

        try {
            const response = await fetch(`${API_BASE_URL}/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password, public_key: publicKey })
            });
            const data = await response.json();

            if (response.ok) {
                showMessage('Registration successful! Please log in.', 'success');
                document.getElementById('login-username').value = username;
                document.getElementById('login-password').value = password;
                showLoginButton.click(); // Switch to login form
            } else {
                showMessage(data.detail || 'Registration failed.', 'error');
            }
        } catch (error) {
            console.error('Registration error:', error);
            showMessage('An error occurred during registration. Please try again.', 'error');
        }
    }

    function logoutUser() {
        accessToken = null;
        localStorage.removeItem('access_token');
        currentUser = null;
        updateUI();
        showMessage('You have been logged out.', 'info');
    }

    async function checkAuthStatus() {
        accessToken = localStorage.getItem('access_token');
        if (accessToken) {
            try {
                const response = await fetch(`${API_BASE_URL}/users/me`, {
                    headers: { 'Authorization': `Bearer ${accessToken}` }
                });
                if (response.ok) {
                    currentUser = await response.json();
                } else {
                    accessToken = null;
                    localStorage.removeItem('access_token');
                    showMessage('Session expired or invalid. Please log in again.', 'error');
                }
            } catch (error) {
                console.error('Auth status check error:', error);
                accessToken = null;
                localStorage.removeItem('access_token');
                showMessage('Could not connect to authentication server. Please try again later.', 'error');
            }
        }
        updateUI();
    }

    function updateUI() {
        if (currentUser) {
            loggedOutView.classList.add('hidden');
            loggedInView.classList.remove('hidden');
            currentUsernameSpan.textContent = currentUser.username;
            currentUserRoleSpan.textContent = currentUser.role;
            currentUserBalanceSpan.textContent = currentUser.balance.toFixed(2);

            mainDashboard.classList.remove('hidden');
            customerDashboard.classList.add('hidden');
            adminDashboard.classList.add('hidden');

            if (currentUser.role === 'customer') {
                customerDashboard.classList.remove('hidden');
                fetchMyOrders();
                fetchMyTrades();
            } else if (currentUser.role === 'admin') {
                adminDashboard.classList.remove('hidden');
                fetchAllUsers();
                fetchAllOrders();
                fetchAllTrades();
            }
            clearMessage(); // Clear messages on successful login
        } else {
            loggedOutView.classList.remove('hidden');
            loggedInView.classList.add('hidden');
            mainDashboard.classList.add('hidden');
            customerDashboard.classList.add('hidden');
            adminDashboard.classList.add('hidden');
            // Ensure login form is visible by default when logged out
            loginForm.classList.remove('hidden');
            registerForm.classList.add('hidden');
            showLoginButton.classList.add('bg-indigo-600', 'hover:bg-indigo-700', 'text-white');
            showLoginButton.classList.remove('bg-gray-200', 'hover:bg-gray-300', 'text-gray-700');
            showRegisterButton.classList.remove('bg-indigo-600', 'hover:bg-indigo-700', 'text-white');
            showRegisterButton.classList.add('bg-gray-200', 'hover:bg-gray-300', 'text-gray-700');
        }
    }

    // --- Data Fetching Functions ---
    async function placeOrder(event) {
        event.preventDefault();
        clearMessage();
        if (!accessToken) {
            showMessage('Please log in to place an order.', 'error');
            return;
        }

        const formData = new FormData(orderForm);
        const order = {
            id: `ord_${Date.now()}`,
            trader_id: currentUser.id,
            asset: formData.get('asset'),
            type: formData.get('type'),
            amount: parseFloat(formData.get('amount')),
            price: parseFloat(formData.get('price')),
        };

        // Retrieve private key
        const privateKey = localStorage.getItem(`private_key_${currentUser.username}`);
        if (!privateKey) {
            showMessage('Private key not found. Please re-register or log in again.', 'error');
            return;
        }
        crypt.setPrivateKey(privateKey);

        // Sign the order
        const orderString = JSON.stringify(order);
        const signature = crypt.sign(orderString, 'sha256');

        const signedOrder = {
            order: order,
            signature: signature,
            public_key: currentUser.public_key // Use the public key from the current user
        };

        try {
            const response = await fetch(`${API_BASE_URL}/order`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` },
                body: JSON.stringify(signedOrder)
            });
            const result = await response.json();
            if (response.ok) {
                console.log(result);
                showMessage('Order placed successfully!', 'success');
                fetchOrderBook();
                fetchSystemStatus();
                if (currentUser.role === 'customer') {
                    fetchMyOrders();
                    fetchMyTrades();
                    fetchMyBalance();
                }
            } else {
                showMessage(result.detail || 'Failed to place order.', 'error');
            }
        } catch (error) {
            console.error('Place order error:', error);
            showMessage('An error occurred while placing the order. Please try again.', 'error');
        }
    }

    async function fetchOrderBook() {
        const asset = assetInput.value;
        try {
            const response = await fetch(`${API_BASE_URL}/orderbook/${asset}`);
            const data = await response.json();
            updateOrderBookUI(data.buy_orders, data.sell_orders);
        } catch (error) {
            console.error('Error fetching order book:', error);
            // showMessage('Could not fetch order book.', 'error'); // Too frequent, maybe not show
        }
    }

    async function fetchSystemStatus() {
        try {
            const merkleResponse = await fetch(`${API_BASE_URL}/merkle_root`);
            const merkleData = await merkleResponse.json();
            document.getElementById('merkle-root').textContent = merkleData.merkle_root;

            const vwapResponse = await fetch(`${API_BASE_URL}/vwap`);
            const vwapData = await vwapResponse.json();
            document.getElementById('vwap').textContent = vwapData.average_price.toFixed(2);
        } catch (error) {
            console.error('Error fetching system status:', error);
            // showMessage('Could not fetch system status.', 'error'); // Too frequent, maybe not show
        }
    }

    async function searchTrades(event) {
        event.preventDefault();
        clearMessage();
        const keyword = document.getElementById('search-keyword').value;
        try {
            const response = await fetch(`${API_BASE_URL}/search?keyword=${keyword}`);
            const data = await response.json();
            updateSearchResultsUI(data.results);
            showMessage(`Found ${data.results.length} results for "${keyword}".`, 'info');
        } catch (error) {
            console.error('Search trades error:', error);
            showMessage('An error occurred during search. Please try again.', 'error');
        }
    }

    async function fetchMyOrders() {
        try {
            const response = await fetch(`${API_BASE_URL}/users/me/orders`, {
                headers: { 'Authorization': `Bearer ${accessToken}` }
            });
            const data = await response.json();
            updateMyOrdersUI(data);
        } catch (error) {
            console.error('Error fetching my orders:', error);
            // showMessage('Could not fetch your orders.', 'error');
        }
    }

    async function fetchMyTrades() {
        try {
            const response = await fetch(`${API_BASE_URL}/users/me/trades`, {
                headers: { 'Authorization': `Bearer ${accessToken}` }
            });
            const data = await response.json();
            updateMyTradesUI(data);
        } catch (error) {
            console.error('Error fetching my trades:', error);
            // showMessage('Could not fetch your trades.', 'error');
        }
    }

    async function fetchMyBalance() {
        try {
            const response = await fetch(`${API_BASE_URL}/users/me/balance`, {
                headers: { 'Authorization': `Bearer ${accessToken}` }
            });
            const data = await response.json();
            currentUserBalanceSpan.textContent = data.balance.toFixed(2);
        } catch (error) {
            console.error('Error fetching my balance:', error);
            // showMessage('Could not fetch your balance.', 'error');
        }
    }

    async function fetchAllUsers() {
        try {
            const response = await fetch(`${API_BASE_URL}/admin/users`, {
                headers: { 'Authorization': `Bearer ${accessToken}` }
            });
            const data = await response.json();
            updateAllUsersUI(data);
        } catch (error) {
            console.error('Error fetching all users:', error);
            // showMessage('Could not fetch all users.', 'error');
        }
    }

    async function fetchAllOrders() {
        try {
            const response = await fetch(`${API_BASE_URL}/admin/orders`, {
                headers: { 'Authorization': `Bearer ${accessToken}` }
            });
            const data = await response.json();
            updateAllOrdersUI(data);
        } catch (error) {
            console.error('Error fetching all orders:', error);
            // showMessage('Could not fetch all orders.', 'error');
        }
    }

    async function fetchAllTrades() {
        try {
            const response = await fetch(`${API_BASE_URL}/admin/trades`, {
                headers: { 'Authorization': `Bearer ${accessToken}` }
            });
            const data = await response.json();
            updateAllTradesUI(data);
        } catch (error) {
            console.error('Error fetching all trades:', error);
            // showMessage('Could not fetch all trades.', 'error');
        }
    }

    // --- UI Update Functions ---
    function updateOrderBookUI(buyOrders, sellOrders) {
        const buyOrdersDiv = document.getElementById('buy-orders');
        const sellOrdersDiv = document.getElementById('sell-orders');
        buyOrdersDiv.innerHTML = '';
        sellOrdersDiv.innerHTML = '';

        buyOrders.forEach(order => {
            const orderDiv = document.createElement('div');
            orderDiv.textContent = `${order.amount.toFixed(2)} @ ${order.price.toFixed(2)}`;
            buyOrdersDiv.appendChild(orderDiv);
        });

        sellOrders.forEach(order => {
            const orderDiv = document.createElement('div');
            orderDiv.textContent = `${order.amount.toFixed(2)} @ ${order.price.toFixed(2)}`;
            sellOrdersDiv.appendChild(orderDiv);
        });
    }

    function updateSearchResultsUI(results) {
        const searchResultsDiv = document.getElementById('search-results');
        searchResultsDiv.innerHTML = '';
        if (results && results.length > 0) {
            results.forEach(result => {
                const resultDiv = document.createElement('div');
                resultDiv.textContent = result;
                searchResultsDiv.appendChild(resultDiv);
            });
        } else {
            searchResultsDiv.textContent = 'No results found.';
        }
    }

    function updateMyOrdersUI(orders) {
        const myOrdersDiv = document.getElementById('my-orders');
        myOrdersDiv.innerHTML = '';
        if (orders && orders.length > 0) {
            orders.forEach(order => {
                const orderDiv = document.createElement('div');
                orderDiv.textContent = `${order.type.toUpperCase()} ${order.amount.toFixed(2)} ${order.asset} @ ${order.price.toFixed(2)} (${order.status})`;
                myOrdersDiv.appendChild(orderDiv);
            });
        } else {
            myOrdersDiv.textContent = 'No orders found.';
        }
    }

    function updateMyTradesUI(trades) {
        const myTradesDiv = document.getElementById('my-trades');
        myTradesDiv.innerHTML = '';
        if (trades && trades.length > 0) {
            trades.forEach(trade => {
                const tradeDiv = document.createElement('div');
                tradeDiv.textContent = `Trade: ${trade.amount.toFixed(2)} @ ${trade.price.toFixed(2)} (Buy: ${trade.buy_order_id}, Sell: ${trade.sell_order_id})`;
                myTradesDiv.appendChild(tradeDiv);
            });
        } else {
            myTradesDiv.textContent = 'No trades found.';
        }
    }

    function updateAllUsersUI(users) {
        const allUsersDiv = document.getElementById('all-users');
        allUsersDiv.innerHTML = '';
        if (users && users.length > 0) {
            users.forEach(user => {
                const userDiv = document.createElement('div');
                userDiv.textContent = `ID: ${user.id}, Username: ${user.username}, Role: ${user.role}, Balance: ${user.balance.toFixed(2)}`;
                allUsersDiv.appendChild(userDiv);
            });
        } else {
            allUsersDiv.textContent = 'No users found.';
        }
    }

    function updateAllOrdersUI(orders) {
        const allOrdersDiv = document.getElementById('all-orders');
        allOrdersDiv.innerHTML = '';
        if (orders && orders.length > 0) {
            orders.forEach(order => {
                const orderDiv = document.createElement('div');
                orderDiv.textContent = `ID: ${order.id}, Trader: ${order.trader_id}, ${order.type.toUpperCase()} ${order.amount.toFixed(2)} ${order.asset} @ ${order.price.toFixed(2)} (${order.status})`;
                allOrdersDiv.appendChild(orderDiv);
            });
        } else {
            allOrdersDiv.textContent = 'No orders found.';
        }
    }

    function updateAllTradesUI(trades) {
        const allTradesDiv = document.getElementById('all-trades');
        allTradesDiv.innerHTML = '';
        if (trades && trades.length > 0) {
            trades.forEach(trade => {
                const tradeDiv = document.createElement('div');
                tradeDiv.textContent = `ID: ${trade.id}, Amount: ${trade.amount.toFixed(2)}, Price: ${trade.price.toFixed(2)}, Timestamp: ${new Date(trade.timestamp).toLocaleString()}`; 
                allTradesDiv.appendChild(tradeDiv);
            });
        } else {
            allTradesDiv.textContent = 'No trades found.';
        }
    }

    // Fetch data periodically
    setInterval(() => {
        fetchOrderBook();
        fetchSystemStatus();
        if (currentUser) {
            if (currentUser.role === 'customer') {
                fetchMyOrders();
                fetchMyTrades();
                fetchMyBalance();
            } else if (currentUser.role === 'admin') {
                fetchAllUsers();
                fetchAllOrders();
                fetchAllTrades();
            }
        }
    }, 5000);
});