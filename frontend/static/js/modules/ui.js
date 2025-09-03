export const elements = {
    loginForm: document.getElementById('login-form'),
    registerForm: document.getElementById('register-form'),
    logoutButton: document.getElementById('logout-button'),
    loggedOutView: document.getElementById('logged-out-view'),
    loggedInView: document.getElementById('loggedIn-view'),
    currentUsernameSpan: document.getElementById('current-username'),
    currentUserRoleSpan: document.getElementById('current-user-role'),
    currentUserBalanceSpan: document.getElementById('current-user-balance'),
    mainDashboard: document.getElementById('main-dashboard'),
    adminContent: document.getElementById('admin-content'),
    showLoginButton: document.getElementById('show-login'),
    showRegisterButton: document.getElementById('show-register'),
    messageAreaLoggedIn: document.getElementById('message-area-logged-in'),
    messageAreaLoggedOut: document.getElementById('message-area-logged-out'),
};

export function updateUI(currentUser) {
    if (currentUser) {
        elements.loggedOutView.classList.add('hidden');
        elements.loggedInView.classList.remove('hidden');
        elements.currentUsernameSpan.textContent = currentUser.username;
        elements.currentUserRoleSpan.textContent = currentUser.role;
        elements.currentUserBalanceSpan.textContent = currentUser.balance.toFixed(2);
        renderDashboard(currentUser);
    } else {
        elements.loggedOutView.classList.remove('hidden');
        elements.loggedInView.classList.add('hidden');
    }
}

export function renderDashboard(currentUser) {
    const dashboardHtml = `
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <section class="bg-white p-8 rounded-lg shadow-md lg:col-span-1">
                <h3 class="text-2xl font-semibold text-gray-800 mb-6">System Status</h3>
                <div class="space-y-3">
                    <p class="text-gray-700 text-lg">Merkle Root: <span id="merkle-root" class="font-mono text-base break-all"></span></p>
                    <p class="text-gray-700 text-lg">VWAP: <span id="vwap" class="font-semibold"></span></p>
                </div>
            </section>

            <section class="bg-white p-8 rounded-lg shadow-md lg:col-span-2">
                <h3 class="text-2xl font-semibold text-gray-800 mb-6">Place Order</h3>
                <form id="order-form" class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                        <label for="asset" class="block text-base font-medium text-gray-700">Asset:</label>
                        <input type="text" id="asset" name="asset" value="BTC" required class="mt-2 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 text-base p-2">
                    </div>
                    <div>
                        <label for="type" class="block text-base font-medium text-gray-700">Type:</label>
                        <select id="type" name="type" class="mt-2 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 text-base p-2">
                            <option value="buy">Buy</option>
                            <option value="sell">Sell</option>
                        </select>
                    </div>
                    <div>
                        <label for="amount" class="block text-base font-medium text-gray-700">Amount:</label>
                        <input type="number" id="amount" name="amount" step="0.01" required class="mt-2 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 text-base p-2">
                    </div>
                    <div>
                        <label for="price" class="block text-base font-medium text-gray-700">Price:</label>
                        <input type="number" id="price" name="price" step="0.01" required class="mt-2 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 text-base p-2">
                    </div>
                    <div class="md:col-span-2">
                        <button type="submit" class="w-full flex justify-center py-3 px-4 border border-transparent rounded-md shadow-sm text-base font-medium text-white bg-indigo-600 hover:bg-indigo-700">Place Order</button>
                    </div>
                </form>
            </section>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-8">
            <section class="bg-white p-8 rounded-lg shadow-md">
                <h3 class="text-2xl font-semibold text-gray-800 mb-6">Order Book</h3>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <div>
                        <h4 class="text-xl font-medium text-gray-700 mb-3">Buy Orders</h4>
                        <div id="buy-orders" class="space-y-2 text-gray-600 text-base"></div>
                    </div>
                    <div>
                        <h4 class="text-xl font-medium text-gray-700 mb-3">Sell Orders</h4>
                        <div id="sell-orders" class="space-y-2 text-gray-600 text-base"></div>
                    </div>
                </div>
            </section>

            <section class="bg-white p-8 rounded-lg shadow-md">
                <h3 class="text-2xl font-semibold text-gray-800 mb-6">Search Trades</h3>
                <form id="search-form" class="flex space-x-6 mb-6">
                    <label for="search-keyword" class="sr-only">Keyword:</label>
                    <input type="text" id="search-keyword" name="keyword" required class="flex-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 text-base p-2" placeholder="Search keyword">
                    <button type="submit" class="px-4 py-2 border border-transparent rounded-md shadow-sm text-base font-medium text-white bg-indigo-600 hover:bg-indigo-700">Search</button>
                </form>
                <div id="search-results" class="space-y-2 text-gray-600 text-base"></div>
            </section>
        </div>
    `;
    elements.mainDashboard.innerHTML = dashboardHtml;
}