console.log("main.js loaded and executing.");

const API_BASE_URL = 'http://127.0.0.1:8000';

import { loginUser, registerUser, logoutUser, checkAuthStatus, getCurrentUser } from './modules/auth.js';
import { placeOrderApi, fetchOrderBookApi, fetchSystemStatusApi, searchTradesApi } from './modules/api.js';
import { showMessage } from './modules/utils.js';
import { elements, updateUI, renderDashboard } from './modules/ui.js';
import { updateDashboardData } from './modules/dashboard.js';

document.addEventListener('DOMContentLoaded', async () => {
    // --- Event Listeners ---
    elements.loginForm.addEventListener('submit', loginUser);
    elements.registerForm.addEventListener('submit', registerUser);
    elements.logoutButton.addEventListener('click', logoutUser);

    document.getElementById('home-link').addEventListener('click', (e) => {
        e.preventDefault();
        elements.mainDashboard.classList.remove('hidden');
        elements.adminContent.classList.add('hidden');
    });

    // --- Protected Content Handler ---
    async function handleProtectedContent(event) {
        event.preventDefault();
        const targetUrl = event.currentTarget.getAttribute('href');
        const accessToken = localStorage.getItem('access_token');

        if (!accessToken) {
            showMessage('Please log in to access this page.', 'error', 'logged-in');
            return;
        }

        const currentUser = getCurrentUser();
        if (!currentUser || currentUser.role !== 'admin') {
            showMessage('You do not have permission to access this page. Admin access required.', 'error', 'logged-in');
            return;
        }

        try {
            const response = await fetch(`${API_BASE_URL}${targetUrl}`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'text/html'
                }
            });

            if (response.ok) {
                const html = await response.text();
                elements.mainDashboard.classList.add('hidden');
                elements.adminContent.innerHTML = html;
                elements.adminContent.classList.remove('hidden');

                if (targetUrl === '/analytics') {
                    fetchVwapChart();
                } else if (targetUrl === '/sim') {
                    setupSimulations();
                }
            } else {
                showMessage(`Error accessing ${targetUrl}: ${response.statusText}`, 'error', 'logged-in');
            }
        } catch (error) {
            showMessage('A network error occurred. Please try again.', 'error', 'logged-in');
        }
    }

    // --- Attach Protected Content Handler to Links ---
    document.querySelectorAll('#analytics-link, #logs-link, #sim-link').forEach(link => {
        link.addEventListener('click', handleProtectedContent);
    });

    // --- Initial Setup ---
    const currentUser = await checkAuthStatus();
    if (currentUser) {
        renderDashboard(currentUser);
        updateDashboardData(currentUser);
    }

    // --- Data Fetching Functions ---
    async function placeOrder(event) {
        event.preventDefault();
        const accessToken = localStorage.getItem('access_token');
        const signedOrder = {}; // Simplified for brevity
        await placeOrderApi(signedOrder, accessToken);
        updateDashboardData(getCurrentUser());
    }

    async function searchTrades(event) {
        event.preventDefault();
        const keyword = document.getElementById('search-keyword').value;
        await searchTradesApi(keyword);
    }

    // Fetch data periodically
    setInterval(async () => {
        if (getCurrentUser()) {
            updateDashboardData(getCurrentUser());
        }
    }, 60000);
});

async function fetchVwapChart() {
    const vwapChartCanvas = document.getElementById('vwap-chart');
    if (!vwapChartCanvas) return;

    try {
        const response = await fetch(`${API_BASE_URL}/analytics/vwap-data`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('access_token')}` }
        });
        if (response.ok) {
            const data = await response.json();
            new Chart(vwapChartCanvas, {
                type: 'line',
                data: {
                    labels: data.labels,
                    datasets: [{
                        label: 'VWAP',
                        data: data.vwap,
                        borderColor: '#4F46E5',
                        backgroundColor: 'rgba(79, 70, 229, 0.1)',
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: { enabled: false }
                    },
                    scales: {
                        x: { display: false },
                        y: { display: false }
                    }
                }
            });
        }
    } catch (error) {
        console.error('Error fetching VWAP chart data:', error);
    }
}

function setupSimulations() {
    const outputDiv = document.getElementById('simulation-output');
    async function runSimulation(endpoint) {
        outputDiv.textContent = `Running simulation for ${endpoint}...
`;
        try {
            const response = await fetch(`${API_BASE_URL}${endpoint}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`
                }
            });
            const data = await response.json();

            if (data.steps) {
                data.steps.forEach(step => {
                    const stepDiv = document.createElement('div');
                    stepDiv.classList.add('p-2', 'my-1', 'rounded-md');
                    if (step.actor === 'Red Team') {
                        stepDiv.classList.add('bg-red-100', 'text-red-800');
                    } else {
                        stepDiv.classList.add('bg-blue-100', 'text-blue-800');
                    }
                    stepDiv.textContent = `[${step.actor}] ${step.action}`;
                    outputDiv.appendChild(stepDiv);
                });
            }

        } catch (error) {
            const errorDiv = document.createElement('div');
            errorDiv.classList.add('bg-red-100', 'text-red-800', 'p-2', 'my-1', 'rounded-md');
            errorDiv.textContent = `Error: ${error.message}`;
            outputDiv.appendChild(errorDiv);
        }
    }

    document.getElementById('sqlmap-sim-btn').addEventListener('click', () => runSimulation('/sim/sqlmap'));
    document.getElementById('bruteforce-sim-btn').addEventListener('click', () => runSimulation('/sim/bruteforce'));
    document.getElementById('replay-sim-btn').addEventListener('click', () => runSimulation('/sim/replay'));
    document.getElementById('mitm-sim-btn').addEventListener('click', () => runSimulation('/sim/mitm'));
}
