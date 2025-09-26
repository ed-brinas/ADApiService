document.addEventListener('DOMContentLoaded', () => {
    // --- Configuration and State ---
    const API_BASE_URL = '/api';
    let currentUser = null;
    let config = null;
    let createUserModal, editUserModal, resetPasswordResultModal, createUserResultModal;

    // --- UI Element Cache ---
    const screens = {
        login: document.getElementById('login-page'),
        error: document.getElementById('error-screen'),
        main: document.getElementById('main-app'),
        loading: document.getElementById('loading-spinner')
    };
    const alertPlaceholder = document.getElementById('alert-placeholder');
    
    // --- UI Functions ---
    const showScreen = (screenName) => {
        Object.values(screens).forEach(s => s.style.display = 'none');
        if (screenName === 'main') {
            // FIX: Use 'block' to ensure the main layout stacks vertically.
            // 'flex' was causing the nav, main, and footer to align in a row.
            screens.main.style.display = 'block';
        } else if (screens[screenName]) {
            // 'flex' is appropriate for login/error screens to center content.
            screens[screenName].style.display = 'flex';
        }
    };

    const showLoading = (show) => { screens.loading.style.display = show ? 'flex' : 'none'; };
    
    const showAlert = (message, type = 'danger') => {
        const wrapper = document.createElement('div');
        wrapper.innerHTML = [
            `<div class="alert alert-${type} alert-dismissible fade show" role="alert">`,
            `   <div>${message}</div>`,
            '   <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>',
            '</div>'
        ].join('');
        alertPlaceholder.innerHTML = '';
        alertPlaceholder.append(wrapper);
    };

    const toISODateString = (date) => date.toISOString().split('T')[0];
    const formatDateForInput = (dateString) => !dateString ? '' : toISODateString(new Date(dateString));
    const formatDisplayDate = (dateString) => !dateString ? 'Never' : new Date(dateString).toLocaleDateString();

    // --- API Communication ---
    const apiFetch = async (url, options = {}) => {
        showLoading(true);
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 15000); // 15-second timeout

            const mergedOptions = { 
                ...options, 
                headers: { 'Content-Type': 'application/json', ...options.headers }, 
                credentials: 'include',
                signal: controller.signal
            };

            if (mergedOptions.body && typeof mergedOptions.body !== 'string') {
                mergedOptions.body = JSON.stringify(mergedOptions.body);
            }
            
            const response = await fetch(url, mergedOptions);
            clearTimeout(timeoutId);

            if (!response.ok) {
                const errorBody = await response.text();
                let errorData;
                try { errorData = JSON.parse(errorBody); }
                catch (e) { errorData = { message: `HTTP error! status: ${response.status}`, detail: errorBody || 'Server returned an unexpected response.' }; }
                if (response.status === 401) errorData.detail = "Authentication failed.";
                throw errorData;
            }
            if (response.status === 204) return null;
            return response.json();
        } catch (error) {
            if (error.name === 'AbortError') {
                throw { message: 'Request Timed Out', detail: 'The server did not respond in time.' };
            }
            throw error;
        } finally {
            showLoading(false);
        }
    };

    // --- Core Application Logic ---
    const setupMainApplication = async () => {
        document.getElementById('user-name').textContent = currentUser.name;
        const domainSelect = document.getElementById('domain-select');
        const createDomainSelect = document.getElementById('create-domain');
        domainSelect.innerHTML = createDomainSelect.innerHTML = '';
        config.domains.forEach(d => {
            domainSelect.add(new Option(d, d));
            createDomainSelect.add(new Option(d, d));
        });
        
        document.getElementById('create-user-show-modal-btn').disabled = !currentUser.isHighPrivilege;
        
        showScreen('main');
        await handleSearch();
    };
    
    const tryAutoLogin = async () => {
        try {
            currentUser = await apiFetch(`${API_BASE_URL}/auth/me`);
            config = await apiFetch(`${API_BASE_URL}/config/settings`);
            await setupMainApplication();
        } catch (error) {
            showScreen('login');
        }
    };

    const handleLoginClick = async () => {
        try {
            // FIX: Removed call to undefined function checkApiHealth().
            // The subsequent apiFetch calls will handle API connection errors.
            currentUser = await apiFetch(`${API_BASE_URL}/auth/me`);
            config = await apiFetch(`${API_BASE_URL}/config/settings`);
            await setupMainApplication();
        } catch (error) {
            document.getElementById('error-title').textContent = 'Access Denied';
            document.getElementById('error-details').textContent = error.detail || error.message || 'You are not authorized to access this portal.';
            showScreen('error');
        }
    };

    const handleLogoutClick = () => {
        currentUser = null;
        config = null;

        showScreen('login');
    };
    
    const handleSearch = async () => {
        const domain = document.getElementById('domain-select').value;
        const nameFilter = document.getElementById('name-filter').value;
        const statusFilter = document.getElementById('status-filter').value;
        const adminFilter = document.getElementById('admin-filter').value;
        const tableBody = document.getElementById('user-table-body');
        tableBody.innerHTML = '<tr><td colspan="7" class="text-center">Searching...</td></tr>';

        const params = new URLSearchParams({ domain });
        if(nameFilter) params.append('nameFilter', nameFilter);
        if(statusFilter) params.append('statusFilter', statusFilter);
        if(adminFilter) params.append('hasAdminAccount', adminFilter);
        const requestUrl = `${API_BASE_URL}/users/list?${params.toString()}`;

        try {
            const users = await apiFetch(requestUrl);
            if (!users || users.length === 0) {
                tableBody.innerHTML = '<tr><td colspan="7" class="text-center">No users found.</td></tr>';
                return;
            }
            
            const tableHtml = users.map(user => `
                <tr>
                    <td>${user.displayName || ''}</td>
                    <td>${user.samAccountName || ''}</td>
                    <td>${domain}</td>
                    <td>${user.enabled ? '<span class="badge text-success-emphasis bg-success-subtle border border-success-subtle rounded-pill">Enabled</span>' : '<span class="badge text-danger-emphasis bg-danger-subtle border border-danger-subtle rounded-pill">Disabled</span>'}</td>
                    <td>${user.hasAdminAccount ? '✔️' : ''}</td>
                    <td>${formatDisplayDate(user.accountExpirationDate)}</td>
                    <td class="action-btn-group">
                        <button class="btn btn-sm btn-secondary" title="Edit User" data-action="edit" data-sam="${user.samAccountName}"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-pencil-square" viewBox="0 0 16 16"><path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z"/><path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5z"/></svg></button>
                        <button class="btn btn-sm btn-warning" title="Reset Password" data-action="reset-pw" data-sam="${user.samAccountName}"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-key-fill" viewBox="0 0 16 16"><path d="M3.5 11.5a3.5 3.5 0 1 1 3.163-5H14L15.5 8 14 9.5l-1-1-1 1-1-1-1 1-1-1-1 1H6.663a3.5 3.5 0 0 1-3.163 2zM2.5 9a1 1 0 1 0 0-2 1 1 0 0 0 0 2"/></svg></button>
                        ${currentUser.isHighPrivilege && user.hasAdminAccount
                            ? `<button class="btn btn-sm btn-dark" title="Reset Admin Password" data-action="reset-admin-pw" data-sam="${user.samAccountName}"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-shield-lock-fill" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M8 0c-.69 0-1.843.265-2.928.56-1.11.3-2.229.655-2.887.87a1.54 1.54 0 0 0-1.044 1.262c-.596 4.477.787 7.795 2.465 9.99a11.8 11.8 0 0 0 2.517 2.453c.386.273.744.482 1.048.625.28.132.581.19.829.19s.548-.058.829-.19c.304-.143.662-.352 1.048-.625a11.8 11.8 0 0 0 2.517-2.453c1.678-2.195 3.061-5.513 2.465-9.99a1.54 1.54 0 0 0-1.044-1.262c-.658-.215-1.777-.57-2.887-.87C9.843.265 8.69 0 8 0m2.028 6.472a.5.5 0 0 1 .472.472v3.056a.5.5 0 0 1-1 0V7.004a.5.5 0 0 1 .528-.472M8 4.5a1.5 1.5 0 1 1 0 3 1.5 1.5 0 0 1 0-3"/></svg></button>`
                            : ''
                        }                      
                        <button class="btn btn-sm btn-info" title="Unlock Account" data-action="unlock" data-sam="${user.samAccountName}"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-unlock-fill" viewBox="0 0 16 16"><path d="M11 1a2 2 0 0 0-2 2v4a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2h5V3a3 3 0 0 1 6 0v4a.5.5 0 0 1-1 0V3a2 2 0 0 0-2-2"/></svg></button>
                        ${user.enabled
                            ? `<button class="btn btn-sm btn-danger" title="Disable Account" data-action="disable" data-sam="${user.samAccountName}"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-person-fill-slash" viewBox="0 0 16 16"><path d="M13.879 10.414a2.502 2.502 0 0 0-3.465-3.465l3.465 3.465Zm.707.707-3.465-3.465a2.502 2.502 0 0 0-3.465 3.465l3.465-3.465Zm-4.56-4.56a2.5 2.5 0 1 0 0-3.535 2.5 2.5 0 0 0 0 3.535M11 5a3 3 0 1 1-6 0 3 3 0 0 1 6 0m-2.293 7.293a1 1 0 0 1-1.414 0l-1.414-1.414a1 1 0 1 1 1.414-1.414l1.414 1.414a1 1 0 0 1 0 1.414m2.828-2.828a1 1 0 0 1-1.414-1.414l-1.414 1.414a1 1 0 1 1-1.414-1.414l1.414-1.414a1 1 0 1 1 1.414 1.414l-1.414 1.414a1 1 0 0 1 1.414 1.414l-3.535-3.535a1 1 0 0 1 1.414-1.414zM4.5 0A3.5 3.5 0 0 1 8 3.5v1.096a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V3.5A3.5 3.5 0 0 1 4.5 0"/></svg></button>`
                            : `<button class="btn btn-sm btn-success" title="Enable Account" data-action="enable" data-sam="${user.samAccountName}"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-person-fill-check" viewBox="0 0 16 16"><path d="M12.5 16a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7m-.646-4.854.646.647.646-.647a.5.5 0 0 1 .708.708l-1 1a.5.5 0 0 1-.708 0l-.5-.5a.5.5 0 0 1 .708-.708z"/><path d="M5.5 2.5a2.5 2.5 0 1 1-5 0 2.5 2.5 0 0 1 5 0m.5 8.5a.5.5 0 0 1 .5.5v1.5a.5.5 0 0 1-1 0V12a.5.5 0 0 1 .5-.5m-2-1a.5.5 0 0 1 .5-.5h4a.5.5 0 0 1 0 1h-4a.5.5 0 0 1-.5-.5m1.5 2a.5.5 0 0 1 .5-.5h2a.5.5 0 0 1 0 1h-2a.5.5 0 0 1-.5-.5"/></svg></button>`
                        }
                    </td>
                </tr>
            `).join('');
            
            tableBody.innerHTML = tableHtml;
        } catch (error) {
            tableBody.innerHTML = `<tr><td colspan="7" class="text-center text-danger">Failed to load users: ${error.detail || error.message}</td></tr>`;
        }
    };
    
    const handleShowCreateModal = () => {
        document.getElementById('create-user-form').reset();
        const expirationInput = document.getElementById('create-expiration');
        const today = new Date();
        const oneYearFromNow = new Date();
        oneYearFromNow.setFullYear(today.getFullYear() + 1);
        expirationInput.min = toISODateString(today);
        expirationInput.max = toISODateString(oneYearFromNow);
        expirationInput.value = toISODateString(oneYearFromNow);
        const groupsContainer = document.getElementById('create-optional-groups-container');
        const adminContainer = document.getElementById('create-admin-container');
        if (currentUser.isHighPrivilege) {
            adminContainer.style.display = 'block';
            const groupsList = document.getElementById('create-optional-groups-list');
            if (config.optionalGroupsForHighPrivilege && config.optionalGroupsForHighPrivilege.length > 0) {
                groupsContainer.style.display = 'block';
                groupsList.innerHTML = config.optionalGroupsForHighPrivilege.map(g => `<div class="form-check"><input class="form-check-input" type="checkbox" value="${g}" id="create-group-${g}"><label class="form-check-label" for="create-group-${g}">${g}</label></div>`).join('');
            } else {
                groupsContainer.style.display = 'none';
            }
        } else {
            groupsContainer.style.display = 'none';
            adminContainer.style.display = 'none';
        }
    };

    const handleShowEditModal = async (sam, domain) => {
        document.getElementById('edit-user-form').reset();
        try {
            const userDetails = await apiFetch(`${API_BASE_URL}/users/details/${domain}/${sam}`);
            if (!userDetails) {
                showAlert(`Could not find details for user '${sam}'. The user may have been deleted or is outside the configured search scope.`, 'warning');
                return;
            }

            document.getElementById('edit-username-display').value = userDetails.samAccountName;
            document.getElementById('edit-samaccountname').value = userDetails.samAccountName;
            // FIX: Changed userDetails.firstName to userDetails.givenName
            document.getElementById('edit-firstname').value = userDetails.firstName || '';
            // FIX: Changed userDetails.lastName to userDetails.sn
            document.getElementById('edit-lastname').value = userDetails.lastName || '';
            document.getElementById('edit-domain').value = domain;
            const expirationInput = document.getElementById('edit-expiration');
            const today = new Date();
            const oneYearFromNow = new Date();
            oneYearFromNow.setFullYear(today.getFullYear() + 1);
            expirationInput.min = toISODateString(today);
            expirationInput.max = toISODateString(oneYearFromNow);
            expirationInput.value = formatDateForInput(userDetails.accountExpirationDate) || toISODateString(oneYearFromNow);
            
            const groupsContainer = document.getElementById('edit-optional-groups-container');
            const adminContainer = document.getElementById('edit-admin-container');
            if (currentUser.isHighPrivilege) {
                adminContainer.style.display = 'block';
                document.getElementById('edit-admin-account').checked = userDetails.hasAdminAccount;
                const groupsList = document.getElementById('edit-optional-groups-list');
                if (config.optionalGroupsForHighPrivilege && config.optionalGroupsForHighPrivilege.length > 0) {
                    groupsContainer.style.display = 'block';
                    groupsList.innerHTML = config.optionalGroupsForHighPrivilege.map(g => `<div class="form-check"><input class="form-check-input" type="checkbox" value="${g}" id="edit-group-${g}" ${userDetails.memberOf.includes(g) ? 'checked' : ''}><label class="form-check-label" for="edit-group-${g}">${g}</label></div>`).join('');
                } else {
                    groupsContainer.style.display = 'none';
                }
            } else {
                groupsContainer.style.display = 'none';
                adminContainer.style.display = 'none';
            }
            editUserModal.show();
        } catch (error) {
            showAlert(`Failed to load user details: ${error.detail || error.message}`);
        }
    };

    const handleResetPassword = async (sam, domain) => {
        if (!confirm(`Are you sure you want to reset the password for ${sam}? A new random password will be generated.`)) return;
        try {
            const result = await apiFetch(`${API_BASE_URL}/users/reset-password`, { method: 'POST', body: { domain, samAccountName: sam } });
            document.getElementById('reset-pw-result-username').textContent = result.samAccountName;
            document.getElementById('reset-pw-result-new').value = result.newPassword;
            resetPasswordResultModal.show();
        } catch (error) {
            showAlert(`Failed to reset password: ${error.detail || error.message}`);
        }
    };

    const handleResetAdminPassword = async (sam, domain) => {
        if (!confirm(`Are you sure you want to reset the ADMIN password for the account associated with ${sam}? A new random password will be generated for the admin account.`)) return;
        try {
            const result = await apiFetch(`${API_BASE_URL}/users/reset-admin-password`, {
                method: 'POST',
                body: { domain, samAccountName: sam }
            });
            document.getElementById('reset-pw-result-username').textContent = result.samAccountName;
            document.getElementById('reset-pw-result-new').value = result.newPassword;
            resetPasswordResultModal.show();
        } catch (error) {
            showAlert(`Failed to reset admin password: ${error.detail || error.message}`);
        }
    };    

    const handleUnlock = async (sam, domain) => {
         if (!confirm(`Are you sure you want to unlock the account for ${sam}?`)) return;
        try {
            await apiFetch(`${API_BASE_URL}/users/unlock`, { method: 'POST', body: { domain, samAccountName: sam } });
            showAlert(`Successfully unlocked account: ${sam}`, 'success');
            handleSearch();
        } catch (error) {
            showAlert(`Failed to unlock account: ${error.detail || error.message}`);
        }
    };

    const handleDisable = async (sam, domain) => {
        if (!confirm(`Are you sure you want to DISABLE the account for ${sam}?`)) return;
        try {
            await apiFetch(`${API_BASE_URL}/users/disable`, { method: 'POST', body: { domain, samAccountName: sam } });
            showAlert(`Successfully disabled account: ${sam}`, 'success');
            handleSearch();
        } catch (error) {
            showAlert(`Failed to disable account: ${error.detail || error.message}`);
        }
    };

    const handleEnable = async (sam, domain) => {
        if (!confirm(`Are you sure you want to ENABLE the account for ${sam}?`)) return;
        try {
            await apiFetch(`${API_BASE_URL}/users/enable`, { method: 'POST', body: { domain, samAccountName: sam } });
            showAlert(`Successfully enabled account: ${sam}`, 'success');
            handleSearch();
        } catch (error) {
            showAlert(`Failed to enable account: ${error.detail || error.message}`);
        }
    };

    const handleCreateSubmit = async (e) => {
        e.preventDefault();
        const form = e.target;
        if (!form.checkValidity()) { 
            form.classList.add('was-validated');
            e.stopPropagation(); 
            return; 
        }
        const expirationDate = form.querySelector('#create-expiration').value;
        const optionalGroups = Array.from(form.querySelectorAll('#create-optional-groups-list input:checked')).map(cb => cb.value);
        const data = {
            domain: form.querySelector('#create-domain').value,
            firstName: form.querySelector('#create-firstname').value,
            lastName: form.querySelector('#create-lastname').value,
            samAccountName: form.querySelector('#create-samaccountname').value,
            optionalGroups: optionalGroups,
            createAdminAccount: form.querySelector('#create-admin-account').checked,
            accountExpirationDate: expirationDate
        };
        try {
            const result = await apiFetch(`${API_BASE_URL}/users/create`, { method: 'POST', body: data });
            createUserModal.hide();
            const resultBody = document.getElementById('create-user-result-body');
            let resultHtml = `<h6>${result.message}</h6>`;
            if (result.userAccount) {
                resultHtml += `<h5 class="mt-4">User Account Details</h5><table class="table table-sm result-table"><tr><td><strong>Username:</strong></td><td>${result.userAccount.samAccountName}</td></tr><tr><td><strong>Display Name:</strong></td><td>${result.userAccount.displayName}</td></tr><tr><td><strong>Temporary Password:</strong></td><td><code>${result.userAccount.initialPassword}</code></td></tr></table>`;
            }
            if (result.adminAccount) {
                resultHtml += `<h5 class="mt-4">Admin Account Details</h5><table class="table table-sm result-table"><tr><td><strong>Username:</strong></td><td>${result.adminAccount.samAccountName}</td></tr><tr><td><strong>Display Name:</strong></td><td>${result.adminAccount.displayName}</td></tr><tr><td><strong>Temporary Password:</strong></td><td><code>${result.adminAccount.initialPassword}</code></td></tr></table>`;
            }
            if(result.groupsAssociated && result.groupsAssociated.length > 0){
                resultHtml += `<h5 class="mt-4">Associated Groups</h5><p>${result.groupsAssociated.join(', ')}</p>`;
            }
            resultBody.innerHTML = resultHtml;
            createUserResultModal.show();
            handleSearch();
        } catch (error) {
            const validationErrors = error.errors ? Object.values(error.errors).flat().join(' ') : '';
            showAlert(`Failed to create user: ${error.detail || error.message} ${validationErrors}`);
        }
    };
    
    const handleEditSubmit = async (e) => {
        e.preventDefault();
        const form = e.target;
         if (!form.checkValidity()) { 
            form.classList.add('was-validated');
            e.stopPropagation(); 
            return; 
        }
        const expirationDate = form.querySelector('#edit-expiration').value;
        const optionalGroups = Array.from(form.querySelectorAll('#edit-optional-groups-list input:checked')).map(cb => cb.value);
        const data = {
            domain: form.querySelector('#edit-domain').value,
            samAccountName: form.querySelector('#edit-samaccountname').value,
            firstName: form.querySelector('#edit-firstname').value,
            lastName: form.querySelector('#edit-lastname').value,
            optionalGroups: optionalGroups,
            manageAdminAccount: form.querySelector('#edit-admin-account').checked,
            accountExpirationDate: expirationDate
        };
        try {
            await apiFetch(`${API_BASE_URL}/users/update`, { method: 'PUT', body: data });
            editUserModal.hide();
            showAlert(`Successfully updated user: ${data.samAccountName}`, 'success');
            handleSearch();
        } catch (error) {
            const validationErrors = error.errors ? Object.values(error.errors).flat().join(' ') : '';
            showAlert(`Failed to update user: ${error.detail || error.message} ${validationErrors}`);
        }
    };

    // --- Event Listeners and Initialization ---
    document.getElementById('login-btn').addEventListener('click', handleLoginClick);
    //document.getElementById('logout-btn').addEventListener('click', () => showScreen('login'));
    document.getElementById('logout-btn').addEventListener('click', handleLogoutClick);
    document.getElementById('try-again-btn').addEventListener('click', () => showScreen('login'));
    document.getElementById('search-users-btn').addEventListener('click', handleSearch);
    document.getElementById('create-user-show-modal-btn').addEventListener('click', () => { handleShowCreateModal(); createUserModal.show(); });
    document.getElementById('create-user-form').addEventListener('submit', handleCreateSubmit);
    document.getElementById('edit-user-form').addEventListener('submit', handleEditSubmit);
    document.getElementById('user-table-body').addEventListener('click', (e) => {
        const button = e.target.closest('button[data-action]');
        if (!button) return;
        const sam = button.dataset.sam;
        const domain = document.getElementById('domain-select').value;
        switch(button.dataset.action) {
            case 'edit': handleShowEditModal(sam, domain); break;
            case 'reset-pw': handleResetPassword(sam, domain); break;
            case 'unlock': handleUnlock(sam, domain); break;
            case 'disable': handleDisable(sam, domain); break;
            case 'enable': handleEnable(sam, domain); break;
        }
    });
    document.getElementById('copy-password-btn').addEventListener('click', () => {
        const passwordInput = document.getElementById('reset-pw-result-new');
        passwordInput.select();
        document.execCommand('copy');
        showAlert('Password copied to clipboard!', 'success');
    });

    createUserModal = new bootstrap.Modal(document.getElementById('create-user-modal'));
    editUserModal = new bootstrap.Modal(document.getElementById('edit-user-modal'));
    resetPasswordResultModal = new bootstrap.Modal(document.getElementById('reset-password-result-modal'));
    createUserResultModal = new bootstrap.Modal(document.getElementById('create-user-result-modal'));

    tryAutoLogin();
});
