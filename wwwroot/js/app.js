$(document).ready(function () {
    let userContext = {};
    let appConfig = {};

    // --- INITIALIZATION ---

    // 1. Check if the user is authenticated
    function initializeApp() {
        $.ajax({
            url: "/api/auth/me",
            method: "GET",
            success: function (data) {
                userContext = data;
                $('#username-display').text(userContext.name);
                $('#main-content').show();
                fetchAppConfig(); // 2. If authenticated, get the app config
            },
            error: function () {
                $('#main-content').hide();
                showAlert("Authentication failed. Please ensure you are logged in and have access.", "danger");
            }
        });
    }

    // 2. Fetch configuration from the backend (domains, groups, etc.)
    function fetchAppConfig() {
        $.get("/api/config/settings", function (data) {
            appConfig = data;
            populateDomainFilters(appConfig.domains); // 3. Populate filters
        }).fail(function (xhr) {
             showAlert(`Error fetching application configuration: ${extractError(xhr)}`, "danger");
        });
    }

    // 3. Populate the main domain filter dropdown
    function populateDomainFilters(domains) {
        const domainFilter = $('#domain-filter');
        domainFilter.empty().append('<option value="">All Domains</option>');
        domains.forEach(d => {
            domainFilter.append(`<option value="${d}">${d}</option>`);
        });
    }


    // --- CORE UI FUNCTIONS ---

    // Fetches and displays the list of users based on current filters
    function listUsers() {
        const params = {
            domain: $('#domain-filter').val(),
            nameFilter: $('#name-filter').val(),
            statusFilter: $('#status-filter').val(),
            hasAdminAccount: $('#admin-account-filter').val()
        };

        // Only include domain if one is selected, otherwise AD will search all domains
        if (!params.domain) {
            delete params.domain;
        }

        const queryString = $.param(params);
        $.get(`/api/users/list?${queryString}`, function (users) {
            const userTableBody = $('#user-table-body');
            userTableBody.empty();
            if (users.length === 0) {
                userTableBody.append('<tr><td colspan="5" class="text-center">No users found.</td></tr>');
                return;
            }
            users.forEach(user => {
                const row = `
                    <tr>
                        <td>${user.displayName || 'N/A'}</td>
                        <td>${user.samAccountName}</td>
                        <td>${user.isEnabled ? '<span class="badge bg-success">Enabled</span>' : '<span class="badge bg-secondary">Disabled</span>'}</td>
                        <td>${user.hasAdminAccount ? '<i class="bi bi-shield-lock-fill text-primary"></i> Yes' : 'No'}</td>
                        <td>
                            <button class="btn btn-sm btn-primary action-btn" data-action="edit" data-sam="${user.samAccountName}" data-domain="${params.domain || appConfig.domains[0]}"><i class="bi bi-pencil-square"></i> Edit</button>
                            <button class="btn btn-sm btn-info action-btn" data-action="reset-password" data-sam="${user.samAccountName}" data-domain="${params.domain || appConfig.domains[0]}"><i class="bi bi-key-fill"></i> Reset Password</button>
                            <button class="btn btn-sm btn-warning action-btn" data-action="unlock" data-sam="${user.samAccountName}" data-domain="${params.domain || appConfig.domains[0]}"><i class="bi bi-unlock-fill"></i> Unlock</button>
                            ${user.isEnabled 
                                ? `<button class="btn btn-sm btn-danger action-btn" data-action="disable" data-sam="${user.samAccountName}" data-domain="${params.domain || appConfig.domains[0]}"><i class="bi bi-person-x-fill"></i> Disable</button>`
                                : `<button class="btn btn-sm btn-success action-btn" data-action="enable" data-sam="${user.samAccountName}" data-domain="${params.domain || appConfig.domains[0]}"><i class="bi bi-person-check-fill"></i> Enable</button>`
                            }
                        </td>
                    </tr>
                `;
                userTableBody.append(row);
            });
        });
    }

    // --- MODAL LOGIC ---

    // Sets up and displays the user modal for either 'create' or 'edit' mode
    function showUserModal(mode, userData = null) {
        $('#user-form')[0].reset();
        $('#modal-mode').val(mode);
        $('#sam-account-name').prop('readonly', mode === 'edit');
        $('#domain-select').prop('disabled', mode === 'edit');
        $('#user-modal .is-invalid').removeClass('is-invalid');
        $('#edit-optional-groups-container').hide();


        // Populate domains dropdown in the modal
        $('#domain-select').empty();
        appConfig.domains.forEach(d => $('#domain-select').append(`<option value="${d}">${d}</option>`));

        // Populate Standard Group Checkboxes
        const standardGroupsContainer = $('#standard-groups-container');
        standardGroupsContainer.find('.form-check').remove();
        if (appConfig.optionalGroupsForStandard && appConfig.optionalGroupsForStandard.length > 0) {
            appConfig.optionalGroupsForStandard.forEach(group => {
                standardGroupsContainer.append(
                    `<div class="form-check form-check-inline">
                        <input class="form-check-input standard-group-checkbox" type="checkbox" value="${group}" id="std-group-${group}">
                        <label class="form-check-label" for="std-group-${group}">${group}</label>
                    </div>`
                );
            });
            standardGroupsContainer.show();
        } else {
            standardGroupsContainer.hide();
        }
        
        // Populate High-Privilege Group Checkboxes (if applicable)
        const highPrivilegeGroupsContainer = $('#edit-optional-groups-container');
        highPrivilegeGroupsContainer.find('.form-check').remove();
        if (userContext.isHighPrivilege && appConfig.optionalGroupsForHighPrivilege && appConfig.optionalGroupsForHighPrivilege.length > 0) {
            appConfig.optionalGroupsForHighPrivilege.forEach(group => {
                highPrivilegeGroupsContainer.append(
                    `<div class="form-check form-check-inline">
                        <input class="form-check-input high-privilege-group-checkbox" type="checkbox" value="${group}" id="hp-group-${group}">
                        <label class="form-check-label" for="hp-group-${group}">${group}</label>
                    </div>`
                );
            });
            $('#privilege-section').show();
        } else {
             $('#privilege-section').hide();
        }
        
        if (mode === 'edit') {
            $('#user-modal-label').text('Edit User');
            fetchAndPopulateUserDetails(userData.domain, userData.samAccountName);
        } else {
            $('#user-modal-label').text('Create New User');
            $('#user-modal').modal('show');
        }
    }

    // Fetches detailed user info and fills the modal for editing
    function fetchAndPopulateUserDetails(domain, samAccountName) {
        $.get(`/api/users/details/${domain}/${samAccountName}`, function (details) {
            $('#original-sam-account-name').val(details.samAccountName);
            $('#sam-account-name').val(details.samAccountName);
            $('#domain-select').val(domain);
            $('#first-name').val(details.firstName);
            $('#last-name').val(details.lastName);
            $('#mobile').val(details.mobileNumber);
            if (details.dateOfBirth) {
                $('#dob').val(details.dateOfBirth.split('T')[0]); 
            }

            details.memberOf.forEach(groupName => {
                $(`.standard-group-checkbox[value="${groupName}"]`).prop('checked', true);
                $(`.high-privilege-group-checkbox[value="${groupName}"]`).prop('checked', true);
            });
            
            const hasAdmin = details.hasAdminAccount;
            $('#manage-admin-account-checkbox').prop('checked', hasAdmin);
            if (hasAdmin) {
                $('#edit-optional-groups-container').show();
            } else {
                $('#edit-optional-groups-container').hide();
            }

            $('#user-modal').modal('show');
        }).fail(function (xhr) {
            showAlert(`Error fetching user details: ${extractError(xhr)}`, "danger");
        });
    }

    // Handles the save button click for both create and edit modes
    function saveUser() {
        const form = $('#user-form');
        if (!form[0].checkValidity()) {
            form[0].reportValidity();
            return;
        }

        const mobileInput = $('#mobile');
        const mobileValue = mobileInput.val();
        const mobileRegex = /^\+966\d{9}$/; // Regex for +966 followed by 9 digits
        if (mobileValue && !mobileRegex.test(mobileValue)) {
            mobileInput.addClass('is-invalid');
            return;
        } else {
            mobileInput.removeClass('is-invalid');
        }

        const mode = $('#modal-mode').val();
        const sam = (mode === 'edit') ? $('#original-sam-account-name').val() : $('#sam-account-name').val();

        let selectedGroups = [];
        $('.standard-group-checkbox:checked').each(function() {
            selectedGroups.push($(this).val());
        });
        if ($('#manage-admin-account-checkbox').is(':checked')) {
            $('.high-privilege-group-checkbox:checked').each(function() {
                selectedGroups.push($(this).val());
            });
        }
        
        const userData = {
            domain: $('#domain-select').val(),
            samAccountName: sam,
            firstName: $('#first-name').val(),
            lastName: $('#last-name').val(),
            dateOfBirth: $('#dob').val(),
            mobileNumber: mobileValue,
            optionalGroups: selectedGroups
        };

        let url, method;
        if (mode === 'create') {
            url = '/api/users/create';
            method = 'POST';
            userData.createAdminAccount = $('#manage-admin-account-checkbox').is(':checked');
        } else {
            url = '/api/users/update';
            method = 'PUT';
            userData.hasAdminAccount = $('#manage-admin-account-checkbox').is(':checked');
        }

        $.ajax({
            url: url,
            method: method,
            contentType: 'application/json',
            data: JSON.stringify(userData),
            success: function (response) {
                $('#user-modal').modal('hide');
                showAlert(`User successfully ${mode === 'create' ? 'created' : 'updated'}.`, 'success');
                if (mode === 'create' && response.initialPassword) {
                   showPasswordModal(response);
                }
                listUsers();
            },
            error: function (xhr) {
                showAlert(`Error: ${extractError(xhr)}`, 'danger');
            }
        });
    }

    // Shows modal with newly created passwords
    function showPasswordModal(response) {
        let content = `<p><strong>Standard Account (${response.samAccountName}):</strong> <kbd>${response.initialPassword}</kbd></p>`;
        if (response.adminAccountName) {
            content += `<p><strong>Admin Account (${response.adminAccountName}):</strong> <kbd>${response.adminInitialPassword}</kbd></p>`;
        }
        $('#password-modal-body').html(content);
        $('#password-modal').modal('show');
    }

    // --- EVENT HANDLERS ---

    $('#filter-button').on('click', listUsers);
    $('#create-user-button').on('click', () => showUserModal('create'));
    $('#save-user-button').on('click', saveUser);

    $('#manage-admin-account-checkbox').on('change', function() {
        if ($(this).is(':checked')) {
            $('#edit-optional-groups-container').slideDown();
        } else {
            $('#edit-optional-groups-container').slideUp();
            $('.high-privilege-group-checkbox').prop('checked', false);
        }
    });

    // Delegated event handler for all action buttons in the user table
    $('#user-table-body').on('click', '.action-btn', function () {
        const action = $(this).data('action');
        const sam = $(this).data('sam');
        const domain = $(this).data('domain');
        
        const requestData = { domain: domain, samAccountName: sam };

        if (action === 'edit') {
            showUserModal('edit', { domain, samAccountName: sam });
            return;
        }

        let url, method, successMessage, confirmationMessage;
        
        switch (action) {
            case 'reset-password':
                confirmationMessage = `Are you sure you want to reset the password for ${sam}?`;
                url = '/api/users/reset-password';
                method = 'POST';
                break;
            case 'unlock':
                url = '/api/users/unlock';
                method = 'POST';
                successMessage = `Account ${sam} has been unlocked.`;
                break;
            case 'disable':
                confirmationMessage = `Are you sure you want to disable the account ${sam}?`;
                url = '/api/users/disable';
                method = 'POST';
                successMessage = `Account ${sam} has been disabled.`;
                break;
            case 'enable':
                url = '/api/users/enable';
                method = 'POST';
                successMessage = `Account ${sam} has been enabled.`;
                break;
            default:
                return;
        }

        if (confirmationMessage && !confirm(confirmationMessage)) {
            return;
        }

        $.ajax({
            url: url,
            method: method,
            contentType: 'application/json',
            data: JSON.stringify(requestData),
            success: function(response) {
                if (action === 'reset-password') {
                    showPasswordModal({ samAccountName: sam, initialPassword: response.newPassword });
                } else {
                    showAlert(successMessage, 'success');
                }
                listUsers();
            },
            error: function (xhr) {
                showAlert(`Error performing action: ${extractError(xhr)}`, 'danger');
            }
        });
    });

    // --- HELPER FUNCTIONS ---

    function extractError(xhr) {
        if (xhr.responseJSON && xhr.responseJSON.message) {
            return xhr.responseJSON.message + (xhr.responseJSON.details ? ` (${xhr.responseJSON.details})` : '');
        }
        return xhr.statusText || 'An unknown error occurred.';
    }

    function showAlert(message, type) {
        const alertPlaceholder = $('#alert-placeholder');
        const wrapper = document.createElement('div');
        wrapper.innerHTML = [
            `<div class="alert alert-${type} alert-dismissible fade show" role="alert">`,
            `   <div>${message}</div>`,
            '   <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>',
            '</div>'
        ].join('');
        alertPlaceholder.append(wrapper);
    }

    // --- START THE APP ---
    initializeApp();
});
