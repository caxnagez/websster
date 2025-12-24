document.addEventListener('DOMContentLoaded', function () {
    const statusForms = document.querySelectorAll('.status-update-form');

    statusForms.forEach(function (form) {
        form.addEventListener('submit', function (event) {
            event.preventDefault();

            const statusSelect = form.querySelector('select[name="status"]');
            const newStatus = statusSelect.value;
            const callId = form.dataset.callId;
            const departmentName = form.dataset.department; 

            console.log("Attempting to update status for call", callId, "department", departmentName, "to", newStatus);

            fetch(`/api/calls/${callId}/status`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ status: newStatus }),
                credentials: 'same-origin'
            })
            .then(response => {
                 console.log("API response status:", response.status);
                 if (!response.ok) {
                    return response.json().then(errorData => {
                        console.error('API returned error:', errorData);
                        throw new Error(`API Error: ${errorData.error || 'Unknown error'}`);
                    });
                }
                return response.json();
            })
            .then(data => {
                console.log('Status updated via API:', data.message);
                const statusItem = Array.from(document.querySelectorAll('.list-group-item')).find(item => {
                    const strongElement = item.querySelector('strong');
                    return strongElement && strongElement.textContent.trim().toLowerCase() === departmentName.toLowerCase();
                });

                if (statusItem) {
                    const statusBadge = statusItem.querySelector('.badge');
                    if (statusBadge) {
                        statusBadge.textContent = newStatus.charAt(0).toUpperCase() + newStatus.slice(1);
                        statusBadge.className = statusBadge.className.replace(/\bbg-\w+\b/g, '');
                        if (newStatus === 'closed') {
                            statusBadge.classList.add('bg-success');
                        } else if (['on_way', 'arrived'].includes(newStatus)) {
                            statusBadge.classList.add('bg-warning');
                        } else {
                            statusBadge.classList.add('bg-info');
                        }

                        showFlashMessage(data.message, 'success');
                    } else {
                        console.warn('Status badge element not found for department:', departmentName);
                    }
                } else {
                    console.warn('List item for department not found:', departmentName);
                }
            })
            .catch(error => {
                console.error('Network or API error:', error);
                showFlashMessage('Error occurred: ' + error.message, 'error');
            });
        });
    });

    function showFlashMessage(message, category) {
         const alertDiv = document.createElement('div');
         alertDiv.className = `alert alert-${category === 'error' ? 'danger' : 'info'} alert-dismissible fade show`;
         alertDiv.setAttribute('role', 'alert');
         alertDiv.innerHTML = `
             ${message}
             <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
         `;
         const container = document.querySelector('.container');
         if (container) {
             container.insertBefore(alertDiv, container.firstChild);
             setTimeout(() => {
                 if (alertDiv.parentNode) {
                     alertDiv.remove();
                 }
             }, 5000);
         } else {
             console.error("Could not find container element to show flash message.");
         }
    }
});