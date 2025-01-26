// static/scripts.js

function updateDateTime() {
    const now = new Date();
    const options = { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'UTC' };
    document.getElementById('date').value = now.toLocaleString('en-GB', options);  // Format as needed
}

setInterval(updateDateTime, 1000);  // Update every second
updateDateTime();  // Initial call to set the value immediately

function toggleForms() {
    var loginForm = document.getElementById('loginForm');
    var registerForm = document.getElementById('registerForm');
    var toggleButton = document.getElementById('toggleButton');

    if (loginForm.style.display === 'none') {
        loginForm.style.display = 'block';
        registerForm.style.display = 'none';
        toggleButton.textContent = 'Switch to Register'; // Change button text to "Switch to Register"
    } else {
        loginForm.style.display = 'none';
        registerForm.style.display = 'block';
        toggleButton.textContent = 'Switch to Login'; // Change button text to "Switch to Login"
    }
}

fetch('/submit_work', {
    method: 'POST', // Ensure this matches the route definition
    body: JSON.stringify(data),
    headers: {
        'Content-Type': 'application/json'
    }
})
.then(response => {
    if (!response.ok) {
        throw new Error('Network response was not ok');
    }
    return response.json();
})
.then(data => {
    console.log(data);
})
.catch(error => {
    console.error('There was a problem with the fetch operation:', error);
});

document.querySelectorAll('.delete-button').forEach(button => {
    button.addEventListener('click', function() {
        const userId = this.dataset.userId; // Assuming each button has a data-user-id attribute

        fetch(`/delete_user/${userId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                // Remove the user row from the table
                const row = document.getElementById(`user-row-${userId}`);
                if (row) {
                    row.remove();
                }
            } else {
                console.error('Failed to delete user:', data.message);
            }
        })
        .catch(error => {
            console.error('There was a problem with the fetch operation:', error);
        });
    });
});