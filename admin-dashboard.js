// admin-dashboard.js
document.getElementById('userManagementForm').addEventListener('submit', async function (event) {
    event.preventDefault();
  
    const userId = document.getElementById('userId').value;
    const action = document.getElementById('action').value;
    const newUsername = document.getElementById('newUsername').value;
    const newPassword = document.getElementById('newPassword').value;
    const newRole = document.getElementById('newRole').value;
  
    // Send form data to the server
    const response = await fetch('/admin/manage-users', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ action, userId, newUsername, newPassword, newRole }),
    });
  
    // Handle the server response
    const result = await response.text();
    alert(result);
  });
  