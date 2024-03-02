document.addEventListener('DOMContentLoaded', () => {
  const updatePasswordForm = document.getElementById('updatePasswordForm');

  updatePasswordForm.addEventListener('submit', async function (event) {
    event.preventDefault();

    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;

    // Send form data to the server for password update
    const response = await fetch('/update-user', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ currentPassword, newPassword }),
    });

    // Handle the server response
    const result = await response.text();
    alert(result);
  });
});
