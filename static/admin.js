document.addEventListener('DOMContentLoaded', () => {
  fetchBookings();

  document.getElementById('searchInput').addEventListener('input', () => {
    filterTable();
  });
});

function fetchBookings() {
  fetch('/admin')
    .then(res => res.json())
    .then(data => renderTable(data))
    .catch(err => console.error('Error fetching bookings:', err));
}

function renderTable(bookings) {
  const tbody = document.querySelector('#bookingsTable tbody');
  tbody.innerHTML = '';
  bookings.forEach(b => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${b.order_id}</td>
      <td>${b.name}</td>
      <td>${b.email}</td>
      <td>${b.phone}</td>
      <td>₦${b.total.toLocaleString()}</td>
      <td>${b.status}</td>
      <td>${b.date}</td>
      <td>
  <button onclick="viewDetails('${b.order_id}')">View</button>
  <button onclick="updateStatus('${b.order_id}', 'completed')">✔ Done</button>
</td>

    `;
    tbody.appendChild(row);
  });
}

function filterTable() {
  const filter = document.getElementById('searchInput').value.toLowerCase();
  const rows = document.querySelectorAll('#bookingsTable tbody tr');
  rows.forEach(row => {
    row.style.display = [...row.cells].some(cell =>
      cell.textContent.toLowerCase().includes(filter)
    ) ? '' : 'none';
  });
}

function viewDetails(orderId) {
  fetch('/admin')
    .then(res => res.json())
    .then(bookings => {
      const booking = bookings.find(b => b.order_id === orderId);
      document.getElementById('bookingDetails').textContent = JSON.stringify(booking, null, 2);
      document.getElementById('modal').classList.remove('hidden');
    });
}

fetchStats();
function fetchStats() {
  fetch('/stats')
    .then(res => res.json())
    .then(data => {
      document.getElementById('statBookings').textContent = data.total_bookings;
      document.getElementById('statRevenue').textContent = data.total_revenue.toLocaleString();
      document.getElementById('statPending').textContent = data.pending;
      document.getElementById('statCompleted').textContent = data.completed;
    });
}
// Function to update booking status

function updateStatus(orderId, newStatus) {
  fetch(`/update-status/${orderId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: newStatus })
  })
  .then(res => res.json())
  .then(data => {
    alert(data.message);
    fetchBookings(); // refresh table
  });
}

function closeModal() {
  document.getElementById('modal').classList.add('hidden');
}
