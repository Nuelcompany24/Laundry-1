document.addEventListener('DOMContentLoaded', () => {
  initAdminDashboard();
});

let allBookings = [];

function initAdminDashboard() {
  fetchBookingsAndStats();

  const searchInput = document.getElementById('searchInput');
  if (searchInput) {
    searchInput.addEventListener('input', filterTable);
  }
}

function fetchBookingsAndStats() {
  fetch('/admin', { headers: { 'Accept': 'application/json' } })
    .then(res => res.json())
    .then(data => {
      allBookings = data.bookings || [];
      renderTable(allBookings);
      updateStats(data.stats || {});
    })
    .catch(err => console.error('Error loading dashboard data:', err));
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
      <td>₦${Number(b.total).toLocaleString()}</td>
      <td>${b.status}</td>
      <td>${b.date}</td>
      <td>
        <button onclick="viewBooking('${b.order_id}')">View</button>
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

function viewBooking(orderId) {
  const booking = allBookings.find(b => b.order_id === orderId);
  if (!booking) return alert("Booking not found!");

  const html = `
    <table>
      <tr><td><strong>Order ID:</strong></td><td>${booking.order_id}</td></tr>
      <tr><td><strong>Customer:</strong></td><td>${booking.name}</td></tr>
      <tr><td><strong>Email:</strong></td><td>${booking.email}</td></tr>
      <tr><td><strong>Phone:</strong></td><td>${booking.phone}</td></tr>
      <tr><td><strong>Status:</strong></td><td>${booking.status}</td></tr>
      <tr><td><strong>Total:</strong></td><td>₦${Number(booking.total).toLocaleString()}</td></tr>
      <tr><td><strong>Date:</strong></td><td>${booking.date}</td></tr>
    </table>
  `;

  document.getElementById('bookingDetails').innerHTML = html;
  document.getElementById('modal').classList.remove('hidden');
}

function updateStats(stats) {
  document.getElementById('statBookings').textContent = stats.total_bookings || 0;
  document.getElementById('statRevenue').textContent = Number(stats.total_revenue || 0).toLocaleString();
  document.getElementById('statPending').textContent = stats.pending || 0;
  document.getElementById('statCompleted').textContent = stats.completed || 0;
}

function updateStatus(orderId, newStatus) {
  fetch(`/admin/${orderId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: newStatus })
  })
  .then(res => res.json())
  .then(data => {
    alert(data.message || 'Status updated!');
    fetchBookingsAndStats(); // Refresh all
  })
  .catch(err => console.error("Update error:", err));
}

function closeModal() {
  document.getElementById('modal').classList.add('hidden');
}
