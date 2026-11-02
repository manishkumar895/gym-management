const menuToggle = document.querySelector("#menu-toggle");
const sidebar = document.querySelector("#sidebar");

if (menuToggle && sidebar) {
  menuToggle.addEventListener("click", () => {
    const isOpen = sidebar.classList.toggle("is-open");
    menuToggle.setAttribute("aria-expanded", String(isOpen));
  });
}

const dateLabel = document.querySelector("#today-date");
if (dateLabel) {
  dateLabel.textContent = new Intl.DateTimeFormat("en-IN", {
    weekday: "short",
    day: "numeric",
    month: "short",
    year: "numeric",
  }).format(new Date());
}

const paymentForm = document.querySelector(".payment-form");
if (paymentForm) {
  const startDate = paymentForm.querySelector('[name="start_date"]');
  const duration = paymentForm.querySelector('[name="duration_months"]');
  const expiryDate = paymentForm.querySelector('[name="expiry_date"]');

  const updateExpiryDate = () => {
    const [year, month, day] = startDate.value.split("-").map(Number);
    const durationMonths = Number(duration.value);
    if (!year || !month || !day || !durationMonths) return;

    const targetMonth = month - 1 + durationMonths;
    const targetYear = year + Math.floor(targetMonth / 12);
    const targetMonthIndex = targetMonth % 12;
    const lastDay = new Date(Date.UTC(targetYear, targetMonthIndex + 1, 0)).getUTCDate();
    const expiryDay = Math.min(day, lastDay);
    expiryDate.value = [
      targetYear,
      String(targetMonthIndex + 1).padStart(2, "0"),
      String(expiryDay).padStart(2, "0"),
    ].join("-");
  };

  startDate.addEventListener("change", updateExpiryDate);
  duration.addEventListener("input", updateExpiryDate);
  updateExpiryDate();
}