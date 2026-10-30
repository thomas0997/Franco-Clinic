// Shared behaviour for the clinic app.
(function () {
  // Account menu
  const userBtn = document.querySelector("[data-user-btn]");
  const userPop = document.querySelector("[data-user-pop]");
  if (userBtn && userPop) {
    userBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      const open = userPop.classList.toggle("open");
      userBtn.setAttribute("aria-expanded", open);
    });
    document.addEventListener("click", (e) => {
      if (!userPop.contains(e.target)) {
        userPop.classList.remove("open");
        userBtn.setAttribute("aria-expanded", "false");
      }
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") userPop.classList.remove("open");
    });
  }

  // Confirm before destructive submits: <form data-confirm="...">
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (e) => {
      if (!window.confirm(form.dataset.confirm)) e.preventDefault();
    });
  });

  // Live filter for tables: <input data-filter="#tableId" data-count="#countId">
  document.querySelectorAll("input[data-filter]").forEach((input) => {
    const table = document.querySelector(input.dataset.filter);
    const count = input.dataset.count && document.querySelector(input.dataset.count);
    if (!table) return;
    const rows = Array.from(table.tBodies[0].rows);
    const label = count ? count.dataset.noun || "rows" : "";
    const update = () => {
      const q = input.value.trim().toLowerCase();
      let shown = 0;
      rows.forEach((r) => {
        const hit = !q || r.textContent.toLowerCase().includes(q);
        r.hidden = !hit;
        if (hit) shown++;
      });
      if (count) {
        count.textContent = q
          ? `${shown.toLocaleString()} of ${rows.length.toLocaleString()} ${label}`
          : `${rows.length.toLocaleString()} ${label}`;
      }
    };
    input.addEventListener("input", update);
    update();
  });

  // Stock stepper: <div class="stepper" data-name="Paracetamol 500mg">
  function badgeFor(qty) {
    if (qty <= 0) return ["out", "Out of stock"];
    if (qty <= 5) return ["low", "Low"];
    return ["ok", "In stock"];
  }

  document.querySelectorAll(".stepper[data-name]").forEach((stepper) => {
    const name = stepper.dataset.name;
    const out = stepper.querySelector("output");
    const row = stepper.closest("[data-med]");
    stepper.querySelectorAll("button[data-action]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const buttons = stepper.querySelectorAll("button");
        buttons.forEach((b) => (b.disabled = true));
        try {
          const res = await fetch(`/inventory/ajax-update/${encodeURIComponent(name)}`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-CSRF-Token": document.querySelector('meta[name="csrf-token"]').content,
            },
            body: JSON.stringify({ action: btn.dataset.action }),
          });
          const data = await res.json();
          if (!res.ok || data.quantity === undefined) throw new Error(data.error || "Update failed");
          out.textContent = data.quantity;
          out.classList.remove("bump");
          void out.offsetWidth;
          out.classList.add("bump");
          const badge = row && row.querySelector(".badge");
          if (badge) {
            const [cls, text] = badgeFor(data.quantity);
            badge.className = "badge " + cls;
            badge.textContent = text;
          }
        } catch (err) {
          window.alert(`Couldn't update ${name}. Check your connection and try again.`);
        } finally {
          buttons.forEach((b) => (b.disabled = false));
        }
      });
    });
  });
})();
