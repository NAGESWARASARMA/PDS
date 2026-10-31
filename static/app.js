/**
 * PDS Client-Side UX Utilities
 * Implements confirmation dialogs, character count indicators,
 * auto-scroll in chat, and flash notice dismissal.
 */

document.addEventListener("DOMContentLoaded", () => {
  // 1. Auto-scroll chat panel to latest message
  const chatPanel = document.querySelector(".chat-panel");
  if (chatPanel) {
    chatPanel.scrollTop = chatPanel.scrollHeight;
  }

  // 2. Character counter for textareas with maxlength
  document.querySelectorAll("textarea[maxlength]").forEach(textarea => {
    const max = textarea.getAttribute("maxlength");
    const counter = document.createElement("div");
    counter.className = "char-counter";
    counter.style.cssText = "font-size: 0.78rem; color: var(--text-subtle); text-align: right; margin-top: 4px;";
    counter.textContent = `${textarea.value.length} / ${max} characters`;
    textarea.parentNode.insertBefore(counter, textarea.nextSibling);

    textarea.addEventListener("input", () => {
      counter.textContent = `${textarea.value.length} / ${max} characters`;
      if (textarea.value.length >= max * 0.9) {
        counter.style.color = "var(--warning)";
      } else {
        counter.style.color = "var(--text-subtle)";
      }
    });
  });

  // 3. Confirmations on critical actions (Accept / Reject / Status updates)
  document.querySelectorAll("form.action-row button[name='status']").forEach(btn => {
    btn.addEventListener("click", (e) => {
      const action = btn.value;
      if (action === "Accepted") {
        if (!confirm("Are you sure you want to ACCEPT this solution? This will mark the challenge as Solved and close submissions.")) {
          e.preventDefault();
        }
      } else if (action === "Rejected") {
        if (!confirm("Are you sure you want to REJECT this submission?")) {
          e.preventDefault();
        }
      }
    });
  });

  // 4. Auto-dismiss flash notices after 6 seconds with fade
  document.querySelectorAll(".notice").forEach(notice => {
    setTimeout(() => {
      notice.style.transition = "opacity 0.6s ease, transform 0.6s ease";
      notice.style.opacity = "0";
      notice.style.transform = "translateY(-6px)";
      setTimeout(() => notice.remove(), 600);
    }, 6000);
  });
});
