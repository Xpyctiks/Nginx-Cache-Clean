function showLoading() {
  const spinner = document.getElementById("spinnerLoading");
  if (spinner) {
    spinner.style.visibility = "visible";
  }
}

function hideLoading() {
  const spinner = document.getElementById("spinnerLoading");
  if (spinner) {
    spinner.style.visibility = "hidden";
  }
}

document.addEventListener("DOMContentLoaded", function () {
  hideLoading();
});

window.addEventListener("pageshow", function (event) {
  if (event.persisted) {
    hideLoading();
  }
});

document.querySelectorAll(".DeleteUser-btn").forEach(btn => {
  btn.addEventListener("click", e => {
    if (!confirm("Delete this user?")) {
      e.preventDefault();
      hideLoading();
    }
  });
});

document.querySelectorAll(".AdminUser-btn").forEach(btn => {
  btn.addEventListener("click", e => {
    if (!confirm("Change this user's admin rights?")) {
      e.preventDefault();
      hideLoading();
    }
  });
});

document.querySelectorAll(".SaveSettings-btn").forEach(btn => {
  btn.addEventListener("click", e => {
    if (!confirm("Save the new settings?")) {
      e.preventDefault();
      hideLoading();
    }
  });
});
