function showLoading() {
  const spinner = document.getElementById("spinner");
  if (spinner) {
    spinner.style.visibility = "visible";
  }
  const message = document.getElementById("message");
  if (message) {
    message.remove();
  }
}

function hideLoading() {
  const spinner = document.getElementById("spinner");
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
