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
