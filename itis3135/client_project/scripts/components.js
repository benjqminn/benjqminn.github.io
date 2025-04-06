function includeHTML() {
    document.querySelectorAll("[data-include]").forEach((el) => {
      let file = el.getAttribute("data-include");
      fetch(file)
        .then((response) => response.text())
        .then((data) => {
          el.innerHTML = data;
  
          const loginLink = el.querySelector("#login-link");
          if (loginLink) {
            loginLink.addEventListener("click", (e) => {
              e.preventDefault();
              const user = localStorage.getItem("loggedInUser");
              if (user) {
                window.location.href = "dashboard.html";
              } else {
                window.location.href = "login.html";
              }
            });
          }
        })
        .catch((err) => console.error("Error loading file: ", file, err));
    });
  }
  
  document.addEventListener("DOMContentLoaded", function () {
    includeHTML();
  });
  