document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("byoForm");

    form.addEventListener("submit", function (event) {
        event.preventDefault();

        const requiredFields = form.querySelectorAll("[required]");
        for (let field of requiredFields) {
            if (!field.value || (field.type === "checkbox" && !field.checked)) {
                alert("Please fill out all required fields.");
                return;
            }
        }

        const imageInput = form.querySelector('input[type="file"]');
        const image = imageInput.files[0];
        if (image && !["image/png", "image/jpeg"].includes(image.type)) {
            alert("Please upload a valid PNG or JPG image.");
            return;
        }

        const dataContainer = document.getElementById("submittedData");
        let output = "<h3>Your Custom Page Content:</h3><ul>";

        new FormData(form).forEach((value, key) => {
            if (key === "courses[]") {
                output += `<li><strong>Course:</strong> ${value}</li>`;
            } else if (key === "agreement") {
                output += `<li><strong>Agreement:</strong> ${value === "on" ? "✓" : "X"}</li>`;
            } else if (key !== "image") {
                const formattedKey = key
                    .replace(/([A-Z])/g, " $1") 
                    .replace(/_/g, " ") 
                    .replace(/^\w/, (c) => c.toUpperCase()); 
                output += `<li><strong>${formattedKey}:</strong> ${value}</li>`;
            }
        });

        if (image) {
            const reader = new FileReader();
            reader.onload = function (e) {
                output += `<li><strong>Image:</strong><br><img src="${e.target.result}" alt="Uploaded Image" style="width: 500px; height: auto; margin-top: 10px;"></li>`;
                output += "</ul><br><a href='#' onclick='resetForm()'>Reset and Try Again</a>";
                dataContainer.innerHTML = output;
                dataContainer.style.display = "block";
                form.style.display = "none";
            };
            reader.readAsDataURL(image);
        } else {
            output += "</ul><br><a href='#' onclick='resetForm()'>Reset and Try Again</a>";
            dataContainer.innerHTML = output;
            dataContainer.style.display = "block";
            form.style.display = "none";
        }
    });
});

function addCourse() {
    const container = document.getElementById("courses-container");
    const div = document.createElement("div");
    div.classList.add("course-field");

    div.innerHTML = `
        <input type="text" name="courses[]" placeholder="New course">
        <button type="button" class="delete-course" onclick="deleteCourse(this)">Delete</button>
    `;

    container.appendChild(div);
}

function deleteCourse(button) {
    button.parentElement.remove();
}

function resetForm() {
    document.getElementById("byoForm").reset();
    document.getElementById("byoForm").style.display = "block";
    document.getElementById("submittedData").style.display = "none";
}