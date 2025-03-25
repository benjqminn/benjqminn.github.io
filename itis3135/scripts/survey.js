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
        let output = `
    <h2>${form.name.value}'s Introduction</h2>
    <figure>
        <img src="" alt="${form.name.value}">
        <figcaption class="italic">${form.caption.value}</figcaption>
    </figure>
    <ul>
        <li><strong>Personal Background:</strong> ${form.personalBackground.value}</li>
        <li><strong>Professional Background:</strong> ${form.professionalBackground.value}</li>
        <li><strong>Academic Background:</strong> ${form.academicBackground.value}</li>
        <li><strong>Background in this Subject:</strong> ${form.webDevBackground.value}</li>
        <li><strong>Primary Computer Platform:</strong> ${form.platform.value}</li>
`;

        const courses = form.querySelectorAll('input[name="courses[]"]');
        if (courses.length > 0) {
            output += `<li><strong>Courses I'm Taking & Why:</strong><ul>`;
            courses.forEach((course) => {
                if (course.value.trim() !== "") {
                    output += `<li>${course.value}</li>`;
                }
            });
            output += `</ul></li>`;
        }

        if (form.funnyThing.value) {
            output += `<li><strong>Funny/Interesting Story:</strong> ${form.funnyThing.value}</li>`;
        }

        if (form.anythingElse.value) {
            output += `<li><strong>I'd also like to Share:</strong> ${form.anythingElse.value}</li>`;
        }

        output += `</ul>`;
        output += `<br><a href='#' onclick='resetForm()'>Reset and Try Again</a>`;

        if (image) {
            const reader = new FileReader();
            reader.onload = function (e) {
                const tempContainer = document.createElement("div");
                tempContainer.innerHTML = output;
                tempContainer.querySelector("img").src = e.target.result;

                dataContainer.innerHTML = tempContainer.innerHTML;
                dataContainer.style.display = "block";
                form.style.display = "none";
            };
            reader.readAsDataURL(image);
        } else {
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