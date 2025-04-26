// fake_data_generator.js
console.log("Cyber Mirage Fake Data Generator Loaded");

function generateFakeData() {
    return {
        name: `John Doe ${Math.floor(Math.random() * 1000)}`,
        email: `johndoe${Math.floor(Math.random() * 1000)}@example.com`,
        phone: `+1-555-${Math.floor(1000 + Math.random() * 9000)}`,
        address: `${Math.floor(Math.random() * 999)} Fake Street, Faketown, FK 12345`,
        password: Math.random().toString(36).slice(-10)
    };
}

function autofillForms() {
    const fakeData = generateFakeData();
    document.querySelectorAll("input").forEach(input => {
        if (input.type === "text" || input.type === "email") {
            input.value = fakeData.email;
        } else if (input.type === "tel") {
            input.value = fakeData.phone;
        } else if (input.type === "password") {
            input.value = fakeData.password;
        }
    });
}

document.addEventListener("DOMContentLoaded", autofillForms);
