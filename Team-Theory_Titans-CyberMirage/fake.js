function fillFakeData() {
    const fakeData = {
        name: "John Doe",
        email: "fakeuser123@email.com",
        phone: "+1234567890",
        address: "123 Fake Street, Faketown, FK 00000",
        password: "SuperSecure123!"
    };

    document.querySelectorAll("input").forEach(input => {
        if (input.type === "text" || input.type === "email") {
            input.value = fakeData.email;
        } else if (input.type === "tel") {
            input.value = fakeData.phone;
        } else if (input.type === "password") {
            input.value = fakeData.password;
        }
    });

    console.log("🔹 Fake data injected!");
}

fillFakeData();
