document.getElementById('saveButton').addEventListener('click', function() {
    let apiKey = document.getElementById('apiKey').value;
    if (apiKey) {
        chrome.storage.local.set({ apiKey: apiKey }, function() {
            alert('API Key saved!');
        });
    } else {
        alert('Please enter a valid API key!');
    }
});
