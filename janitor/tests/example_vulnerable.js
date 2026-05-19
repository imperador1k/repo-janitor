// Example vulnerable JavaScript file for testing

// HIGH: Using eval with user input
function processInput(userInput) {
    return eval(userInput);
}

// HIGH: innerHTML XSS
function renderContent(html) {
    document.getElementById('output').innerHTML = html;
}

// LOW: Console log left in code
function fetchData() {
    console.log('Fetching data...');
    return fetch('/api/data');
}

// MEDIUM: Debugger statement
function debugFunction() {
    debugger;
    return true;
}

// CRITICAL: Storing password in localStorage
function saveCredentials(username, password) {
    localStorage.setItem('password', password);
}

// LOW: Using alert
function showMessage(msg) {
    alert(msg);
}
