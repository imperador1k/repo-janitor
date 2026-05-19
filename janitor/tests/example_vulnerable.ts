// Example vulnerable TypeScript file for testing

// MEDIUM: Using any type
function processData(data: any): any {
    return data.value;
}

// HIGH: Using @ts-nocheck
// @ts-nocheck
function unsafeFunction() {
    return eval('1+1');
}

// MEDIUM: Using @ts-ignore
// @ts-ignore
function ignoredError() {
    const x: string = 123;
    return x;
}

// HIGH: innerHTML XSS
function render(html: string) {
    document.getElementById('app').innerHTML = html;
}

// LOW: Console log
function log(msg: string) {
    console.log(msg);
}
