Java.perform(function () {
  // Find the Gmail activity responsible for setting up the account
  var activity = Java.use("com.google.android.gm.setup.SetupAccountsActivity");

  // Simulate a tap on the "Add another account" button
  activity.clickAddAccountButton.implementation = function () {
    console.log("[*] Clicked 'Add another account'");
    this.clickAddAccountButton();
  };

  // Simulate text input for the email address and password
  var emailField = Java.use("com.google.android.gms.common.SignInButton");
  emailField.setText.implementation = function (text: string) {
    console.log("[*] Setting email address to: " + text);
    this.setText(text);
  };

  var passwordField = Java.use("com.google.android.gms.common.SignInButton");
  passwordField.setText.implementation = function (text: string) {
    console.log("[*] Setting password to: " + text);
    this.setText(text);
  };

  // Simulate a tap on the "Next" button
  var nextButton = Java.use("com.google.android.gms.common.SignInButton");
  nextButton.performClick.implementation = function () {
    console.log("[*] Clicked 'Next'");
    this.performClick();
  };

  // Simulate a tap on the "I agree" button
  var agreeButton = Java.use("android.widget.Button");
  agreeButton.performClick.implementation = function () {
    console.log("[*] Clicked 'I agree'");
    this.performClick();
  };
});
