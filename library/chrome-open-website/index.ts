// Get a reference to the Chrome browser package
var chromePackage = 'com.android.chrome';
// Get a reference to the Chrome browser activity
var chromeActivity = 'com.google.android.apps.chrome.Main';
// Launch the Chrome browser with the specified URL
Java.perform(function () {
  // Get a reference to the current application context
  var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();

  // Create an intent to launch the Chrome browser with the specified URL
  var intent = Java.use('android.content.Intent').$new();
  intent.setAction('android.intent.action.VIEW');
  intent.setData(Java.use('android.net.Uri').parse('https://www.apple.com'));

  // Set the package and activity for the intent
  intent.setClassName(chromePackage, chromeActivity);

  // Start the activity with the intent
  context.startActivity(intent);
});