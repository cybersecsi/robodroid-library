Java.perform(function () {
  // Get a reference to the main activity
  var MainActivity = Java.use('com.instagram.mainactivity.MainActivity');

  // Get a reference to the view pager
  var viewPager = MainActivity.A00.value.A0Q.A00;

  // Get a reference to the adapter for the view pager
  var adapter = viewPager.getAdapter();

  // Get the number of items in the adapter
  var count = adapter.getCount();

  // Swipe left on the view pager
  viewPager.setCurrentItem((viewPager.getCurrentItem() + 1) % count, true);
});