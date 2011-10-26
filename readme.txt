CAS DB
author: ULCC
ulcc.ac.uk

To get this working, install as usual (copy this into the extensions directory, then go to the extensions
page and click'install next to it), then copy the init.php file to the docroot, replacing the existing one.

Make sure you have an institution set up, then install an auth instance of this plugin for it.

Make sure the settings in /auth/casdb/lib.php at the top of the AuthCasdb class are correct

If you have something complex going on, make a better SQL query in get_user_info()