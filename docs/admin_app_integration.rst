Admin App Integration
=====================

The Django admin app requires a little additional work to get it to
function properly with WIND auth. Basically, admin wants to use its
own login template instead of auth's login template. So you need to
make an 'admin/login.html' template in your templates directory. Admin
doesn't pass in a 'next' variable in the context, so you need to set
that to '/admin/' yourself to have them redirected to the admin
interface when they log in. Once you get the admin template properly
overridden, you should be able to login through WIND and, if your user
is marked as staff or superuser, you'll be able to get into the admin
interface.
