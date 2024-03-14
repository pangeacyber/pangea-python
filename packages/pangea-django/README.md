# Pangea Django Setup

Use Django as your authentication backend in a few simple steps.

## Install the Pangea SDK

Run the following command

```
pip install pangea-django
```

## Set up AuthN with Pangea

Go to the [Pangea AuthN service](https://console.pangea.cloud/service/authn) and step through the dialogs. You will need to collect the auth token you created, the domain and the hosted login link for later. Also set the redirect (callback) link under Settings/General/Redirect(callback) Settings, this is where the hosted flow will send the user once they are logged in.

## Environment Variables
Set up the environment variables ([Instructions](https://pangea.cloud/docs/getting-started/integrate/#set-environment-variables)) `PANGEA_AUTHN_TOKEN` and `PANGEA_DOMAIN` with your project token configured on the Pangea User Console (token should have access to AuthN service [Instructions](https://pangea.cloud/docs/getting-started/configure-services/#configure-a-pangea-service)) and with your Pangea domain.
Note that the Django integration only need the client token and not the service token. The client token has fewer privileges and is therefore safer to use. If you are using Pangea AuthN endpoints outside this integration, you may need the full service token.

## Django Settings

Modify the following values in the settings.py of your Django project

* Add `'pangea_django.PangeaAuthMiddleware'` to the `MIDDLEWARE`. You can keep or remove the standard Django contrib auth middleware.
* Ensure you have sessions set up, you should have this already. See [Using Django Sessions](https://docs.djangoproject.com/en/4.2/topics/http/sessions/)
* Ensure you have a working user model. Typically this just means enabling a DB. You can use a SQLite DB to get up and running quickly. See [Django Databases#SQLite](https://docs.djangoproject.com/en/4.2/ref/databases/#sqlite-notes)
* This auth backend is designed to use the hosted login method provided by Pangea. You will need to do the following to authenticate
    - From the Django view(s) where you want to kick off a login process, redirect to your hosted login link.`redirect(f"<link you copied from the Pangea Console>?state={generate_state_param(request)}")`. Note the use of the `generate_state_param` helper function from the pangea_django module. This creates a secure state param for this purpose.
    - From the Django view where the user was redirected from the login process, use the pangea_django.PangeaAuthentication class to authenticate the request `PangeaAuthentication().authenticate(request=request)`. If authentication was successful you will get a UserModel object representing the user (`None` otherwise).
    - From views where you wish to check if the user is logged in you can use the normal Django patterns of checking `request.user.is_authenticated` or using the `login_required` decorator etc.
    - You can log the user out with `PangeaAuthentication().logout(request)`
    - The `authenticate` call will create a user based on the email(username) address in Pangea if that user does not exist, it will also populate basic info (first name, last name, email address and last login time).
    - The user will be logged out automatically once the user's active token has expired and their refresh token can no longer refresh the session.
