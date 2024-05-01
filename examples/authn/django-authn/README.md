# Pangea Django Example

Install pangea-dgango
Install python-dotenv

make .env.example into .env

Fill out the tokens & values found in .env with the values found in the Pangea AuthN Overview page

Run python manage.py migrate

where app is running:
locally
    In Pangea, go to AuthN > General > Redirect Settings and redirect to LocalPort/post_login

In Codespaces
    In Pangea go to AuthN > General > Redirect Settings and redirect CodeSpacePort/post_login

Run python manage.py runserver