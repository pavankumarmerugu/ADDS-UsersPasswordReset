"""WSGI entry point.

Run this with a real WSGI server, never with Flask's development server:

    gunicorn --bind 0.0.0.0:8000 wsgi:app

The original ``app.run(debug=True, host='0.0.0.0')`` exposed the Werkzeug
debugger — an interactive Python console — to the whole network.
"""

from dotenv import load_dotenv

load_dotenv()

from app import create_app  # noqa: E402  (must follow load_dotenv)

app = create_app()
