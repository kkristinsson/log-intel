"""Production WSGI entry — syslogb Flask UI + hub network ingest."""

from dotenv import load_dotenv

load_dotenv()

from log_intel.main import create_application

application = create_application()
