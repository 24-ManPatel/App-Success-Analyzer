import os
from dotenv import load_dotenv

load_dotenv()

MONGO_URI      = os.getenv("MONGO_URI")
DB_NAME        = os.getenv("DB_NAME", "app_success_analyzer")
SECRET_KEY     = os.getenv("SECRET_KEY")
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY")
