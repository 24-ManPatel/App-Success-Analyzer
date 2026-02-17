from pymongo import MongoClient
import config

client = MongoClient(config.MONGO_URI)
db = client[config.DB_NAME]

db.test.insert_one({"status": "MongoDB working"})
print("MongoDB connected successfully")